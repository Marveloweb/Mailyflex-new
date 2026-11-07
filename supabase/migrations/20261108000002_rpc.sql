-- RPCs used by the web app, edge functions and the Cloudflare Worker.

-- Create an organization; caller becomes its owner.
create or replace function public.create_organization(p_name text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
  v_org uuid;
begin
  if v_uid is null then raise exception 'Not signed in' using errcode = 'insufficient_privilege'; end if;
  if (select count(*) from public.memberships where user_id = v_uid and role = 'owner') >= 20 then
    raise exception 'Organization limit reached' using errcode = 'check_violation';
  end if;
  insert into public.organizations (name, created_by) values (btrim(p_name), v_uid) returning id into v_org;
  insert into public.memberships (org_id, user_id, role) values (v_org, v_uid, 'owner');
  insert into public.alert_settings (org_id) values (v_org);
  return v_org;
end;
$$;

-- Create an invite; returns the raw token once (only its hash is stored).
create or replace function public.create_invite(p_org uuid, p_email text, p_role public.org_role default 'member')
returns text language plpgsql security definer set search_path = '' as $$
declare
  v_token text := public.random_token(32);
begin
  if not public.has_org_role(p_org, 'admin') then
    raise exception 'Only admins can invite people' using errcode = 'insufficient_privilege';
  end if;
  if p_role = 'owner' then
    raise exception 'Invite as admin, then promote to owner' using errcode = 'check_violation';
  end if;
  if exists (
    select 1 from public.memberships m join public.profiles p on p.id = m.user_id
    where m.org_id = p_org and p.email = lower(btrim(p_email))
  ) then
    raise exception 'That person is already a member' using errcode = 'unique_violation';
  end if;
  delete from public.invites where org_id = p_org and email = lower(btrim(p_email)) and accepted_at is null;
  insert into public.invites (org_id, email, role, token_hash, invited_by)
  values (p_org, lower(btrim(p_email)), p_role, encode(sha256(convert_to(v_token, 'UTF8')), 'hex'), (select auth.uid()));
  return v_token;
end;
$$;

-- Accept an invite addressed to the caller's email.
create or replace function public.accept_invite(p_token text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
  v_email text;
  v_inv public.invites;
begin
  if v_uid is null then raise exception 'Not signed in' using errcode = 'insufficient_privilege'; end if;
  select lower(email) into v_email from auth.users where id = v_uid;
  select * into v_inv from public.invites
  where token_hash = encode(sha256(convert_to(p_token, 'UTF8')), 'hex')
  for update;
  if not found or v_inv.accepted_at is not null or v_inv.expires_at < now() then
    raise exception 'This invite is invalid or has expired' using errcode = 'P0001';
  end if;
  if v_inv.email <> v_email then
    raise exception 'This invite was sent to a different email address' using errcode = 'insufficient_privilege';
  end if;
  insert into public.memberships (org_id, user_id, role) values (v_inv.org_id, v_uid, v_inv.role)
  on conflict (org_id, user_id) do nothing;
  update public.invites set accepted_at = now() where id = v_inv.id;
  return v_inv.org_id;
end;
$$;

-- Daily DMARC volume and alignment (RLS applies: security invoker).
create or replace function public.domain_daily_stats(p_domain uuid, p_days int default 30)
returns table (day date, total bigint, passing bigint, dkim_aligned bigint, spf_aligned bigint, quarantined bigint, rejected bigint)
language sql stable security invoker set search_path = '' as $$
  select r.day,
         sum(r.count)::bigint,
         coalesce(sum(r.count) filter (where r.dkim_aligned or r.spf_aligned), 0)::bigint,
         coalesce(sum(r.count) filter (where r.dkim_aligned), 0)::bigint,
         coalesce(sum(r.count) filter (where r.spf_aligned), 0)::bigint,
         coalesce(sum(r.count) filter (where r.disposition = 'quarantine'), 0)::bigint,
         coalesce(sum(r.count) filter (where r.disposition = 'reject'), 0)::bigint
  from public.dmarc_records r
  where r.domain_id = p_domain and r.day >= current_date - least(greatest(p_days, 1), 366)
  group by r.day
  order by r.day;
$$;

-- Volume per identified service; unidentified IPs are listed individually.
create or replace function public.domain_sender_stats(p_domain uuid, p_days int default 30)
returns table (sender text, sender_key text, ip_count bigint, total bigint, passing bigint, dkim_aligned bigint, spf_aligned bigint, sample_ip inet, ptr text, as_name text, last_seen date)
language sql stable security invoker set search_path = '' as $$
  with r as (
    select coalesce(r.sender_key, i.sender_key) as sk, r.source_ip, r.count, r.dkim_aligned, r.spf_aligned, r.day, i.ptr, i.as_name
    from public.dmarc_records r
    left join public.ip_intel i on i.ip = r.source_ip
    where r.domain_id = p_domain and r.day >= current_date - least(greatest(p_days, 1), 366)
  )
  select coalesce(sk, 'ip:' || host(source_ip)) as sender,
         sk,
         count(distinct source_ip)::bigint,
         sum(count)::bigint,
         coalesce(sum(count) filter (where dkim_aligned or spf_aligned), 0)::bigint,
         coalesce(sum(count) filter (where dkim_aligned), 0)::bigint,
         coalesce(sum(count) filter (where spf_aligned), 0)::bigint,
         min(source_ip),
         max(ptr),
         max(as_name),
         max(day)
  from r
  group by 1, 2
  order by 4 desc
  limit 300;
$$;

-- Store a parsed aggregate report (service role only). Idempotent per (domain, org, report id).
create or replace function public.ingest_dmarc_report(p_report_token text, p_report jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_domain public.domains;
  v_policy_domain text := lower(p_report -> 'policy' ->> 'domain');
  v_begin timestamptz := (p_report ->> 'dateBegin')::timestamptz;
  v_end timestamptz := (p_report ->> 'dateEnd')::timestamptz;
  v_report bigint;
  v_rows int;
begin
  select * into v_domain from public.domains where report_token = lower(p_report_token);
  if not found then return jsonb_build_object('status', 'unknown_token'); end if;
  if v_policy_domain is null or not (v_policy_domain = v_domain.name or v_policy_domain like '%.' || v_domain.name) then
    return jsonb_build_object('status', 'domain_mismatch', 'domain_id', v_domain.id, 'policy_domain', v_policy_domain);
  end if;
  if v_end < v_begin or v_end - v_begin > interval '35 days' then
    return jsonb_build_object('status', 'bad_date_range', 'domain_id', v_domain.id);
  end if;
  insert into public.dmarc_reports (domain_id, org_name, report_id, email, date_begin, date_end, policy, record_count, message_count)
  values (
    v_domain.id,
    left(p_report ->> 'orgName', 255),
    left(p_report ->> 'reportId', 255),
    left(p_report ->> 'email', 255),
    v_begin,
    v_end,
    coalesce(p_report -> 'policy', '{}'),
    jsonb_array_length(coalesce(p_report -> 'records', '[]')),
    (select coalesce(sum((x ->> 'count')::bigint), 0) from jsonb_array_elements(coalesce(p_report -> 'records', '[]')) x)
  )
  on conflict (domain_id, org_name, report_id) do nothing
  returning id into v_report;
  if v_report is null then return jsonb_build_object('status', 'duplicate', 'domain_id', v_domain.id); end if;

  insert into public.dmarc_records (report_id, domain_id, day, source_ip, count, disposition, dkim_aligned, spf_aligned, header_from, envelope_from, dkim, spf, sender_key)
  select v_report,
         v_domain.id,
         ((v_begin + (v_end - v_begin) / 2) at time zone 'utc')::date,
         (x ->> 'sourceIp')::inet,
         (x ->> 'count')::int,
         coalesce(x ->> 'disposition', 'none'),
         coalesce((x ->> 'dkimAligned')::boolean, false),
         coalesce((x ->> 'spfAligned')::boolean, false),
         lower(coalesce(x ->> 'headerFrom', v_policy_domain)),
         lower(x ->> 'envelopeFrom'),
         coalesce(x -> 'dkim', '[]'),
         coalesce(x -> 'spf', '[]'),
         x ->> 'senderKey'
  from jsonb_array_elements(coalesce(p_report -> 'records', '[]')) x;
  get diagnostics v_rows = row_count;
  return jsonb_build_object('status', 'stored', 'domain_id', v_domain.id, 'org_id', v_domain.org_id, 'report_id', v_report, 'records', v_rows);
end;
$$;

-- Public MTA-STS policy text for a hosted domain (called by the Cloudflare Worker with the anon key).
create or replace function public.mta_sts_policy(p_host text)
returns text language plpgsql stable security definer set search_path = '' as $$
declare
  v_name text := lower(regexp_replace(btrim(p_host), '\.$', ''));
  v_cfg public.mta_sts_configs;
  v_text text;
begin
  if v_name not like 'mta-sts.%' then return null; end if;
  v_name := substr(v_name, 9);
  select c.* into v_cfg
  from public.mta_sts_configs c join public.domains d on d.id = c.domain_id
  where d.name = v_name and d.verified_at is not null and d.hosted_mta_sts;
  if not found then return null; end if;
  v_text := 'version: STSv1' || E'\r\n' || 'mode: ' || v_cfg.mode || E'\r\n';
  select v_text || coalesce(string_agg('mx: ' || m, E'\r\n' order by ord) || E'\r\n', '')
  into v_text
  from unnest(v_cfg.mx) with ordinality as t(m, ord);
  return v_text || 'max_age: ' || v_cfg.max_age || E'\r\n';
end;
$$;

-- Senders first seen on or after p_since (service role; used for "new sender" alerts).
create or replace function public.domain_new_senders(p_domain uuid, p_since date)
returns table (sender text, total bigint, sample_ip inet, passing bigint)
language sql stable security definer set search_path = '' as $$
  with r as (
    select coalesce(r.sender_key, i.sender_key, 'ip:' || host(r.source_ip)) as sender, r.day, r.count, r.source_ip, (r.dkim_aligned or r.spf_aligned) as pass
    from public.dmarc_records r left join public.ip_intel i on i.ip = r.source_ip
    where r.domain_id = p_domain
  )
  select sender, sum(count)::bigint, min(source_ip), coalesce(sum(count) filter (where pass), 0)::bigint
  from r
  group by sender
  having min(day) >= p_since
  order by 2 desc
  limit 50;
$$;

revoke all on function public.domain_new_senders(uuid, date) from public, anon, authenticated;
grant execute on function public.domain_new_senders(uuid, date) to service_role;
revoke all on function public.create_organization(text) from public, anon;
revoke all on function public.create_invite(uuid, text, public.org_role) from public, anon;
revoke all on function public.accept_invite(text) from public, anon;
revoke all on function public.domain_daily_stats(uuid, int) from public, anon;
revoke all on function public.domain_sender_stats(uuid, int) from public, anon;
revoke all on function public.ingest_dmarc_report(text, jsonb) from public, anon, authenticated;
revoke all on function public.mta_sts_policy(text) from public;

grant execute on function public.create_organization(text) to authenticated;
grant execute on function public.create_invite(uuid, text, public.org_role) to authenticated;
grant execute on function public.accept_invite(text) to authenticated;
grant execute on function public.domain_daily_stats(uuid, int) to authenticated, service_role;
grant execute on function public.domain_sender_stats(uuid, int) to authenticated, service_role;
grant execute on function public.ingest_dmarc_report(text, jsonb) to service_role;
grant execute on function public.mta_sts_policy(text) to anon, authenticated, service_role;
