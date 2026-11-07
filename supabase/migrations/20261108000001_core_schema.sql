-- Maily Flex core schema: multi-tenant orgs, domains, hosted-record config, DMARC reports, alerts.
-- Every table has RLS enabled. Tenancy is enforced through public.has_org_role().

-- ---------------------------------------------------------------- types
create type public.org_role as enum ('viewer', 'member', 'admin', 'owner'); -- ordered: higher = more rights
create type public.dmarc_policy as enum ('none', 'quarantine', 'reject');

create or replace function public.random_token(bytes int default 16)
returns text language sql volatile set search_path = '' as $$
  select string_agg(replace(gen_random_uuid()::text, '-', ''), '') from generate_series(1, greatest(1, ceil(bytes / 16.0)::int));
$$;

-- ---------------------------------------------------------------- tables
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  full_name text,
  created_at timestamptz not null default now()
);

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(btrim(name)) between 1 and 100),
  plan text not null default 'free',
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);

create table public.memberships (
  org_id uuid not null references public.organizations (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role public.org_role not null default 'member',
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);
create index memberships_user_idx on public.memberships (user_id);

create table public.invites (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  email text not null check (email = lower(email) and email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  role public.org_role not null default 'member' check (role <> 'owner'),
  token_hash text not null unique,
  invited_by uuid references auth.users (id) on delete set null,
  expires_at timestamptz not null default now() + interval '7 days',
  accepted_at timestamptz,
  created_at timestamptz not null default now()
);
create index invites_org_idx on public.invites (org_id);

create table public.domains (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  name text not null check (name = lower(name) and name ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$' and char_length(name) <= 253),
  verification_token text not null default public.random_token(16),
  verified_at timestamptz,
  report_token text not null unique default public.random_token(10),
  health_score int check (health_score between 0 and 100),
  grade text,
  last_scan_at timestamptz,
  dkim_selectors text[] not null default '{}',
  hosted_dmarc boolean not null default false,
  hosted_spf boolean not null default false,
  hosted_mta_sts boolean not null default false,
  created_at timestamptz not null default now(),
  unique (org_id, name)
);
-- A domain can be added by several orgs while unverified, but only one org can own it once verified.
create unique index domains_verified_name_idx on public.domains (name) where verified_at is not null;
create index domains_org_idx on public.domains (org_id);

create table public.domain_scans (
  id bigint generated always as identity primary key,
  domain_id uuid not null references public.domains (id) on delete cascade,
  score int not null check (score between 0 and 100),
  grade text not null,
  result jsonb not null,
  records jsonb not null default '{}',
  created_at timestamptz not null default now()
);
create index domain_scans_domain_idx on public.domain_scans (domain_id, created_at desc);

create table public.dmarc_policies (
  domain_id uuid primary key references public.domains (id) on delete cascade,
  p public.dmarc_policy not null default 'none',
  sp public.dmarc_policy,
  np public.dmarc_policy,
  adkim text not null default 'r' check (adkim in ('r', 's')),
  aspf text not null default 'r' check (aspf in ('r', 's')),
  t boolean not null default false,
  extra_rua text[] not null default '{}' check (array_length(extra_rua, 1) is null or array_length(extra_rua, 1) <= 5),
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users (id) on delete set null
);

create table public.spf_configs (
  domain_id uuid primary key references public.domains (id) on delete cascade,
  includes text[] not null default '{}',
  ip4 text[] not null default '{}',
  ip6 text[] not null default '{}',
  all_qualifier text not null default '~' check (all_qualifier in ('-', '~')),
  flattened jsonb,
  lookup_count int,
  flattened_at timestamptz,
  last_error text,
  updated_at timestamptz not null default now()
);

create table public.mta_sts_configs (
  domain_id uuid primary key references public.domains (id) on delete cascade,
  mode text not null default 'testing' check (mode in ('none', 'testing', 'enforce')),
  mx text[] not null default '{}',
  max_age int not null default 604800 check (max_age between 86400 and 31557600),
  policy_id text not null default to_char(now() at time zone 'utc', 'YYYYMMDDHH24MISS'),
  tlsrpt_enabled boolean not null default true,
  updated_at timestamptz not null default now()
);

create table public.dmarc_reports (
  id bigint generated always as identity primary key,
  domain_id uuid not null references public.domains (id) on delete cascade,
  org_name text not null,
  report_id text not null,
  email text,
  date_begin timestamptz not null,
  date_end timestamptz not null,
  policy jsonb not null default '{}',
  record_count int not null default 0,
  message_count bigint not null default 0,
  received_at timestamptz not null default now(),
  unique (domain_id, org_name, report_id)
);
create index dmarc_reports_domain_idx on public.dmarc_reports (domain_id, date_begin desc);

create table public.dmarc_records (
  id bigint generated always as identity primary key,
  report_id bigint not null references public.dmarc_reports (id) on delete cascade,
  domain_id uuid not null references public.domains (id) on delete cascade,
  day date not null,
  source_ip inet not null,
  count int not null check (count >= 0),
  disposition text not null default 'none',
  dkim_aligned boolean not null,
  spf_aligned boolean not null,
  header_from text not null,
  envelope_from text,
  dkim jsonb not null default '[]',
  spf jsonb not null default '[]',
  sender_key text
);
create index dmarc_records_domain_day_idx on public.dmarc_records (domain_id, day);
create index dmarc_records_domain_ip_idx on public.dmarc_records (domain_id, source_ip);
create index dmarc_records_report_idx on public.dmarc_records (report_id);

create table public.ip_intel (
  ip inet primary key,
  ptr text,
  asn int,
  as_name text,
  country text,
  sender_key text,
  updated_at timestamptz not null default now()
);

create table public.alerts (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.organizations (id) on delete cascade,
  domain_id uuid references public.domains (id) on delete cascade,
  kind text not null,
  severity text not null check (severity in ('critical', 'warning', 'info')),
  title text not null,
  body text not null default '',
  dedupe_key text,
  emailed_at timestamptz,
  created_at timestamptz not null default now(),
  read_at timestamptz
);
-- NULL dedupe keys never conflict; non-partial so PostgREST upserts can target it.
create unique index alerts_dedupe_idx on public.alerts (org_id, dedupe_key);
create index alerts_org_idx on public.alerts (org_id, created_at desc);

create table public.alert_settings (
  org_id uuid primary key references public.organizations (id) on delete cascade,
  weekly_digest boolean not null default true,
  email_on_critical boolean not null default true,
  pass_rate_threshold numeric(4, 3) not null default 0.950 check (pass_rate_threshold between 0 and 1)
);

create table public.inbound_log (
  id bigint generated always as identity primary key,
  resend_email_id text not null unique,
  recipient text,
  status text not null,
  detail text,
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------- helper functions
create or replace function public.has_org_role(p_org uuid, p_min public.org_role default 'viewer')
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.memberships m
    where m.org_id = p_org and m.user_id = (select auth.uid()) and m.role >= p_min
  );
$$;

create or replace function public.domain_org(p_domain uuid)
returns uuid language sql stable security definer set search_path = '' as $$
  select org_id from public.domains where id = p_domain;
$$;

-- ---------------------------------------------------------------- triggers
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, email, full_name)
  values (new.id, lower(new.email), coalesce(new.raw_user_meta_data ->> 'full_name', ''))
  on conflict (id) do nothing;
  return new;
end;
$$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Never leave an organization without an owner.
create or replace function public.guard_last_owner()
returns trigger language plpgsql set search_path = '' as $$
begin
  if old.role = 'owner' and (tg_op = 'DELETE' or new.role <> 'owner') then
    -- Allow when the whole organization is being deleted (cascade).
    if not exists (select 1 from public.organizations where id = old.org_id) then
      return coalesce(new, old);
    end if;
    if not exists (
      select 1 from public.memberships
      where org_id = old.org_id and role = 'owner' and user_id <> old.user_id
    ) then
      raise exception 'An organization must keep at least one owner' using errcode = 'check_violation';
    end if;
  end if;
  return coalesce(new, old);
end;
$$;
create trigger memberships_guard_last_owner before update or delete on public.memberships
  for each row execute function public.guard_last_owner();

-- Only owners may grant or remove the owner role.
create or replace function public.guard_owner_changes()
returns trigger language plpgsql set search_path = '' as $$
begin
  if (select auth.uid()) is null then return coalesce(new, old); end if; -- service role / internal
  if ((tg_op <> 'INSERT' and old.role = 'owner') or (tg_op <> 'DELETE' and new.role = 'owner'))
     and not public.has_org_role(coalesce(new.org_id, old.org_id), 'owner')
     and not (tg_op = 'DELETE' and old.user_id = (select auth.uid()))
     -- first owner of a brand-new organization (create_organization)
     and not (tg_op = 'INSERT' and not exists (select 1 from public.memberships where org_id = new.org_id)) then
    raise exception 'Only owners can change owner memberships' using errcode = 'insufficient_privilege';
  end if;
  return coalesce(new, old);
end;
$$;
create trigger memberships_guard_owner before insert or update or delete on public.memberships
  for each row execute function public.guard_owner_changes();

-- MTA-STS: any policy change must get a new id so senders refetch it.
create or replace function public.bump_mta_sts_policy_id()
returns trigger language plpgsql set search_path = '' as $$
begin
  if tg_op = 'INSERT' or new.mode is distinct from old.mode or new.mx is distinct from old.mx or new.max_age is distinct from old.max_age then
    new.policy_id := to_char(clock_timestamp() at time zone 'utc', 'YYYYMMDDHH24MISSUS');
  end if;
  new.updated_at := now();
  return new;
end;
$$;
create trigger mta_sts_configs_policy_id before insert or update on public.mta_sts_configs
  for each row execute function public.bump_mta_sts_policy_id();

create or replace function public.touch_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin
  new.updated_at := now();
  return new;
end;
$$;
create trigger dmarc_policies_touch before update on public.dmarc_policies for each row execute function public.touch_updated_at();
create trigger spf_configs_touch before update on public.spf_configs for each row execute function public.touch_updated_at();

-- ---------------------------------------------------------------- RLS
alter table public.profiles enable row level security;
alter table public.organizations enable row level security;
alter table public.memberships enable row level security;
alter table public.invites enable row level security;
alter table public.domains enable row level security;
alter table public.domain_scans enable row level security;
alter table public.dmarc_policies enable row level security;
alter table public.spf_configs enable row level security;
alter table public.mta_sts_configs enable row level security;
alter table public.dmarc_reports enable row level security;
alter table public.dmarc_records enable row level security;
alter table public.ip_intel enable row level security;
alter table public.alerts enable row level security;
alter table public.alert_settings enable row level security;
alter table public.inbound_log enable row level security;

-- profiles: yourself, plus people in your organizations
create policy profiles_select on public.profiles for select to authenticated using (
  id = (select auth.uid())
  or exists (
    select 1 from public.memberships mine join public.memberships theirs on theirs.org_id = mine.org_id
    where mine.user_id = (select auth.uid()) and theirs.user_id = profiles.id
  )
);
create policy profiles_update on public.profiles for update to authenticated
  using (id = (select auth.uid())) with check (id = (select auth.uid()));

create policy orgs_select on public.organizations for select to authenticated using (public.has_org_role(id, 'viewer'));
create policy orgs_update on public.organizations for update to authenticated
  using (public.has_org_role(id, 'admin')) with check (public.has_org_role(id, 'admin'));
create policy orgs_delete on public.organizations for delete to authenticated using (public.has_org_role(id, 'owner'));

create policy memberships_select on public.memberships for select to authenticated using (public.has_org_role(org_id, 'viewer'));
create policy memberships_update on public.memberships for update to authenticated
  using (public.has_org_role(org_id, 'admin')) with check (public.has_org_role(org_id, 'admin'));
create policy memberships_delete on public.memberships for delete to authenticated
  using (public.has_org_role(org_id, 'admin') or user_id = (select auth.uid()));

create policy invites_select on public.invites for select to authenticated using (public.has_org_role(org_id, 'admin'));
create policy invites_delete on public.invites for delete to authenticated using (public.has_org_role(org_id, 'admin'));

create policy domains_select on public.domains for select to authenticated using (public.has_org_role(org_id, 'viewer'));
create policy domains_insert on public.domains for insert to authenticated with check (public.has_org_role(org_id, 'admin'));
create policy domains_update on public.domains for update to authenticated
  using (public.has_org_role(org_id, 'admin')) with check (public.has_org_role(org_id, 'admin'));
create policy domains_delete on public.domains for delete to authenticated using (public.has_org_role(org_id, 'admin'));

create policy scans_select on public.domain_scans for select to authenticated using (public.has_org_role(public.domain_org(domain_id), 'viewer'));
create policy reports_select on public.dmarc_reports for select to authenticated using (public.has_org_role(public.domain_org(domain_id), 'viewer'));
create policy records_select on public.dmarc_records for select to authenticated using (public.has_org_role(public.domain_org(domain_id), 'viewer'));

do $$
declare t text;
begin
  foreach t in array array['dmarc_policies', 'spf_configs', 'mta_sts_configs'] loop
    execute format('create policy %1$s_select on public.%1$s for select to authenticated using (public.has_org_role(public.domain_org(domain_id), ''viewer''))', t);
    execute format('create policy %1$s_insert on public.%1$s for insert to authenticated with check (public.has_org_role(public.domain_org(domain_id), ''admin''))', t);
    execute format('create policy %1$s_update on public.%1$s for update to authenticated using (public.has_org_role(public.domain_org(domain_id), ''admin'')) with check (public.has_org_role(public.domain_org(domain_id), ''admin''))', t);
    execute format('create policy %1$s_delete on public.%1$s for delete to authenticated using (public.has_org_role(public.domain_org(domain_id), ''admin''))', t);
  end loop;
end $$;

create policy ip_intel_select on public.ip_intel for select to authenticated using (true);

create policy alerts_select on public.alerts for select to authenticated using (public.has_org_role(org_id, 'viewer'));
create policy alerts_update on public.alerts for update to authenticated
  using (public.has_org_role(org_id, 'viewer')) with check (public.has_org_role(org_id, 'viewer'));

create policy alert_settings_select on public.alert_settings for select to authenticated using (public.has_org_role(org_id, 'viewer'));
create policy alert_settings_update on public.alert_settings for update to authenticated
  using (public.has_org_role(org_id, 'admin')) with check (public.has_org_role(org_id, 'admin'));

-- inbound_log: no policies (service role only)

-- ---------------------------------------------------------------- privileges
-- Start from nothing, then grant exactly what the app needs. Column lists stop users
-- from writing server-managed fields (verified_at, scores, report tokens, flattened SPF...).
revoke all on all tables in schema public from anon, authenticated;
revoke all on all functions in schema public from public, anon, authenticated;

grant select, update (full_name) on public.profiles to authenticated;
grant select, update (name), delete on public.organizations to authenticated;
grant select, update (role), delete on public.memberships to authenticated;
grant select, delete on public.invites to authenticated;
grant select, insert (org_id, name, dkim_selectors), update (dkim_selectors, hosted_dmarc, hosted_spf, hosted_mta_sts), delete on public.domains to authenticated;
grant select on public.domain_scans, public.dmarc_reports, public.dmarc_records, public.ip_intel to authenticated;
-- domain_id is updatable only so PostgREST upserts work; RLS re-checks admin rights on the target domain.
grant select, insert (domain_id, p, sp, np, adkim, aspf, t, extra_rua, updated_by), update (domain_id, p, sp, np, adkim, aspf, t, extra_rua, updated_by), delete on public.dmarc_policies to authenticated;
grant select, insert (domain_id, includes, ip4, ip6, all_qualifier), update (domain_id, includes, ip4, ip6, all_qualifier), delete on public.spf_configs to authenticated;
grant select, insert (domain_id, mode, mx, max_age, tlsrpt_enabled), update (domain_id, mode, mx, max_age, tlsrpt_enabled), delete on public.mta_sts_configs to authenticated;
grant select, update (read_at) on public.alerts to authenticated;
grant select, update (weekly_digest, email_on_critical, pass_rate_threshold) on public.alert_settings to authenticated;

grant all on all tables in schema public to service_role;
grant usage, select on all sequences in schema public to service_role;

grant execute on function public.has_org_role(uuid, public.org_role) to authenticated, service_role;
grant execute on function public.domain_org(uuid) to authenticated, service_role;
grant execute on function public.random_token(int) to authenticated, service_role; -- used by column defaults
