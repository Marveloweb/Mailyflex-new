-- Hardening after the Supabase security advisor:
-- 1. pg_net belongs in the extensions schema, not public (its functions live in schema "net" either way).
-- 2. domain_org() only answers for organizations the caller belongs to (no org-id lookups for other tenants).
-- 3. Cron calls are authenticated against the Vault secret "cron_secret", so the edge functions
--    don't need a second copy of it as an environment variable.

do $$
begin
  if exists (select 1 from pg_extension e join pg_namespace n on n.oid = e.extnamespace where e.extname = 'pg_net' and n.nspname = 'public') then
    drop extension pg_net;
    create extension pg_net with schema extensions;
  end if;
end $$;

create or replace function public.domain_org(p_domain uuid)
returns uuid language sql stable security definer set search_path = '' as $$
  select d.org_id from public.domains d
  where d.id = p_domain
    and exists (select 1 from public.memberships m where m.org_id = d.org_id and m.user_id = (select auth.uid()));
$$;

create or replace function public.check_cron_secret(p_secret text)
returns boolean language plpgsql stable security definer set search_path = '' as $$
declare v_secret text;
begin
  begin
    select decrypted_secret into v_secret from vault.decrypted_secrets where name = 'cron_secret';
  exception when others then
    return false; -- Vault not available (plain Postgres)
  end;
  return v_secret is not null and length(v_secret) >= 32 and p_secret is not null and v_secret = p_secret;
end;
$$;
revoke all on function public.check_cron_secret(text) from public, anon, authenticated;
grant execute on function public.check_cron_secret(text) to service_role;
