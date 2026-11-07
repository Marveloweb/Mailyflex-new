-- Scheduled jobs: pg_cron calls edge functions through pg_net.
-- Requires two Vault secrets (see README):
--   select vault.create_secret('https://<project-ref>.supabase.co', 'project_url');
--   select vault.create_secret('<same value as the CRON_SECRET function secret>', 'cron_secret');
-- Skipped automatically where pg_cron / pg_net are not available (e.g. plain Postgres in CI).

create or replace function public.invoke_edge_function(p_name text, p_body jsonb default '{}')
returns bigint language plpgsql security definer set search_path = '' as $$
declare
  v_url text;
  v_secret text;
  v_id bigint;
begin
  select decrypted_secret into v_url from vault.decrypted_secrets where name = 'project_url';
  select decrypted_secret into v_secret from vault.decrypted_secrets where name = 'cron_secret';
  if v_url is null or v_secret is null then
    raise warning 'invoke_edge_function: vault secrets project_url / cron_secret are not set';
    return null;
  end if;
  select net.http_post(
    url := rtrim(v_url, '/') || '/functions/v1/' || p_name,
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', v_secret),
    body := p_body,
    timeout_milliseconds := 60000
  ) into v_id;
  return v_id;
end;
$$;
revoke all on function public.invoke_edge_function(text, jsonb) from public, anon, authenticated;

do $$
begin
  if exists (select 1 from pg_available_extensions where name = 'pg_cron')
     and exists (select 1 from pg_available_extensions where name = 'pg_net') then
    create extension if not exists pg_cron;
    create extension if not exists pg_net with schema extensions;
    -- Rescan every domain every 6 hours (DNS changes, blocklists, score).
    perform cron.schedule('mailyflex-scan-all', '17 */6 * * *', $cmd$ select public.invoke_edge_function('domain-scan', '{"all": true}') $cmd$);
    -- Re-resolve hosted SPF includes and republish flattened records.
    perform cron.schedule('mailyflex-dns-sync', '47 */6 * * *', $cmd$ select public.invoke_edge_function('dns-sync', '{"all": true}') $cmd$);
    -- Daily alert checks (pass-rate drops, new senders); weekly digest on Mondays.
    perform cron.schedule('mailyflex-daily-alerts', '5 7 * * *', $cmd$ select public.invoke_edge_function('digest', '{"mode": "daily"}') $cmd$);
    perform cron.schedule('mailyflex-weekly-digest', '35 7 * * 1', $cmd$ select public.invoke_edge_function('digest', '{"mode": "weekly"}') $cmd$);
  else
    raise notice 'pg_cron/pg_net not available; scheduled jobs not created';
  end if;
end $$;
