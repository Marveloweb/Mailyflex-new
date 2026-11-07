-- RLS / RPC behaviour tests. Run by scripts/test-db.sh after migrations. Any failure aborts.
\set ON_ERROR_STOP 1
set client_min_messages = warning;

create schema t;
create function t.expect_error(p_sql text, p_pattern text) returns void language plpgsql as $$
begin
  execute p_sql;
  raise exception 'expected error matching "%" but statement succeeded: %', p_pattern, p_sql;
exception when others then
  if sqlerrm like 'expected error matching%' then raise; end if;
  if sqlerrm !~* p_pattern then
    raise exception 'expected error matching "%" but got "%" for: %', p_pattern, sqlerrm, p_sql;
  end if;
end $$;
create function t.eq(p_actual anyelement, p_expected anyelement, p_label text) returns void language plpgsql as $$
begin
  if p_actual is distinct from p_expected then
    raise exception '% : expected %, got %', p_label, p_expected, p_actual;
  end if;
end $$;
grant usage on schema t to anon, authenticated, service_role;
grant execute on all functions in schema t to anon, authenticated, service_role;
create table t.ctx (k text primary key, v text);
grant all on t.ctx to anon, authenticated, service_role;

insert into auth.users (id, email, raw_user_meta_data) values
  ('00000000-0000-0000-0000-00000000000a', 'Alice@acme.com', '{"full_name":"Alice"}'),
  ('00000000-0000-0000-0000-00000000000b', 'bob@bobco.com', '{}'),
  ('00000000-0000-0000-0000-00000000000c', 'carol@acme.com', '{}'),
  ('00000000-0000-0000-0000-00000000000d', 'dave@acme.com', '{}');
select t.eq((select email from public.profiles where id = '00000000-0000-0000-0000-00000000000a'), 'alice@acme.com', 'profile created by trigger');

-- ---------- Alice creates an org and a domain
set role authenticated;
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000a', false);
insert into t.ctx values ('org_a', public.create_organization('Acme'));
insert into public.domains (org_id, name) select v::uuid, 'acme.com' from t.ctx where k = 'org_a';
insert into t.ctx select 'dom_a', id::text from public.domains where name = 'acme.com';
select t.eq((select count(*) from public.alert_settings)::int, 1, 'alert settings created');
select t.expect_error($$update public.domains set verified_at = now()$$, 'permission denied');
select t.expect_error($$update public.domains set report_token = 'x'$$, 'permission denied');
select t.expect_error($$insert into public.memberships (org_id, user_id, role) select v::uuid, '00000000-0000-0000-0000-00000000000b', 'owner' from t.ctx where k='org_a'$$, 'permission denied');
update public.domains set hosted_mta_sts = true, dkim_selectors = '{custom1}';
insert into public.mta_sts_configs (domain_id, mode, mx) select v::uuid, 'enforce', '{mx1.acme.com,*.mail.acme.com}' from t.ctx where k = 'dom_a';
insert into t.ctx select 'policy_id_1', policy_id from public.mta_sts_configs;
insert into t.ctx values ('invite_carol', public.create_invite((select v::uuid from t.ctx where k = 'org_a'), 'Carol@acme.com', 'admin'));
insert into t.ctx values ('invite_dave', public.create_invite((select v::uuid from t.ctx where k = 'org_a'), 'dave@acme.com', 'viewer'));
select t.expect_error($$select public.create_invite((select v::uuid from t.ctx where k = 'org_a'), 'x@acme.com', 'owner')$$, 'promote');
reset role;

-- ---------- Bob: separate tenant, sees nothing of Acme
set role authenticated;
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000b', false);
insert into t.ctx values ('org_b', public.create_organization('Bobco'));
select t.eq((select count(*) from public.domains)::int, 0, 'bob sees no acme domains');
select t.eq((select count(*) from public.organizations)::int, 1, 'bob sees only his org');
select t.eq((select count(*) from public.mta_sts_configs)::int, 0, 'bob sees no acme config');
select t.eq((select count(*) from public.profiles)::int, 1, 'bob sees only his profile');
select t.expect_error($$insert into public.domains (org_id, name) select v::uuid, 'evil.com' from t.ctx where k = 'org_a'$$, 'row-level security');
select t.expect_error($$select public.create_invite((select v::uuid from t.ctx where k = 'org_a'), 'bob2@bobco.com')$$, 'Only admins');
select t.expect_error($$select public.accept_invite((select v from t.ctx where k = 'invite_carol'))$$, 'different email');
-- Bob can add acme.com to his own org while it is unverified (no squatting once verified).
insert into public.domains (org_id, name) select v::uuid, 'acme.com' from t.ctx where k = 'org_b';
update public.organizations set name = 'Hacked' where id = (select v::uuid from t.ctx where k = 'org_a');
reset role;
select t.eq((select name from public.organizations where id = (select v::uuid from t.ctx where k = 'org_a')), 'Acme', 'bob cannot rename acme');

-- ---------- Carol and Dave accept invites
set role authenticated;
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000c', false);
select t.eq(public.accept_invite((select v from t.ctx where k = 'invite_carol')), (select v::uuid from t.ctx where k = 'org_a'), 'carol joins acme');
select t.expect_error($$select public.accept_invite((select v from t.ctx where k = 'invite_carol'))$$, 'invalid or has expired');
select t.eq((select role::text from public.memberships where user_id = '00000000-0000-0000-0000-00000000000c'), 'admin', 'carol is admin');
select t.eq((select count(*) from public.profiles)::int, 2, 'carol sees alice + herself');
-- admin cannot make herself owner or remove the owner
select t.expect_error($$update public.memberships set role = 'owner' where user_id = '00000000-0000-0000-0000-00000000000c'$$, 'Only owners');
select t.expect_error($$delete from public.memberships where user_id = '00000000-0000-0000-0000-00000000000a'$$, 'owner');
-- admin can edit hosted DMARC config, including via upsert (what the web client sends)
insert into public.dmarc_policies (domain_id, p) select v::uuid, 'none' from t.ctx where k = 'dom_a';
insert into public.dmarc_policies (domain_id, p) select v::uuid, 'quarantine' from t.ctx where k = 'dom_a'
  on conflict (domain_id) do update set domain_id = excluded.domain_id, p = excluded.p;
insert into public.spf_configs (domain_id, includes) select v::uuid, '{_spf.google.com}' from t.ctx where k = 'dom_a'
  on conflict (domain_id) do update set domain_id = excluded.domain_id, includes = excluded.includes;
-- but cannot move a config onto a domain in another org
select t.expect_error($$update public.spf_configs set domain_id = (select id from public.domains d where d.org_id = (select v::uuid from t.ctx where k = 'org_b'))$$, 'row-level security|violates');
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000d', false);
select public.accept_invite((select v from t.ctx where k = 'invite_dave'));
select t.eq((select count(*) from public.domains)::int, 1, 'viewer sees domain');
update public.dmarc_policies set p = 'none'; -- RLS filters this to 0 rows; verified below
reset role;
select t.eq((select p::text from public.dmarc_policies), 'quarantine', 'viewer could not change policy');
set role authenticated;
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000d', false);
select t.expect_error($$insert into public.domains (org_id, name) select v::uuid, 'viewer.com' from t.ctx where k = 'org_a'$$, 'row-level security');
update public.alerts set read_at = now(); -- allowed (no rows yet)
reset role;

-- ---------- Owner safety
set role authenticated;
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000a', false);
select t.expect_error($$delete from public.memberships where user_id = '00000000-0000-0000-0000-00000000000a'$$, 'at least one owner');
select t.expect_error($$update public.memberships set role = 'admin' where user_id = '00000000-0000-0000-0000-00000000000a'$$, 'at least one owner');
update public.memberships set role = 'owner' where user_id = '00000000-0000-0000-0000-00000000000c';
delete from public.memberships where user_id = '00000000-0000-0000-0000-00000000000a'; -- alice leaves; carol is owner
reset role;
select t.eq((select count(*) from public.memberships where org_id = (select v::uuid from t.ctx where k = 'org_a'))::int, 2, 'alice left');

-- ---------- MTA-STS policy id bumps on change
update public.mta_sts_configs set mode = 'testing';
select t.eq((select policy_id <> (select v from t.ctx where k = 'policy_id_1') from public.mta_sts_configs), true, 'policy id changed');

-- ---------- Public MTA-STS policy (anon)
set role anon;
select t.eq(public.mta_sts_policy('mta-sts.acme.com'), null::text, 'unverified domain has no public policy');
select t.expect_error($$select * from public.domains$$, 'permission denied');
reset role;
update public.domains set verified_at = now() where id = (select v::uuid from t.ctx where k = 'dom_a');
select t.expect_error($$update public.domains set verified_at = now() where org_id = (select v::uuid from t.ctx where k = 'org_b')$$, 'duplicate key');
set role anon;
select t.eq(public.mta_sts_policy('MTA-STS.acme.com.'), E'version: STSv1\r\nmode: testing\r\nmx: mx1.acme.com\r\nmx: *.mail.acme.com\r\nmax_age: 604800\r\n', 'policy text');
select t.eq(public.mta_sts_policy('acme.com'), null::text, 'host must be mta-sts.*');
select t.expect_error($$select public.ingest_dmarc_report('x', '{}')$$, 'permission denied');
reset role;

-- ---------- Report ingestion (service role)
set role service_role;
select t.eq(public.ingest_dmarc_report((select report_token from public.domains where id = (select v::uuid from t.ctx where k = 'dom_a')),
  '{"orgName":"google.com","reportId":"r1","dateBegin":"2026-11-06T00:00:00Z","dateEnd":"2026-11-06T23:59:59Z","policy":{"domain":"acme.com","p":"none"},
    "records":[{"sourceIp":"209.85.220.41","count":100,"disposition":"none","dkimAligned":true,"spfAligned":true,"headerFrom":"acme.com","dkim":[],"spf":[],"senderKey":"google"},
               {"sourceIp":"198.51.100.7","count":5,"disposition":"none","dkimAligned":false,"spfAligned":false,"headerFrom":"acme.com","dkim":[],"spf":[]}]}'::jsonb) ->> 'status', 'stored', 'report stored');
select t.eq(public.ingest_dmarc_report((select report_token from public.domains where id = (select v::uuid from t.ctx where k = 'dom_a')),
  '{"orgName":"google.com","reportId":"r1","dateBegin":"2026-11-06T00:00:00Z","dateEnd":"2026-11-06T23:59:59Z","policy":{"domain":"acme.com"},"records":[]}'::jsonb) ->> 'status', 'duplicate', 'duplicate ignored');
select t.eq(public.ingest_dmarc_report((select report_token from public.domains where id = (select v::uuid from t.ctx where k = 'dom_a')),
  '{"orgName":"x","reportId":"r2","dateBegin":"2026-11-06T00:00:00Z","dateEnd":"2026-11-06T23:59:59Z","policy":{"domain":"evil.com"},"records":[]}'::jsonb) ->> 'status', 'domain_mismatch', 'foreign domain rejected');
select t.eq(public.ingest_dmarc_report('nope', '{}'::jsonb) ->> 'status', 'unknown_token', 'unknown token');
insert into public.ip_intel (ip, ptr, as_name, sender_key) values ('198.51.100.7', 'host.example.net', 'EXAMPLE-NET', null);
reset role;
select t.eq((select message_count from public.dmarc_reports)::int, 105, 'message count');
select t.eq((select day from public.dmarc_records limit 1), date '2026-11-06', 'record day');

-- ---------- Stats respect tenancy
set role authenticated;
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000d', false);
create temp table s as select * from public.domain_daily_stats((select v::uuid from t.ctx where k = 'dom_a'), 3650);
select t.eq((select total from s)::int, 105, 'viewer sees daily stats');
select t.eq((select passing from s)::int, 100, 'passing');
select t.eq((select count(*) from public.domain_sender_stats((select v::uuid from t.ctx where k = 'dom_a'), 3650))::int, 2, 'two senders');
select t.eq((select ptr from public.domain_sender_stats((select v::uuid from t.ctx where k = 'dom_a'), 3650) where sender = 'ip:198.51.100.7'), 'host.example.net', 'unknown sender enriched');
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000b', false);
select t.eq((select count(*) from public.domain_daily_stats((select v::uuid from t.ctx where k = 'dom_a'), 3650))::int, 0, 'bob sees no acme stats');
select t.eq((select count(*) from public.dmarc_records)::int, 0, 'bob sees no acme records');
reset role;

-- ---------- New senders (service role) and alert dedupe
set role service_role;
select t.eq((select count(*) from public.domain_new_senders((select v::uuid from t.ctx where k = 'dom_a'), date '2026-11-01'))::int, 2, 'both senders are new since Nov 1');
select t.eq((select count(*) from public.domain_new_senders((select v::uuid from t.ctx where k = 'dom_a'), date '2026-11-07'))::int, 0, 'none new since Nov 7');
insert into public.alerts (org_id, kind, severity, title, dedupe_key) select v::uuid, 'x', 'info', 'a', 'k1' from t.ctx where k = 'org_a';
insert into public.alerts (org_id, kind, severity, title, dedupe_key) select v::uuid, 'x', 'info', 'a', 'k1' from t.ctx where k = 'org_a' on conflict (org_id, dedupe_key) do nothing;
insert into public.alerts (org_id, kind, severity, title) select v::uuid, 'x', 'info', 'no key' from t.ctx where k = 'org_a';
insert into public.alerts (org_id, kind, severity, title) select v::uuid, 'x', 'info', 'no key' from t.ctx where k = 'org_a';
reset role;
select t.eq((select count(*) from public.alerts)::int, 3, 'dedupe only applies to keyed alerts');
set role authenticated;
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000d', false);
select t.expect_error($$select public.domain_new_senders((select v::uuid from t.ctx where k = 'dom_a'), current_date)$$, 'permission denied');
select t.expect_error($$update public.alerts set title = 'x'$$, 'permission denied');
update public.alerts set read_at = now();
reset role;
select t.eq((select count(*) from public.alerts where read_at is not null)::int, 3, 'viewer can mark alerts read');

-- ---------- Org deletion cascades despite owner guard
set role authenticated;
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000b', false);
delete from public.organizations where id = (select v::uuid from t.ctx where k = 'org_b');
reset role;
select t.eq((select count(*) from public.organizations where id = (select v::uuid from t.ctx where k = 'org_b'))::int, 0, 'bob deleted his org');

\echo 'ALL DATABASE TESTS PASSED'
