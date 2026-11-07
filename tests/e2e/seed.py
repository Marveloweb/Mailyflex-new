# Usage: python3 seed.py <domain>   (local Supabase stack must be running)
# Seed realistic DMARC aggregate data for a domain via the service-only ingest RPC (what dmarc-inbound calls).
import json, subprocess, sys, datetime, random
domain = sys.argv[1]
DB = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres'
def sql(q):
    return subprocess.run(['psql', DB, '-Atc', q], capture_output=True, text=True, check=True).stdout.strip()
token = sql(f"select report_token from public.domains where name = '{domain}' order by created_at desc limit 1")
random.seed(7)
today = datetime.date.today()
for i in range(14, 0, -1):
    d = today - datetime.timedelta(days=i)
    begin = datetime.datetime(d.year, d.month, d.day, tzinfo=datetime.timezone.utc)
    end = begin + datetime.timedelta(seconds=86399)
    for org in ['google.com', 'Outlook.com']:
        recs = [
            {'sourceIp': '209.85.220.41', 'count': random.randint(300, 420), 'disposition': 'none', 'dkimAligned': True, 'spfAligned': True, 'headerFrom': domain, 'dkim': [{'domain': domain, 'selector': 'google', 'result': 'pass'}], 'spf': [{'domain': domain, 'result': 'pass'}], 'senderKey': 'google'},
            {'sourceIp': '167.89.12.34', 'count': random.randint(80, 140), 'disposition': 'none', 'dkimAligned': True, 'spfAligned': False, 'headerFrom': domain, 'dkim': [{'domain': domain, 'selector': 's1', 'result': 'pass'}], 'spf': [{'domain': 'sendgrid.net', 'result': 'pass'}], 'senderKey': 'sendgrid'},
            {'sourceIp': '205.201.139.12', 'count': random.randint(20, 40), 'disposition': 'none', 'dkimAligned': False, 'spfAligned': False, 'headerFrom': domain, 'dkim': [{'domain': 'mcsv.net', 'result': 'pass'}], 'spf': [{'domain': 'mcsv.net', 'result': 'pass'}], 'senderKey': 'mailchimp'},
        ]
        if i % 3 == 0:
            recs.append({'sourceIp': '198.51.100.23', 'count': random.randint(3, 9), 'disposition': 'none', 'dkimAligned': False, 'spfAligned': False, 'headerFrom': domain, 'dkim': [], 'spf': [{'domain': 'spoof.example', 'result': 'fail'}], 'senderKey': None})
        rep = {'orgName': org, 'reportId': f'{org}-{d.isoformat()}', 'email': f'noreply@{org.lower()}', 'dateBegin': begin.isoformat(), 'dateEnd': end.isoformat(), 'policy': {'domain': domain, 'p': 'quarantine'}, 'records': recs}
        q = "set role service_role; select public.ingest_dmarc_report('%s', '%s'::jsonb)->>'status';" % (token, json.dumps(rep).replace("'", "''"))
        out = sql(q)
print('seeded', domain, token, out)
sql("insert into public.ip_intel (ip, ptr, asn, as_name, country, sender_key) values ('198.51.100.23', 'vps-23.cheaphost.example', 64500, 'CHEAPHOST-AS', 'NL', null) on conflict (ip) do nothing")
