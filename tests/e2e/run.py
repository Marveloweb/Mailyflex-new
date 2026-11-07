import asyncio, os, pathlib, subprocess, re, time, sys
from playwright.async_api import async_playwright, expect
HERE = pathlib.Path(__file__).parent
OUT = pathlib.Path(os.environ.get('E2E_OUT', '/tmp/mailyflex-e2e')); OUT.mkdir(parents=True, exist_ok=True)
# Optional: a fake Resend API that appends sent emails as JSON lines to this file.
EMAIL_LOG = os.environ.get('E2E_EMAIL_LOG')
BASE = os.environ.get('E2E_BASE', 'http://localhost:4173')
DB = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres'
STAMP = str(int(time.time()))
OWNER = f'owner{STAMP}@acme.test'
MATE = f'mate{STAMP}@acme.test'
DOMAIN = 'github.com'
def sql(q):
    return subprocess.run(['psql', DB, '-Atc', q], capture_output=True, text=True, check=True).stdout.strip()
errors = []
async def shot(pg, name):
    await pg.wait_for_timeout(700)
    await pg.screenshot(path=str(OUT / f'{name}.png'), full_page=True)
    print('shot', name, pg.url)
def watch(pg, who):
    pg.on('console', lambda m: errors.append(f'[{who}] {m.type}: {m.text}') if m.type == 'error' else None)
    pg.on('pageerror', lambda e: errors.append(f'[{who}] pageerror: {e}'))

async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path='/usr/bin/google-chrome')
        ctx = await b.new_context(viewport={'width': 1280, 'height': 900})
        pg = await ctx.new_page(); watch(pg, 'owner')
        # 1. sign up
        await pg.goto(BASE + '/signup')
        await pg.fill('#name', 'Olivia Owner'); await pg.fill('#email', OWNER); await pg.fill('#password', 'correct-horse-9')
        await pg.click('button[type=submit]')
        await pg.wait_for_url('**/app/new-org', timeout=20000)
        await shot(pg, '01-new-org')
        # 2. org
        await pg.fill('#org-name', 'Acme Test'); await pg.click('button[type=submit]')
        await pg.wait_for_url('**/app/domains/new', timeout=20000)
        # 3. domain
        await pg.fill('#new-domain', 'https://GitHub.com/'); await pg.click('button[type=submit]')
        await pg.wait_for_url(re.compile(r'.*/app/domains/[0-9a-f-]{36}$'), timeout=20000)
        domain_url = pg.url
        await pg.click('text=Verify domain')
        await pg.wait_for_selector('text=/We found|could not see/', timeout=30000)
        await shot(pg, '02-verify')
        # simulate the TXT record being found + reports arriving
        sql(f"update public.domains set verified_at = now() where name = '{DOMAIN}' and verified_at is null and org_id in (select id from public.organizations where name='Acme Test' order by created_at desc limit 1)")
        print(subprocess.run(['python3', str(HERE / 'seed.py'), DOMAIN], capture_output=True, text=True).stdout)
        # 4. scan
        await pg.reload()
        await pg.click('text=Check now')
        await pg.wait_for_selector('figure[role=img]', timeout=60000)
        await shot(pg, '03-overview')
        # 5. tabs
        await pg.click('nav >> text=Reports'); await pg.wait_for_selector('text=Messages per day', timeout=20000)
        await pg.hover('svg[role=img] rect >> nth=5')
        await shot(pg, '04-reports')
        await pg.click('nav >> text=Senders'); await pg.wait_for_selector('text=Who sends email', timeout=20000)
        await shot(pg, '05-senders')
        await pg.click('nav >> text=Enforcement'); await pg.wait_for_selector('text=Path to p=reject', timeout=20000)
        await shot(pg, '06-enforcement')
        await pg.click('nav >> text=Hosted records'); await pg.wait_for_selector('text=Hosted DMARC', timeout=20000)
        await pg.click('section:has-text("Hosted DMARC") >> button:has-text("Turn on")')
        await pg.wait_for_selector('text=/Publishing failed|Saved and published/', timeout=30000)
        await shot(pg, '07-hosted')
        # 6. alerts
        sql("insert into public.alerts (org_id, domain_id, kind, severity, title, body) select d.org_id, d.id, 'dns_change', 'critical', 'github.com: SPF record was removed', 'Before: v=spf1 ...\nAfter: (none)' from public.domains d join public.organizations o on o.id=d.org_id where o.name='Acme Test' and d.name='github.com'")
        await pg.goto(BASE + '/app/alerts'); await pg.wait_for_selector('text=SPF record was removed')
        await shot(pg, '08-alerts')
        await pg.click('text=Mark as read'); await pg.wait_for_timeout(800)
        # 7. settings + invite
        await pg.goto(BASE + '/app/settings'); await pg.wait_for_selector('text=Team')
        await pg.fill('#invite-email', MATE); await pg.select_option('select[aria-label=Role]', 'admin'); await pg.click('text=Send invite')
        await pg.wait_for_selector('text=/share this link|Invite sent/', timeout=20000)
        if EMAIL_LOG:
            import json as _j
            mails = [_j.loads(l) for l in open(EMAIL_LOG)]
            inv = [m for m in mails if MATE in m['to']][-1]
            print('email subject:', inv['subject'])
            link = re.search(r'(https?://\S+/invite/[0-9a-f]+)', inv['text']).group(1)
        else:  # no RESEND_API_KEY: the app shows the link to copy
            link = await pg.locator('code').filter(has_text='/invite/').inner_text()
        print('invite link', link)
        await shot(pg, '09-settings')
        # 8. teammate accepts
        ctx2 = await b.new_context(viewport={'width': 1280, 'height': 900}); pg2 = await ctx2.new_page(); watch(pg2, 'mate')
        await pg2.goto(link.replace('https://app.mailyflex.com', BASE).replace('http://localhost:4173', BASE))
        await pg2.wait_for_url('**/signup**', timeout=20000)
        await pg2.fill('#name', 'Max Mate'); await pg2.fill('#email', MATE); await pg2.fill('#password', 'correct-horse-9'); await pg2.click('button[type=submit]')
        await pg2.wait_for_url(BASE + '/app', timeout=30000)
        await pg2.wait_for_selector('text=github.com', timeout=20000)
        await shot(pg2, '10-mate-dashboard')
        # 9. domain list for owner, mobile view
        await pg.goto(BASE + '/app'); await pg.wait_for_selector('text=github.com')
        await shot(pg, '11-domains')
        mob = await b.new_context(viewport={'width': 390, 'height': 844}, storage_state=await ctx.storage_state())
        pm = await mob.new_page(); watch(pm, 'mobile')
        await pm.goto(domain_url + '/reports'); await pm.wait_for_selector('text=Messages per day', timeout=20000)
        await shot(pm, '12-mobile-reports')
        await b.close()
    print('CONSOLE ERRORS:', errors or 'none')
asyncio.run(main())
