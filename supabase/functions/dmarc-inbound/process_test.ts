import { assertEquals } from 'jsr:@std/assert@1';
import { gzipSync, strToU8 } from 'fflate';
import { StaticResolver } from '@mailyflex/core';
import { processInbound, tokenFromRecipients, type IngestDeps } from './process.ts';
import { signSvix, verifySvix } from '../_shared/svix.ts';

const XML = `<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name><report_id>42</report_id>
<date_range><begin>1762387200</begin><end>1762473599</end></date_range></report_metadata>
<policy_published><domain>acme.com</domain><p>none</p></policy_published>
<record><row><source_ip>209.85.220.41</source_ip><count>10</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>acme.com</header_from></identifiers><auth_results><dkim><domain>acme.com</domain><result>pass</result></dkim><spf><domain>acme.com</domain><result>pass</result></spf></auth_results></record>
<record><row><source_ip>198.51.100.9</source_ip><count>3</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
<identifiers><header_from>acme.com</header_from></identifiers><auth_results><spf><domain>sendgrid.net</domain><result>pass</result></spf></auth_results></record>
</feedback>`;

Deno.test('token extraction', () => {
  assertEquals(tokenFromRecipients(['Reports <a1b2c3d4e5f6a7b8c9d0@rua.mailyflex.com>'], 'rua.mailyflex.com'), 'a1b2c3d4e5f6a7b8c9d0');
  assertEquals(tokenFromRecipients('a1b2c3d4e5+x@RUA.mailyflex.com', 'rua.mailyflex.com'), 'a1b2c3d4e5');
  assertEquals(tokenFromRecipients(['someone@else.com', 'not-hex@rua.mailyflex.com'], 'rua.mailyflex.com'), null);
});

Deno.test('processes a gzip report end to end with enrichment', async () => {
  const ingested: { token: string; report: any }[] = [];
  const saved: any[] = [];
  const deps: IngestDeps = {
    ruaDomain: 'rua.mailyflex.com',
    resolver: new StaticResolver({
      'PTR 41.220.85.209.in-addr.arpa': ['mail-sor-f41.google.com'],
      'TXT 41.220.85.209.origin.asn.cymru.com': ['15169 | 209.85.128.0/17 | US | arin | 2002-12-11'],
      'TXT as15169.asn.cymru.com': ['15169 | US | arin | 2000-03-30 | GOOGLE, US'],
    }),
    listAttachments: async () => [
      { filename: 'google.com!acme.com!1!2.xml.gz', content_type: 'application/gzip', bytes: async () => gzipSync(strToU8(XML)) },
      { filename: 'logo.png', content_type: 'image/png', bytes: async () => new Uint8Array() },
      { filename: 'broken.xml', content_type: 'text/xml', bytes: async () => strToU8('<html/>') },
    ],
    ingest: async (token, report) => {
      ingested.push({ token, report });
      return { status: 'stored' };
    },
    getIntel: async () => new Map(),
    saveIntel: async (rows) => {
      saved.push(...rows);
    },
  };
  const r = await processInbound({ type: 'email.received', data: { email_id: 'e1', to: ['abcdef0123456789abcd@rua.mailyflex.com'] } }, deps);
  assertEquals(r.token, 'abcdef0123456789abcd');
  assertEquals(r.reports.map((x) => x.status), ['stored', 'skipped', 'error']);
  const rep = ingested[0]!.report;
  assertEquals(rep.reportId, '42');
  assertEquals(rep.dateBegin, '2025-11-06T00:00:00.000Z');
  assertEquals(rep.records.map((x: any) => x.senderKey), ['google', 'sendgrid']);
  assertEquals(saved.find((s) => s.ip === '209.85.220.41')?.sender_key, 'google');
});

Deno.test('svix signatures', async () => {
  const secret = 'whsec_' + btoa('supersecretkey-0123456789');
  const now = 1_700_000_000;
  const sig = await signSvix(secret, 'msg_1', String(now), '{"a":1}');
  assertEquals(await verifySvix(secret, { id: 'msg_1', timestamp: String(now), signature: `v1,bogus v1,${sig}` }, '{"a":1}', now), true);
  assertEquals(await verifySvix(secret, { id: 'msg_1', timestamp: String(now), signature: `v1,${sig}` }, '{"a":2}', now), false);
  assertEquals(await verifySvix(secret, { id: 'msg_1', timestamp: String(now - 1000), signature: `v1,${sig}` }, '{"a":1}', now), false);
  assertEquals(await verifySvix(secret, { id: null, timestamp: String(now), signature: `v1,${sig}` }, '{"a":1}', now), false);
});
