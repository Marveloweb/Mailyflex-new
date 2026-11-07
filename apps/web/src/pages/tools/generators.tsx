import { useEffect, useMemo, useState } from 'react';
import { SPF_PRESETS, analyzeSpf, buildDmarc, buildSpf, parseDmarc, type DmarcPolicy, type SpfAnalysis } from '@mailyflex/core';
import { Badge, Field, Input, RecordBlock, Select, Spinner } from '../../components/ui.tsx';
import { newResolver } from '../../lib/resolver.ts';
import { ToolPage } from './shared.tsx';

function splitList(s: string): string[] {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

export function SpfGeneratorPage() {
  const [domain, setDomain] = useState('');
  const [presets, setPresets] = useState<string[]>([]);
  const [customIncludes, setCustomIncludes] = useState('');
  const [ip4, setIp4] = useState('');
  const [ip6, setIp6] = useState('');
  const [mx, setMx] = useState(false);
  const [all, setAll] = useState<'-' | '~'>('~');
  const [analysis, setAnalysis] = useState<SpfAnalysis | null>(null);
  const [checking, setChecking] = useState(false);

  const built = useMemo(
    () =>
      buildSpf({
        includes: [...SPF_PRESETS.filter((p) => presets.includes(p.key)).map((p) => p.include), ...splitList(customIncludes)],
        ip4: splitList(ip4),
        ip6: splitList(ip6),
        mx,
        all,
      }),
    [presets, customIncludes, ip4, ip6, mx, all],
  );

  useEffect(() => {
    if (built.errors.length) return;
    let cancelled = false;
    const t = setTimeout(async () => {
      setChecking(true);
      const a = await analyzeSpf(domain || 'example.com', newResolver(), { recordOverride: built.record });
      if (!cancelled) {
        setAnalysis(a);
        setChecking(false);
      }
    }, 400);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [built, domain]);

  return (
    <ToolPage wide title="SPF record generator" intro="Pick the services that send email for you. We count the DNS lookups live so you stay under the limit of 10.">
      <div className="grid gap-10 md:grid-cols-[1fr_1.1fr]">
        <div className="space-y-5">
          <Field label="Your domain" htmlFor="spf-domain" hint="Used for the mx mechanism and the preview.">
            <Input id="spf-domain" value={domain} onChange={(e) => setDomain(e.target.value.trim().toLowerCase())} placeholder="yourcompany.com" />
          </Field>
          <fieldset className="space-y-2">
            <legend className="mb-1 text-sm font-medium">Services that send as you</legend>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
              {SPF_PRESETS.map((p) => (
                <label key={p.key} className="flex items-center gap-2 text-[15px]">
                  <input
                    type="checkbox"
                    className="h-4 w-4 accent-[var(--color-ink)]"
                    checked={presets.includes(p.key)}
                    onChange={(e) => setPresets((v) => (e.target.checked ? [...v, p.key] : v.filter((k) => k !== p.key)))}
                  />
                  {p.name}
                </label>
              ))}
            </div>
          </fieldset>
          <Field label="Other include domains" htmlFor="spf-inc" hint="From your provider's setup guide, separated by spaces.">
            <Input id="spf-inc" value={customIncludes} onChange={(e) => setCustomIncludes(e.target.value)} placeholder="spf.example-provider.com" />
          </Field>
          <Field label="IPv4 addresses or ranges" htmlFor="spf-ip4">
            <Input id="spf-ip4" value={ip4} onChange={(e) => setIp4(e.target.value)} placeholder="203.0.113.10 198.51.100.0/24" />
          </Field>
          <Field label="IPv6 addresses or ranges" htmlFor="spf-ip6">
            <Input id="spf-ip6" value={ip6} onChange={(e) => setIp6(e.target.value)} placeholder="2001:db8::/32" />
          </Field>
          <label className="flex items-center gap-2 text-[15px]">
            <input type="checkbox" className="h-4 w-4 accent-[var(--color-ink)]" checked={mx} onChange={(e) => setMx(e.target.checked)} />
            My inbound mail servers (MX) also send mail
          </label>
          <Field label="Mail from servers not on this list" htmlFor="spf-all">
            <Select id="spf-all" value={all} onChange={(e) => setAll(e.target.value as '-' | '~')}>
              <option value="~">Mark as suspicious (~all, recommended while setting up)</option>
              <option value="-">Reject (-all)</option>
            </Select>
          </Field>
        </div>
        <div className="space-y-4 md:sticky md:top-6 md:self-start">
          <h2 className="text-xl">Your record</h2>
          <RecordBlock type="TXT" host={domain || '@'} value={built.record} note="Replace any existing v=spf1 record; a domain can only have one." />
          {built.errors.map((e) => (
            <p key={e} className="text-[15px] text-fail">
              {e}
            </p>
          ))}
          {analysis && !built.errors.length && (
            <div className="flex flex-wrap items-center gap-3 text-[15px]">
              {checking && <Spinner />}
              <Badge status={analysis.lookupCount > 10 ? 'fail' : analysis.lookupCount > 8 ? 'warn' : 'pass'}>{analysis.lookupCount} of 10 lookups</Badge>
              {analysis.lookupCount > 10 && <span className="text-fail">Too many. Remove a service or use hosted SPF in Maily Flex.</span>}
            </div>
          )}
        </div>
      </div>
    </ToolPage>
  );
}

export function DmarcGeneratorPage() {
  const [domain, setDomain] = useState('');
  const [p, setP] = useState<DmarcPolicy>('none');
  const [sp, setSp] = useState<'' | DmarcPolicy>('');
  const [np, setNp] = useState<'' | DmarcPolicy>('');
  const [rua, setRua] = useState('');
  const [ruf, setRuf] = useState('');
  const [strict, setStrict] = useState(false);
  const [testing, setTesting] = useState(false);

  const record = buildDmarc({
    p,
    ...(sp ? { sp } : {}),
    ...(np ? { np } : {}),
    adkim: strict ? 's' : 'r',
    aspf: strict ? 's' : 'r',
    rua: splitList(rua),
    ruf: splitList(ruf),
    fo: '1',
    t: testing,
  });
  const parsed = parseDmarc(record);
  const policyOptions = (
    <>
      <option value="none">none: monitor only</option>
      <option value="quarantine">quarantine: send failing mail to spam</option>
      <option value="reject">reject: refuse failing mail</option>
    </>
  );
  return (
    <ToolPage wide title="DMARC record generator" intro="Build a DMARC record that follows RFC 9989. Start with p=none and a report address, then tighten the policy once reports show your real senders pass.">
      <div className="grid gap-10 md:grid-cols-[1fr_1.1fr]">
        <div className="space-y-5">
          <Field label="Your domain" htmlFor="d-domain">
            <Input id="d-domain" value={domain} onChange={(e) => setDomain(e.target.value.trim().toLowerCase())} placeholder="yourcompany.com" />
          </Field>
          <Field label="Policy" htmlFor="d-p">
            <Select id="d-p" value={p} onChange={(e) => setP(e.target.value as DmarcPolicy)} className="w-full">
              {policyOptions}
            </Select>
          </Field>
          <Field label="Subdomain policy (sp)" htmlFor="d-sp" hint="Leave as same to apply the main policy to subdomains.">
            <Select id="d-sp" value={sp} onChange={(e) => setSp(e.target.value as DmarcPolicy | '')} className="w-full">
              <option value="">Same as main policy</option>
              {policyOptions}
            </Select>
          </Field>
          <Field label="Policy for subdomains that don't exist (np)" htmlFor="d-np" hint="New in RFC 9989. Stops spoofing of made-up subdomains like billing.yourcompany.com.">
            <Select id="d-np" value={np} onChange={(e) => setNp(e.target.value as DmarcPolicy | '')} className="w-full">
              <option value="">Not set</option>
              {policyOptions}
            </Select>
          </Field>
          <Field label="Send aggregate reports to" htmlFor="d-rua" hint="Maily Flex gives every domain its own report address.">
            <Input id="d-rua" value={rua} onChange={(e) => setRua(e.target.value)} placeholder="dmarc@yourcompany.com" />
          </Field>
          <Field label="Send failure reports to (optional)" htmlFor="d-ruf" hint="May contain personal data; few providers send them.">
            <Input id="d-ruf" value={ruf} onChange={(e) => setRuf(e.target.value)} placeholder="" />
          </Field>
          <label className="flex items-center gap-2 text-[15px]">
            <input type="checkbox" className="h-4 w-4 accent-[var(--color-ink)]" checked={strict} onChange={(e) => setStrict(e.target.checked)} />
            Strict alignment (exact domain match for SPF and DKIM)
          </label>
          <label className="flex items-center gap-2 text-[15px]">
            <input type="checkbox" className="h-4 w-4 accent-[var(--color-ink)]" checked={testing} onChange={(e) => setTesting(e.target.checked)} disabled={p === 'none'} />
            Test mode (t=y): receivers apply one step softer while you check for problems
          </label>
        </div>
        <div className="space-y-4 md:sticky md:top-6 md:self-start">
          <h2 className="text-xl">Your record</h2>
          <RecordBlock type="TXT" host={`_dmarc.${domain || 'yourcompany.com'}`} value={record} />
          {[...parsed.errors].map((e) => (
            <p key={e} className="text-[15px] text-fail">
              {e}
            </p>
          ))}
          {!splitList(rua).length && <p className="text-[15px] text-warn">Add a report address, or you won't see who sends email as your domain.</p>}
        </div>
      </div>
    </ToolPage>
  );
}
