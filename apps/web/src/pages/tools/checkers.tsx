import { Link } from 'react-router';
import {
  analyzeBimi,
  analyzeBlacklists,
  analyzeDkim,
  analyzeDmarc,
  analyzeMtaSts,
  analyzeMx,
  analyzeSpf,
  analyzeTlsRpt,
  scanDomain,
  type ScanResult,
} from '@mailyflex/core';
import { BimiView, BlacklistView, DkimView, DmarcView, FixList, MtaStsView, MxView, SpfView, TlsRptView } from '../../components/checks.tsx';
import { ScoreStamp } from '../../components/ScoreStamp.tsx';
import { browserPolicyFetcher, newResolver } from '../../lib/resolver.ts';
import { CheckError, DomainForm, ToolPage, useDomainCheck } from './shared.tsx';

export function FullReport({ r }: { r: ScanResult }) {
  return (
    <div className="space-y-10">
      <div className="flex flex-col items-start gap-6 sm:flex-row sm:items-center">
        <ScoreStamp score={r.score} grade={r.grade} animate />
        <div>
          <h2 className="text-2xl">{r.domain}</h2>
          <p className="mt-1 text-ink-soft">
            {r.fixes.filter((f) => f.severity === 'critical').length} urgent fix{r.fixes.filter((f) => f.severity === 'critical').length === 1 ? '' : 'es'}, checked with {r.dnsQueries} DNS queries.
          </p>
        </div>
      </div>
      <section className="space-y-4">
        <h2 className="text-xl">What to fix</h2>
        <FixList fixes={r.fixes} />
      </section>
      <div className="space-y-8 rounded-xl border border-rule bg-sheet p-6">
        <DmarcView a={r.dmarc} />
        <SpfView a={r.spf} />
        <DkimView a={r.dkim} />
        <MxView a={r.mx} />
        <MtaStsView a={r.mtaSts} fetched={!!browserPolicyFetcher} />
        <TlsRptView a={r.tlsRpt} />
        <BimiView a={r.bimi} />
        {r.blacklist && <BlacklistView a={r.blacklist} />}
      </div>
    </div>
  );
}

export function runFullScan(domain: string, selector?: string) {
  return scanDomain(domain, { resolver: newResolver(), policyFetcher: browserPolicyFetcher, dkimSelectors: selector ? [selector] : [] });
}

export function DomainCheckPage() {
  const c = useDomainCheck((d, sel) => runFullScan(d, sel), 'selector');
  return (
    <ToolPage title="Domain health check" intro="One check for everything that decides whether your email lands in the inbox: DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI and blocklists.">
      <DomainForm initial={c.domain} busy={c.busy} onSubmit={c.submit} extra={{ label: 'DKIM selector (optional)', placeholder: 'DKIM selector (optional)', initial: c.extra }} />
      <CheckError error={c.error} />
      {c.result && <FullReport r={c.result} />}
    </ToolPage>
  );
}

export function SpfCheckPage() {
  const c = useDomainCheck((d) => analyzeSpf(d, newResolver()));
  return (
    <ToolPage title="SPF checker" intro={<>Counts every DNS lookup in your SPF record, including nested includes. Receivers stop at 10 and fail SPF for all your mail.</>}>
      <DomainForm initial={c.domain} busy={c.busy} onSubmit={c.submit} cta="Check SPF" />
      <CheckError error={c.error} />
      {c.result && <SpfView a={c.result} />}
      <p className="text-ink-soft">
        Need a new record? Use the <Link className="text-airmail-blue underline" to="/tools/spf-generator">SPF generator</Link>.
      </p>
    </ToolPage>
  );
}

export function DmarcCheckPage() {
  const c = useDomainCheck((d) => analyzeDmarc(d, newResolver()));
  return (
    <ToolPage title="DMARC checker" intro="Validates your DMARC record against RFC 9989, including the new np, psd and t tags, and checks that your report addresses are allowed to receive reports.">
      <DomainForm initial={c.domain} busy={c.busy} onSubmit={c.submit} cta="Check DMARC" />
      <CheckError error={c.error} />
      {c.result && <DmarcView a={c.result} />}
      <p className="text-ink-soft">
        Need a record? Use the <Link className="text-airmail-blue underline" to="/tools/dmarc-generator">DMARC generator</Link>.
      </p>
    </ToolPage>
  );
}

export function DkimCheckPage() {
  const c = useDomainCheck((d, sel) => analyzeDkim(d, newResolver(), sel ? [sel] : []), 'selector');
  return (
    <ToolPage title="DKIM checker" intro="Finds DKIM keys on the selectors used by Google Workspace, Microsoft 365, Mailchimp, SendGrid and other services, and checks key strength.">
      <DomainForm initial={c.domain} busy={c.busy} onSubmit={c.submit} cta="Check DKIM" extra={{ label: 'Selector (optional)', placeholder: 'Selector (optional)', initial: c.extra }} />
      <CheckError error={c.error} />
      {c.result && <DkimView a={c.result} />}
    </ToolPage>
  );
}

export function MxCheckPage() {
  const c = useDomainCheck((d) => analyzeMx(d, newResolver()));
  return (
    <ToolPage title="MX lookup" intro="Shows which servers receive email for a domain and which provider runs them.">
      <DomainForm initial={c.domain} busy={c.busy} onSubmit={c.submit} cta="Look up MX" />
      <CheckError error={c.error} />
      {c.result && <MxView a={c.result} />}
    </ToolPage>
  );
}

export function MtaStsCheckPage() {
  const c = useDomainCheck(async (d) => {
    const r = newResolver();
    const mx = await analyzeMx(d, r);
    return analyzeMtaSts(d, r, browserPolicyFetcher, mx.hosts.map((h) => h.host));
  });
  return (
    <ToolPage title="MTA-STS checker" intro="Checks your MTA-STS record and policy file, and that every MX host is covered by the policy.">
      <DomainForm initial={c.domain} busy={c.busy} onSubmit={c.submit} cta="Check MTA-STS" />
      <CheckError error={c.error} />
      {c.result && <MtaStsView a={c.result} fetched={!!browserPolicyFetcher} />}
    </ToolPage>
  );
}

export function TlsRptCheckPage() {
  const c = useDomainCheck((d) => analyzeTlsRpt(d, newResolver()));
  return (
    <ToolPage title="TLS-RPT checker" intro="Checks the record that tells other mail servers where to report TLS delivery failures to your domain.">
      <DomainForm initial={c.domain} busy={c.busy} onSubmit={c.submit} cta="Check TLS-RPT" />
      <CheckError error={c.error} />
      {c.result && <TlsRptView a={c.result} />}
    </ToolPage>
  );
}

export function BimiCheckPage() {
  const c = useDomainCheck(async (d) => {
    const r = newResolver();
    return analyzeBimi(d, r, await analyzeDmarc(d, r));
  });
  return (
    <ToolPage title="BIMI checker" intro="Checks your BIMI record, logo URL and certificate, and whether your DMARC policy is strict enough for logos to show.">
      <DomainForm initial={c.domain} busy={c.busy} onSubmit={c.submit} cta="Check BIMI" />
      <CheckError error={c.error} />
      {c.result && <BimiView a={c.result} />}
    </ToolPage>
  );
}

export function BlacklistCheckPage() {
  const c = useDomainCheck(async (d) => {
    const r = newResolver();
    const mx = await analyzeMx(d, r);
    return analyzeBlacklists(d, mx.hosts.flatMap((h) => h.addresses), r);
  });
  return (
    <ToolPage title="Blocklist checker" intro="Checks your domain and mail server IPs against the DNS blocklists that mailbox providers use.">
      <DomainForm initial={c.domain} busy={c.busy} onSubmit={c.submit} cta="Check blocklists" />
      <CheckError error={c.error} />
      {c.result && <BlacklistView a={c.result} />}
    </ToolPage>
  );
}
