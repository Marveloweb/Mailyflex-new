import { useCallback, useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate, useParams } from 'react-router';
import { buildDmarc, reportAddress, verificationRecord, type DmarcPolicy } from '@mailyflex/core';
import { BimiView, BlacklistView, DkimView, DmarcView, FixList, MtaStsView, MxView, SpfView, TlsRptView } from '../../components/checks.tsx';
import { ScoreStamp } from '../../components/ScoreStamp.tsx';
import { Badge, Button, EmptyState, Field, Input, Notice, RecordBlock, Section, Spinner } from '../../components/ui.tsx';
import { hostedEnv } from '../../lib/config.ts';
import { timeAgo } from '../../lib/format.ts';
import { atLeast, useOrg } from '../../lib/org.tsx';
import { callFunction, db, errorMessage } from '../../lib/supabase.ts';
import type { DomainRow, ScanRow } from '../../lib/types.ts';
import { DomainContext, useDomain } from './domainContext.tsx';

export function DomainLayout() {
  const { id } = useParams();
  const { current } = useOrg();
  const [domain, setDomain] = useState<DomainRow | null | undefined>(undefined);
  const [scan, setScan] = useState<ScanRow | null>(null);

  const reload = useCallback(async () => {
    const [{ data: d }, { data: s }] = await Promise.all([
      db().from('domains').select('*').eq('id', id!).maybeSingle(),
      db().from('domain_scans').select('id, score, grade, result, created_at').eq('domain_id', id!).order('created_at', { ascending: false }).limit(1).maybeSingle(),
    ]);
    setDomain((d as DomainRow) ?? null);
    setScan((s as ScanRow) ?? null);
  }, [id]);

  useEffect(() => {
    void reload();
  }, [reload]);

  if (domain === undefined) return <Spinner />;
  if (domain === null) return <EmptyState title="Domain not found">It may have been removed, or it belongs to another organization.</EmptyState>;

  const tab = ({ isActive }: { isActive: boolean }) =>
    `-mb-px whitespace-nowrap border-b-2 px-1 pb-2 text-[15px] ${isActive ? 'border-airmail-red font-medium text-ink' : 'border-transparent text-ink-soft hover:text-ink'}`;
  return (
    <DomainContext.Provider value={{ domain, scan, role: current?.role, reload }}>
      <div className="space-y-8">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-3xl break-all">{domain.name}</h1>
          {domain.verified_at ? <Badge status="pass">Verified</Badge> : <Badge status="warn">Not verified</Badge>}
        </div>
        <nav className="flex gap-6 overflow-x-auto border-b border-rule" aria-label="Domain sections">
          <NavLink end to={`/app/domains/${domain.id}`} className={tab}>
            Overview
          </NavLink>
          <NavLink to={`/app/domains/${domain.id}/reports`} className={tab}>
            Reports
          </NavLink>
          <NavLink to={`/app/domains/${domain.id}/senders`} className={tab}>
            Senders
          </NavLink>
          <NavLink to={`/app/domains/${domain.id}/hosted`} className={tab}>
            Hosted records
          </NavLink>
          <NavLink to={`/app/domains/${domain.id}/enforcement`} className={tab}>
            Enforcement
          </NavLink>
        </nav>
        <Outlet />
      </div>
    </DomainContext.Provider>
  );
}

function VerifyCard() {
  const { domain, reload, role } = useDomain();
  const rec = verificationRecord(domain.name, domain.verification_token);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ status: 'fail' | 'warn'; text: string } | null>(null);
  const verify = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await callFunction<{ verified: boolean; found?: string[] }>('domain-verify', { domain_id: domain.id });
      if (r.verified) await reload();
      else
        setMsg({
          status: 'warn',
          text: r.found?.length
            ? `We found ${r.found.length} TXT record(s) at that host, but not the one above. Check for typos.`
            : 'We could not see the record yet. DNS changes can take a few minutes to appear; try again shortly.',
        });
    } catch (e) {
      setMsg({ status: 'fail', text: errorMessage(e) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Section title="Prove you own this domain" description="Add this TXT record at your DNS provider. Monitoring, reports and hosted records start once it is verified.">
      <RecordBlock type={rec.type} host={rec.host} value={rec.value} />
      {msg && <Notice status={msg.status}>{msg.text}</Notice>}
      {atLeast(role, 'admin') ? (
        <Button onClick={verify} busy={busy}>
          Verify domain
        </Button>
      ) : (
        <p className="text-ink-soft">Ask an admin to verify this domain.</p>
      )}
    </Section>
  );
}

function ReportAddressCard() {
  const { domain, scan } = useDomain();
  const env = hostedEnv;
  const ours = reportAddress(domain.report_token, env);
  const dmarc = scan?.result.dmarc;
  const current = dmarc?.parsed?.record;
  const hasOurs = current?.rua.some((u) => u.toLowerCase() === `mailto:${ours}`);
  if (domain.hosted_dmarc || hasOurs || !scan) return null;
  const value = buildDmarc({
    p: (current?.p ?? 'none') as DmarcPolicy,
    ...(current?.sp ? { sp: current.sp } : {}),
    ...(current?.np ? { np: current.np } : {}),
    adkim: current?.adkim,
    aspf: current?.aspf,
    t: current?.t === 'y',
    rua: [ours, ...(current?.rua ?? [])],
    ruf: current?.ruf ?? [],
    ...(current?.fo ? { fo: current.fo } : {}),
  });
  return (
    <Section
      title="Send DMARC reports to Maily Flex"
      description={
        current
          ? 'Your DMARC record does not send reports to us yet. Update it to this (your current policy and report addresses are kept):'
          : 'Publish this DMARC record. It only monitors (p=none), so nothing gets blocked while we learn who sends your mail.'
      }
    >
      <RecordBlock type="TXT" host={`_dmarc.${domain.name}`} value={value} note="Or turn on hosted DMARC under Hosted records and we manage this record for you." />
    </Section>
  );
}

function SelectorsCard() {
  const { domain, reload, role } = useDomain();
  const [value, setValue] = useState(domain.dkim_selectors.join(', '));
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  if (!atLeast(role, 'admin')) return null;
  const save = async () => {
    setBusy(true);
    const selectors = value
      .split(/[\s,]+/)
      .map((s) => s.trim().toLowerCase())
      .filter((s) => /^[a-z0-9._-]{1,63}$/.test(s));
    await db().from('domains').update({ dkim_selectors: selectors }).eq('id', domain.id);
    await reload();
    setBusy(false);
    setSaved(true);
  };
  return (
    <Field label="Custom DKIM selectors" htmlFor="selectors" hint="We check common selectors automatically. Add yours if your provider uses a custom one.">
      <div className="flex gap-2">
        <Input id="selectors" value={value} onChange={(e) => (setValue(e.target.value), setSaved(false))} placeholder="mycorp2026, s1" />
        <Button variant="secondary" onClick={save} busy={busy}>
          {saved ? 'Saved' : 'Save'}
        </Button>
      </div>
    </Field>
  );
}

function DeleteDomain() {
  const { domain, role } = useDomain();
  const navigate = useNavigate();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!atLeast(role, 'admin')) return null;
  const remove = async () => {
    setBusy(true);
    setError(null);
    try {
      await callFunction('dns-sync', { domain_id: domain.id, action: 'remove' });
      navigate('/app');
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  };
  return (
    <div className="space-y-3 border-t border-rule pt-6">
      <h2 className="text-lg">Remove domain</h2>
      <p className="max-w-2xl text-ink-soft">
        Deletes this domain, its reports and history. Hosted records are removed too, so any CNAMEs pointing at Maily Flex will stop working. Point them back to your own records first.
      </p>
      {error && <Notice status="fail">{error}</Notice>}
      {confirming ? (
        <div className="flex gap-2">
          <Button variant="danger" onClick={remove} busy={busy}>
            Remove {domain.name}
          </Button>
          <Button variant="ghost" onClick={() => setConfirming(false)}>
            Keep it
          </Button>
        </div>
      ) : (
        <Button variant="danger" onClick={() => setConfirming(true)}>
          Remove domain
        </Button>
      )}
    </div>
  );
}

export function DomainOverview() {
  const { domain, scan, reload, role } = useDomain();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const rescan = async () => {
    setBusy(true);
    setError(null);
    try {
      await callFunction('domain-scan', { domain_id: domain.id });
      await reload();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const r = scan?.result;
  return (
    <div className="space-y-12">
      {!domain.verified_at && <VerifyCard />}
      <div className="flex flex-col gap-8 sm:flex-row sm:items-center">
        {scan ? <ScoreStamp score={scan.score} grade={scan.grade} /> : null}
        <div className="space-y-3">
          <p className="text-ink-soft">{scan ? `Checked ${timeAgo(scan.created_at)}. We recheck every 6 hours.` : 'Not checked yet.'}</p>
          {atLeast(role, 'member') && (
            <Button variant="secondary" onClick={rescan} busy={busy}>
              Check now
            </Button>
          )}
          {error && <Notice status="fail">{error}</Notice>}
        </div>
      </div>
      {r && (
        <Section title="What to fix" description="Ordered by impact. Each fix includes the record to paste at your DNS provider.">
          <FixList fixes={r.fixes} />
        </Section>
      )}
      <ReportAddressCard />
      {r && (
        <details className="rounded-xl border border-rule bg-sheet">
          <summary className="cursor-pointer px-6 py-4 font-medium">All record details</summary>
          <div className="space-y-8 px-6 pb-6">
            <DmarcView a={r.dmarc} />
            <SpfView a={r.spf} />
            <DkimView a={r.dkim} />
            <MxView a={r.mx} />
            <MtaStsView a={r.mtaSts} fetched />
            <TlsRptView a={r.tlsRpt} />
            <BimiView a={r.bimi} />
            {r.blacklist && <BlacklistView a={r.blacklist} />}
          </div>
        </details>
      )}
      <SelectorsCard />
      <DeleteDomain />
    </div>
  );
}
