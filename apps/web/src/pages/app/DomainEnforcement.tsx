import { useEffect, useState } from 'react';
import { ENFORCEMENT_LADDER, buildDmarc, nextStep, readiness, stepIndex, type ReadinessCheck } from '@mailyflex/core';
import { Badge, Button, Notice, RecordBlock, Section, Spinner } from '../../components/ui.tsx';
import { hostedEnv } from '../../lib/config.ts';
import { atLeast } from '../../lib/org.tsx';
import { callFunction, db, errorMessage } from '../../lib/supabase.ts';
import type { DmarcPolicyRow, SenderStat } from '../../lib/types.ts';
import { reportAddress } from '@mailyflex/core';
import { useDomain } from './domainContext.tsx';

export function DomainEnforcement() {
  const { domain, scan, role, reload } = useDomain();
  const [checks, setChecks] = useState<{ ready: boolean; checks: ReadinessCheck[] } | null>(null);
  const [hosted, setHosted] = useState<DmarcPolicyRow | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ status: 'pass' | 'fail'; text: string } | null>(null);

  useEffect(() => {
    Promise.all([
      db().rpc('domain_daily_stats', { p_domain: domain.id, p_days: 14 }),
      db().rpc('domain_sender_stats', { p_domain: domain.id, p_days: 14 }),
      db().from('dmarc_policies').select('*').eq('domain_id', domain.id).maybeSingle(),
    ]).then(([daily, senders, pol]) => {
      const days = (daily.data ?? []) as { total: number; passing: number }[];
      const total = days.reduce((a, d) => a + Number(d.total), 0);
      const passing = days.reduce((a, d) => a + Number(d.passing), 0);
      const unknownFailing = ((senders.data ?? []) as SenderStat[]).filter((s) => !s.sender_key).map((s) => Number(s.total) - Number(s.passing));
      const spf = scan?.result.spf;
      setChecks(
        readiness({
          daysWithData: days.length,
          passRate: total ? passing / total : 0,
          largestUnknownShare: total ? Math.max(0, ...unknownFailing) / total : 0,
          spfLookups: domain.hosted_spf ? 1 : spf?.record ? spf.lookupCount : null,
          hasDkim: !!scan?.result.dkim.selectors.some((s) => s.parsed.valid && !s.parsed.revoked),
        }),
      );
      setHosted((pol.data as DmarcPolicyRow) ?? null);
    });
  }, [domain.id, domain.hosted_spf, scan]);

  if (!checks) return <Spinner />;
  const useHosted = domain.hosted_dmarc && !!hosted;
  const live = scan?.result.dmarc;
  const current = useHosted ? stepIndex(hosted!.p, hosted!.t) : stepIndex(live?.policy ?? null, live?.testing);
  const next = nextStep(current, checks.ready);

  const apply = async (target: (typeof ENFORCEMENT_LADDER)[number]) => {
    setBusy(true);
    setMsg(null);
    try {
      const { error } = await db().from('dmarc_policies').update({ p: target.p, t: target.t }).eq('domain_id', domain.id);
      if (error) throw error;
      await callFunction('dns-sync', { domain_id: domain.id });
      setMsg({ status: 'pass', text: `Policy is now ${target.label.toLowerCase()}. Receivers pick it up within the record's TTL (5 minutes).` });
      setHosted({ ...hosted!, p: target.p, t: target.t });
      await reload();
    } catch (e) {
      setMsg({ status: 'fail', text: errorMessage(e) });
    } finally {
      setBusy(false);
    }
  };

  const manualRecord = (target: (typeof ENFORCEMENT_LADDER)[number]) => {
    const r = live?.parsed?.record;
    return buildDmarc({
      p: target.p,
      ...(r?.sp ? { sp: r.sp } : {}),
      ...(r?.np ? { np: r.np } : {}),
      adkim: r?.adkim,
      aspf: r?.aspf,
      t: target.t,
      rua: r?.rua.length ? r.rua : [reportAddress(domain.report_token, hostedEnv)],
    });
  };

  return (
    <div className="space-y-10">
      <Section title="Path to p=reject" description="Each step is offered only when your reports show it is safe. You can always step back.">
        <ol className="space-y-3">
          {ENFORCEMENT_LADDER.map((s, i) => (
            <li key={s.label} className={`grid grid-cols-[2rem_1fr] gap-3 rounded-lg px-3 py-2 ${i === current ? 'bg-sheet shadow-[inset_3px_0_0_var(--color-airmail-red)]' : ''}`}>
              <span className={`font-display text-xl font-bold ${i <= current ? 'text-airmail-red' : 'text-ink-faint'}`}>{i + 1}</span>
              <div>
                <p className="font-medium">
                  {s.label} {i === current && <Badge status="info">You are here</Badge>}
                </p>
                <p className="text-[15px] text-ink-soft">{s.description}</p>
              </div>
            </li>
          ))}
        </ol>
        {current === -1 && <Notice status="warn">No DMARC record found. Publish one first (see Overview).</Notice>}
      </Section>

      <Section title="Readiness, last 14 days">
        <ul className="space-y-2">
          {checks.checks.map((c) => (
            <li key={c.id} className="flex items-start gap-3">
              <Badge status={c.ok ? 'pass' : 'warn'}>{c.ok ? 'Ready' : 'Not yet'}</Badge>
              <span>
                <span className="font-medium">{c.label}.</span> <span className="text-ink-soft">{c.detail}</span>
              </span>
            </li>
          ))}
        </ul>
      </Section>

      {msg && <Notice status={msg.status}>{msg.text}</Notice>}
      {next && atLeast(role, 'admin') && (
        <Section title={`Next: ${next.label}`} description={next.description}>
          {useHosted ? (
            <Button onClick={() => apply(next)} busy={busy}>
              Move to {next.label.toLowerCase()}
            </Button>
          ) : (
            <RecordBlock type="TXT" host={`_dmarc.${domain.name}`} value={manualRecord(next)} note="Replace your current DMARC record with this one, or turn on hosted DMARC to do it in one click." />
          )}
        </Section>
      )}
      {!next && current >= 0 && current < ENFORCEMENT_LADDER.length - 1 && (
        <Notice status="info" title="Not ready for the next step">
          Fix the items above first. Most domains get there by turning on DKIM for each sending service in the Senders tab.
        </Notice>
      )}
      {current === ENFORCEMENT_LADDER.length - 1 && (
        <Notice status="pass" title="Fully enforced">
          Spoofed mail using your domain is rejected. Keep watching the Senders tab when you add new services.
        </Notice>
      )}
      {useHosted && current > 0 && atLeast(role, 'admin') && (
        <Button variant="ghost" onClick={() => apply(ENFORCEMENT_LADDER[current - 1]!)} disabled={busy}>
          Step back to {ENFORCEMENT_LADDER[current - 1]!.label.toLowerCase()}
        </Button>
      )}
    </div>
  );
}
