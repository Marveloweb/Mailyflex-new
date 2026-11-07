/**
 * Policy-enforcement ladder with readiness gates based on real DMARC report data.
 */
import type { DmarcPolicy } from './dmarc.ts';

export interface PolicyStep {
  p: DmarcPolicy;
  t: boolean;
  label: string;
  description: string;
}

export const ENFORCEMENT_LADDER: PolicyStep[] = [
  { p: 'none', t: false, label: 'Monitor', description: 'Collect reports. Nothing is blocked.' },
  { p: 'quarantine', t: true, label: 'Quarantine (test)', description: 'Receivers that support RFC 9989 still deliver failing mail normally; you watch for problems.' },
  { p: 'quarantine', t: false, label: 'Quarantine', description: 'Mail that fails DMARC goes to spam.' },
  { p: 'reject', t: true, label: 'Reject (test)', description: 'Failing mail is quarantined, not rejected, while you confirm nothing legitimate breaks.' },
  { p: 'reject', t: false, label: 'Reject', description: 'Mail that fails DMARC is refused. Full protection against spoofing.' },
];

export function stepIndex(p: DmarcPolicy | null | undefined, t: boolean | undefined): number {
  if (!p) return -1;
  const i = ENFORCEMENT_LADDER.findIndex((s) => s.p === p && s.t === !!t);
  if (i >= 0) return i;
  return ENFORCEMENT_LADDER.findIndex((s) => s.p === p);
}

export interface ReadinessInput {
  /** Days of report data in the window. */
  daysWithData: number;
  /** Aligned pass rate (0–1) across mail from identified/authorised senders. */
  passRate: number;
  /** Share (0–1) of total volume from the largest unidentified failing source. */
  largestUnknownShare: number;
  spfLookups: number | null;
  hasDkim: boolean;
}

export interface ReadinessCheck {
  id: string;
  ok: boolean;
  label: string;
  detail: string;
}

export const READINESS_THRESHOLDS = { minDays: 7, minPassRate: 0.98, maxUnknownShare: 0.01, maxSpfLookups: 10 };

export function readiness(input: ReadinessInput): { ready: boolean; checks: ReadinessCheck[] } {
  const t = READINESS_THRESHOLDS;
  const checks: ReadinessCheck[] = [
    {
      id: 'data',
      ok: input.daysWithData >= t.minDays,
      label: `At least ${t.minDays} days of reports`,
      detail: `${input.daysWithData} day(s) of report data so far.`,
    },
    {
      id: 'pass-rate',
      ok: input.passRate >= t.minPassRate,
      label: `${Math.round(t.minPassRate * 100)}%+ of mail passes DMARC`,
      detail: `${(input.passRate * 100).toFixed(1)}% passes (SPF or DKIM aligned).`,
    },
    {
      id: 'unknown',
      ok: input.largestUnknownShare <= t.maxUnknownShare,
      label: 'No large unidentified failing sender',
      detail: `Largest unidentified failing source is ${(input.largestUnknownShare * 100).toFixed(1)}% of volume.`,
    },
    {
      id: 'spf',
      ok: input.spfLookups !== null && input.spfLookups <= t.maxSpfLookups,
      label: 'SPF within the 10-lookup limit',
      detail: input.spfLookups === null ? 'SPF record missing or not checked.' : `${input.spfLookups} lookup(s).`,
    },
    { id: 'dkim', ok: input.hasDkim, label: 'DKIM is set up', detail: input.hasDkim ? 'DKIM key found.' : 'No DKIM key found.' },
  ];
  return { ready: checks.every((c) => c.ok), checks };
}

/** The next step is offered only when ready; moving back down is always allowed. */
export function nextStep(current: number, ready: boolean): PolicyStep | null {
  if (!ready) return null;
  return ENFORCEMENT_LADDER[current + 1] ?? null;
}
