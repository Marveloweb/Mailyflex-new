import type { SupabaseClient } from '@supabase/supabase-js';
import { DohResolver, diffSnapshots, directPolicyFetcher, reportAddress, scanDomain, type ScanResult } from '@mailyflex/core';
import { hostedEnv } from './env.ts';
import { createAlerts, emailPendingCritical, type NewAlert } from './alerts.ts';
import type { DomainRow } from './supabase.ts';

const RECORD_LABELS: Record<string, string> = {
  spf: 'SPF record',
  dmarc: 'DMARC record',
  mx: 'MX records',
  'mta-sts': 'MTA-STS record',
  'mta-sts-policy': 'MTA-STS policy file',
  'tls-rpt': 'TLS-RPT record',
  bimi: 'BIMI record',
};

function label(key: string): string {
  return key.startsWith('dkim:') ? `DKIM key "${key.slice(5)}"` : (RECORD_LABELS[key] ?? key);
}

async function hash(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
  return Array.from(d.slice(0, 8), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Run a scan, store it, update the domain and raise change / blocklist / score alerts. */
export async function runScan(db: SupabaseClient, domain: DomainRow): Promise<ScanResult> {
  const result = await scanDomain(domain.name, {
    resolver: new DohResolver(),
    policyFetcher: directPolicyFetcher,
    dkimSelectors: domain.dkim_selectors,
    ruaAddress: reportAddress(domain.report_token, hostedEnv()),
  });
  const { data: prev } = await db
    .from('domain_scans')
    .select('score, records')
    .eq('domain_id', domain.id)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  const { error: insErr } = await db.from('domain_scans').insert({
    domain_id: domain.id,
    score: result.score,
    grade: result.grade,
    result,
    records: result.records,
  });
  if (insErr) throw insErr;
  await db.from('domains').update({ health_score: result.score, grade: result.grade, last_scan_at: result.scannedAt }).eq('id', domain.id);

  const alerts: NewAlert[] = [];
  const base = { org_id: domain.org_id, domain_id: domain.id };
  // Only alert on DNS changes for verified domains with a previous scan, and only when DNS lookups succeeded.
  const lookupsOk = ![result.spf, result.dmarc, result.mx].some((a) => a.status === 'error');
  if (prev && domain.verified_at && lookupsOk) {
    for (const c of diffSnapshots(prev.records ?? {}, result.records)) {
      const removed = c.after.length === 0;
      const critical = removed && (c.key === 'spf' || c.key === 'dmarc' || c.key.startsWith('dkim:'));
      alerts.push({
        ...base,
        kind: 'dns_change',
        severity: critical ? 'critical' : 'warning',
        title: `${domain.name}: ${label(c.key)} ${removed ? 'was removed' : c.before.length === 0 ? 'was added' : 'changed'}`,
        body: `Before: ${c.before.join(' | ') || '(none)'}\nAfter: ${c.after.join(' | ') || '(none)'}`,
        dedupe_key: `dns:${domain.id}:${c.key}:${await hash(JSON.stringify(c.after))}`,
      });
    }
    if (typeof prev.score === 'number' && prev.score - result.score >= 15) {
      alerts.push({
        ...base,
        kind: 'score_drop',
        severity: 'warning',
        title: `${domain.name}: health score dropped from ${prev.score} to ${result.score}`,
        body: result.fixes.slice(0, 3).map((f) => f.title).join('; '),
        dedupe_key: `score:${domain.id}:${result.scannedAt.slice(0, 10)}`,
      });
    }
  }
  const week = Math.floor(Date.now() / (7 * 86400_000));
  for (const l of result.blacklist?.listed ?? []) {
    alerts.push({
      ...base,
      kind: 'blacklist',
      severity: 'critical',
      title: `${l.target} is listed on ${l.name}`,
      body: `Mail from ${l.target} may be blocked. Request removal at ${l.delistUrl} after fixing the cause.`,
      dedupe_key: `bl:${domain.id}:${l.zone}:${l.target}:${week}`,
    });
  }
  if (alerts.length) {
    await createAlerts(db, alerts);
    await emailPendingCritical(db, domain.org_id);
  }
  return result;
}
