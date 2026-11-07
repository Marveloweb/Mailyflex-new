import type { SupabaseClient } from '@supabase/supabase-js';
import { DohResolver, analyzeSpf, flattenForHosting, renderZoneRecords, type FlatRecord, type HostedEnv } from '@mailyflex/core';
import type { DomainRow } from '../_shared/supabase.ts';
import { ensureCustomHostname, reconcileTxt, removeCustomHostname } from '../_shared/cloudflare.ts';

export interface SpfConfigRow {
  domain_id: string;
  includes: string[];
  ip4: string[];
  ip6: string[];
  all_qualifier: '-' | '~';
  flattened: FlatRecord[] | null;
}

/** Build the record that lists the customer's senders, then flatten it. Returns null on DNS trouble. */
export async function flattenSpfConfig(domain: DomainRow, cfg: SpfConfigRow, env: HostedEnv) {
  const terms = [...cfg.includes.map((i) => `include:${i}`), ...cfg.ip4.map((i) => `ip4:${i}`), ...cfg.ip6.map((i) => `ip6:${i}`)];
  const analysis = await analyzeSpf(domain.name, new DohResolver(), { recordOverride: `v=spf1 ${terms.join(' ')} -all` });
  const dnsTrouble = analysis.errors.filter((e) => /temporary error|lookup failed|no SPF record/i.test(e));
  if (dnsTrouble.length) return { ok: false as const, error: dnsTrouble.join(' ') };
  return {
    ok: true as const,
    flattened: flattenForHosting(domain.report_token, analysis.ip4, analysis.ip6, analysis.unflattenable, env),
    lookupCount: analysis.lookupCount,
  };
}

export async function syncDomain(db: SupabaseClient, domain: DomainRow, env: HostedEnv) {
  const [{ data: dmarc }, { data: spf }, { data: sts }] = await Promise.all([
    db.from('dmarc_policies').select('*').eq('domain_id', domain.id).maybeSingle(),
    db.from('spf_configs').select('*').eq('domain_id', domain.id).maybeSingle<SpfConfigRow>(),
    db.from('mta_sts_configs').select('*').eq('domain_id', domain.id).maybeSingle(),
  ]);
  const verified = !!domain.verified_at;
  let spfFlattened: FlatRecord[] | null = null;
  let spfError: string | null = null;
  if (verified && domain.hosted_spf && spf) {
    const f = await flattenSpfConfig(domain, spf, env);
    if (f.ok) {
      spfFlattened = f.flattened;
      await db.from('spf_configs').update({ flattened: f.flattened, lookup_count: f.lookupCount, flattened_at: new Date().toISOString(), last_error: null }).eq('domain_id', domain.id);
    } else {
      // Keep serving the last good flattening rather than publishing a partial record.
      spfFlattened = spf.flattened;
      spfError = f.error;
      await db.from('spf_configs').update({ last_error: f.error }).eq('domain_id', domain.id);
    }
  }
  const desired = verified
    ? renderZoneRecords(
        {
          name: domain.name,
          token: domain.report_token,
          dmarc: domain.hosted_dmarc && dmarc ? { p: dmarc.p, sp: dmarc.sp, np: dmarc.np, adkim: dmarc.adkim, aspf: dmarc.aspf, t: dmarc.t, extraRua: dmarc.extra_rua } : null,
          spfFlattened: domain.hosted_spf ? spfFlattened : null,
          mtaSts: domain.hosted_mta_sts && sts ? { mode: sts.mode, policyId: sts.policy_id, tlsrptEnabled: sts.tlsrpt_enabled } : null,
        },
        env,
      )
    : [];
  const counts = await reconcileTxt(domain.report_token, desired);
  let customHostname: string | null = null;
  if (verified && domain.hosted_mta_sts && sts) {
    const h = await ensureCustomHostname(`mta-sts.${domain.name}`);
    customHostname = `${h.status}${h.ssl ? ` / ssl ${h.ssl.status}` : ''}`;
  } else {
    await removeCustomHostname(`mta-sts.${domain.name}`);
  }
  return { domain: domain.name, records: desired.length, ...counts, customHostname, spfError };
}

export async function removeDomainRecords(domain: DomainRow) {
  const counts = await reconcileTxt(domain.report_token, []);
  await removeCustomHostname(`mta-sts.${domain.name}`);
  return counts;
}
