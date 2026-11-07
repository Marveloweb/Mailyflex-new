import { useEffect, useState, type ReactNode } from 'react';
import { SPF_PRESETS, customerRecords, hostedNames, isSpfRecord, type CustomerRecord, type DmarcPolicy, type SpfMechanism } from '@mailyflex/core';
import { Badge, Button, Field, Input, Notice, RecordBlock, Select, Spinner } from '../../components/ui.tsx';
import { hostedEnv } from '../../lib/config.ts';
import { timeAgo } from '../../lib/format.ts';
import { atLeast } from '../../lib/org.tsx';
import { newResolver } from '../../lib/resolver.ts';
import { callFunction, db, errorMessage } from '../../lib/supabase.ts';
import type { DmarcPolicyRow, MtaStsConfigRow, SpfConfigRow } from '../../lib/types.ts';
import { useDomain } from './domainContext.tsx';

type Feature = 'dmarc' | 'spf' | 'mtaSts';

/** Live DNS check: is the customer's delegation record in place? */
async function delegationStatus(domain: string, token: string): Promise<Record<Feature, boolean>> {
  const r = newResolver();
  const n = hostedNames(token, hostedEnv);
  const [dmarc, spf, sts, stsHost] = await Promise.all([
    r.query(`_dmarc.${domain}`, 'CNAME'),
    r.query(domain, 'TXT'),
    r.query(`_mta-sts.${domain}`, 'CNAME'),
    r.query(`mta-sts.${domain}`, 'CNAME'),
  ]);
  return {
    dmarc: dmarc.answers.some((a) => a.data === n.dmarc),
    spf: spf.answers.some((a) => isSpfRecord(a.data) && a.data.toLowerCase().includes(`include:${n.spf}`)),
    mtaSts: sts.answers.some((a) => a.data === n.mtaSts) && stsHost.answers.some((a) => a.data === hostedEnv.mtaStsTarget),
  };
}

function Panel({ title, description, enabled, delegated, children }: { title: string; description: string; enabled: boolean; delegated: boolean | null; children: ReactNode }) {
  return (
    <section className="space-y-5 rounded-xl border border-rule bg-sheet p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-xl">{title}</h2>
          <p className="mt-1 max-w-2xl text-ink-soft">{description}</p>
        </div>
        {enabled ? (
          delegated === null ? (
            <Spinner />
          ) : delegated ? (
            <Badge status="pass">Live</Badge>
          ) : (
            <Badge status="warn">Waiting for your DNS change</Badge>
          )
        ) : (
          <Badge status="neutral">Off</Badge>
        )}
      </div>
      {children}
    </section>
  );
}

function Records({ records }: { records: CustomerRecord[] }) {
  return (
    <div className="space-y-3">
      <p className="text-[15px] font-medium">Add at your DNS provider, once:</p>
      {records.map((r) => (
        <RecordBlock key={r.host} type={r.type} host={r.host} value={r.value} note={r.note} />
      ))}
    </div>
  );
}

const policyOpts = (
  <>
    <option value="none">none (monitor)</option>
    <option value="quarantine">quarantine (spam folder)</option>
    <option value="reject">reject (block)</option>
  </>
);

export function DomainHosted() {
  const { domain, scan, reload, role } = useDomain();
  const canEdit = atLeast(role, 'admin');
  const records = customerRecords(domain.name, domain.report_token, hostedEnv);
  const [delegated, setDelegated] = useState<Record<Feature, boolean> | null>(null);
  const [dmarc, setDmarc] = useState<DmarcPolicyRow | null>(null);
  const [spf, setSpf] = useState<SpfConfigRow | null>(null);
  const [sts, setSts] = useState<MtaStsConfigRow | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState<Feature | null>(null);
  const [message, setMessage] = useState<{ feature: Feature; status: 'pass' | 'fail' | 'warn'; text: string } | null>(null);

  useEffect(() => {
    void delegationStatus(domain.name, domain.report_token).then(setDelegated);
    Promise.all([
      db().from('dmarc_policies').select('*').eq('domain_id', domain.id).maybeSingle(),
      db().from('spf_configs').select('*').eq('domain_id', domain.id).maybeSingle(),
      db().from('mta_sts_configs').select('*').eq('domain_id', domain.id).maybeSingle(),
    ]).then(([a, b, c]) => {
      const current = scan?.result.dmarc.parsed?.record;
      setDmarc(
        (a.data as DmarcPolicyRow) ?? {
          domain_id: domain.id,
          p: (current?.p ?? 'none') as DmarcPolicy,
          sp: current?.sp ?? null,
          np: current?.np ?? null,
          adkim: current?.adkim ?? 'r',
          aspf: current?.aspf ?? 'r',
          t: current?.t === 'y',
          extra_rua: [],
        },
      );
      const terms = (scan?.result.spf.parsed?.terms ?? []).filter((t): t is SpfMechanism => t.kind === 'mechanism' && t.qualifier === '+');
      setSpf(
        (b.data as SpfConfigRow) ?? {
          domain_id: domain.id,
          includes: terms.filter((t) => t.name === 'include' && !t.value!.includes(hostedEnv.zone)).map((t) => t.value!),
          ip4: terms.filter((t) => t.name === 'ip4').map((t) => t.value!),
          ip6: terms.filter((t) => t.name === 'ip6').map((t) => t.value!),
          all_qualifier: scan?.result.spf.allQualifier === '-' ? '-' : '~',
          flattened: null,
          lookup_count: null,
          flattened_at: null,
          last_error: null,
        },
      );
      setSts(
        (c.data as MtaStsConfigRow) ?? {
          domain_id: domain.id,
          mode: 'testing',
          mx: scan?.result.mx.hosts.map((h) => h.host) ?? [],
          max_age: 604800,
          policy_id: '',
          tlsrpt_enabled: true,
        },
      );
      setLoaded(true);
    });
  }, [domain.id, domain.name, domain.report_token, scan]);

  if (!loaded || !dmarc || !spf || !sts) return <Spinner />;

  const save = async (feature: Feature, enable: boolean) => {
    setBusy(feature);
    setMessage(null);
    try {
      if (feature === 'dmarc' && enable) {
        const { error } = await db().from('dmarc_policies').upsert({ domain_id: domain.id, p: dmarc.p, sp: dmarc.sp, np: dmarc.np, adkim: dmarc.adkim, aspf: dmarc.aspf, t: dmarc.t, extra_rua: dmarc.extra_rua });
        if (error) throw error;
      }
      if (feature === 'spf' && enable) {
        const { error } = await db().from('spf_configs').upsert({ domain_id: domain.id, includes: spf.includes, ip4: spf.ip4, ip6: spf.ip6, all_qualifier: spf.all_qualifier });
        if (error) throw error;
      }
      if (feature === 'mtaSts' && enable) {
        if (!sts.mx.length) throw new Error('List at least one MX host.');
        const { error } = await db().from('mta_sts_configs').upsert({ domain_id: domain.id, mode: sts.mode, mx: sts.mx, max_age: sts.max_age, tlsrpt_enabled: sts.tlsrpt_enabled });
        if (error) throw error;
      }
      const flag = feature === 'dmarc' ? 'hosted_dmarc' : feature === 'spf' ? 'hosted_spf' : 'hosted_mta_sts';
      const { error } = await db().from('domains').update({ [flag]: enable }).eq('id', domain.id);
      if (error) throw error;
      try {
        const r = await callFunction<{ spfError?: string | null }>('dns-sync', { domain_id: domain.id });
        setMessage({ feature, status: r.spfError ? 'warn' : 'pass', text: r.spfError ? `Saved, but SPF could not be refreshed: ${r.spfError}` : enable ? 'Saved and published.' : 'Turned off.' });
      } catch (e) {
        setMessage({ feature, status: 'warn', text: `Saved. Publishing failed: ${errorMessage(e)}` });
      }
      await reload();
      const { data } = await db().from('spf_configs').select('*').eq('domain_id', domain.id).maybeSingle();
      if (data) setSpf(data as SpfConfigRow);
    } catch (e) {
      setMessage({ feature, status: 'fail', text: errorMessage(e) });
    } finally {
      setBusy(null);
    }
  };

  const actions = (feature: Feature, enabled: boolean) =>
    canEdit && (
      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={() => save(feature, true)} busy={busy === feature} disabled={!domain.verified_at}>
          {enabled ? 'Save and publish' : 'Turn on'}
        </Button>
        {enabled && (
          <Button variant="ghost" onClick={() => save(feature, false)} disabled={busy === feature}>
            Turn off
          </Button>
        )}
        {!domain.verified_at && <span className="text-sm text-ink-soft">Verify the domain first.</span>}
      </div>
    );
  const msg = (f: Feature) => message?.feature === f && <Notice status={message.status}>{message.text}</Notice>;
  const list = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

  return (
    <div className="space-y-8">
      <p className="max-w-3xl text-ink-soft">
        Point a few records at Maily Flex once, and from then on you change policies and senders here instead of at your DNS provider.
      </p>

      <Panel title="Hosted DMARC" description="Change your DMARC policy in one click. Reports come to Maily Flex automatically." enabled={domain.hosted_dmarc} delegated={delegated?.dmarc ?? null}>
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Policy" htmlFor="h-p">
            <Select id="h-p" className="w-full" disabled={!canEdit} value={dmarc.p} onChange={(e) => setDmarc({ ...dmarc, p: e.target.value as DmarcPolicy })}>
              {policyOpts}
            </Select>
          </Field>
          <Field label="Subdomains" htmlFor="h-sp">
            <Select id="h-sp" className="w-full" disabled={!canEdit} value={dmarc.sp ?? ''} onChange={(e) => setDmarc({ ...dmarc, sp: (e.target.value || null) as DmarcPolicy | null })}>
              <option value="">Same as policy</option>
              {policyOpts}
            </Select>
          </Field>
          <Field label="Made-up subdomains (np)" htmlFor="h-np">
            <Select id="h-np" className="w-full" disabled={!canEdit} value={dmarc.np ?? ''} onChange={(e) => setDmarc({ ...dmarc, np: (e.target.value || null) as DmarcPolicy | null })}>
              <option value="">Not set</option>
              {policyOpts}
            </Select>
          </Field>
        </div>
        <label className="flex items-center gap-2 text-[15px]">
          <input type="checkbox" className="h-4 w-4 accent-[var(--color-ink)]" disabled={!canEdit || dmarc.p === 'none'} checked={dmarc.t} onChange={(e) => setDmarc({ ...dmarc, t: e.target.checked })} />
          Test mode (t=y)
        </label>
        <Field label="Also send reports to (optional)" htmlFor="h-rua">
          <Input id="h-rua" disabled={!canEdit} value={dmarc.extra_rua.join(' ')} onChange={(e) => setDmarc({ ...dmarc, extra_rua: list(e.target.value).map((a) => (a.startsWith('mailto:') ? a : `mailto:${a}`)) })} placeholder="security@yourcompany.com" />
        </Field>
        {(!domain.hosted_dmarc || !delegated?.dmarc) && <Records records={records.dmarc} />}
        {msg('dmarc')}
        {actions('dmarc', domain.hosted_dmarc)}
      </Panel>

      <Panel
        title="Hosted SPF"
        description="List your sending services here. We resolve them to IP addresses and publish a flattened record every 6 hours, so you stay under the 10-lookup limit."
        enabled={domain.hosted_spf}
        delegated={delegated?.spf ?? null}
      >
        <fieldset>
          <legend className="mb-2 text-sm font-medium">Services</legend>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 md:grid-cols-3">
            {SPF_PRESETS.map((p) => (
              <label key={p.key} className="flex items-center gap-2 text-[15px]">
                <input
                  type="checkbox"
                  className="h-4 w-4 accent-[var(--color-ink)]"
                  disabled={!canEdit}
                  checked={spf.includes.includes(p.include)}
                  onChange={(e) => setSpf({ ...spf, includes: e.target.checked ? [...spf.includes, p.include] : spf.includes.filter((i) => i !== p.include) })}
                />
                {p.name}
              </label>
            ))}
          </div>
        </fieldset>
        <Field label="Other include domains" htmlFor="h-inc">
          <Input
            id="h-inc"
            disabled={!canEdit}
            value={spf.includes.filter((i) => !SPF_PRESETS.some((p) => p.include === i)).join(' ')}
            onChange={(e) => setSpf({ ...spf, includes: [...spf.includes.filter((i) => SPF_PRESETS.some((p) => p.include === i)), ...list(e.target.value)] })}
          />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="IPv4" htmlFor="h-ip4">
            <Input id="h-ip4" disabled={!canEdit} value={spf.ip4.join(' ')} onChange={(e) => setSpf({ ...spf, ip4: list(e.target.value) })} />
          </Field>
          <Field label="IPv6" htmlFor="h-ip6">
            <Input id="h-ip6" disabled={!canEdit} value={spf.ip6.join(' ')} onChange={(e) => setSpf({ ...spf, ip6: list(e.target.value) })} />
          </Field>
        </div>
        {spf.flattened_at && (
          <p className="text-[15px] text-ink-soft">
            Last flattened {timeAgo(spf.flattened_at)} into {spf.flattened?.length ?? 0} record{spf.flattened?.length === 1 ? '' : 's'}; your services need {spf.lookup_count} lookups unflattened.
          </p>
        )}
        {spf.last_error && <Notice status="warn" title="Last refresh kept the previous record">{spf.last_error}</Notice>}
        <Records records={customerRecords(domain.name, domain.report_token, hostedEnv, { allQualifier: spf.all_qualifier }).spf} />
        {msg('spf')}
        {actions('spf', domain.hosted_spf)}
      </Panel>

      <Panel
        title="Hosted MTA-STS and TLS reporting"
        description="Tells other mail servers to deliver to you only over verified TLS. We host the policy file and certificate; start in testing mode."
        enabled={domain.hosted_mta_sts}
        delegated={delegated?.mtaSts ?? null}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Mode" htmlFor="h-mode">
            <Select id="h-mode" className="w-full" disabled={!canEdit} value={sts.mode} onChange={(e) => setSts({ ...sts, mode: e.target.value as MtaStsConfigRow['mode'] })}>
              <option value="testing">testing: report problems only</option>
              <option value="enforce">enforce: refuse insecure delivery</option>
              <option value="none">none: switch the policy off</option>
            </Select>
          </Field>
          <Field label="Policy lifetime" htmlFor="h-age">
            <Select id="h-age" className="w-full" disabled={!canEdit} value={sts.max_age} onChange={(e) => setSts({ ...sts, max_age: Number(e.target.value) })}>
              <option value={86400}>1 day</option>
              <option value={604800}>1 week</option>
              <option value={2592000}>30 days</option>
            </Select>
          </Field>
        </div>
        <Field label="Mail servers (MX)" htmlFor="h-mx" hint="Every MX host must match. Wildcards like *.mail.protection.outlook.com are allowed.">
          <Input id="h-mx" disabled={!canEdit} value={sts.mx.join(' ')} onChange={(e) => setSts({ ...sts, mx: list(e.target.value.toLowerCase()) })} />
        </Field>
        <Records records={records.mtaSts} />
        {msg('mtaSts')}
        {actions('mtaSts', domain.hosted_mta_sts)}
      </Panel>
    </div>
  );
}
