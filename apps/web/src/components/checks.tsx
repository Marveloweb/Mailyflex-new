import type { ReactNode } from 'react';
import type { BimiAnalysis, BlacklistAnalysis, DkimAnalysis, DmarcAnalysis, Fix, MtaStsAnalysis, MxAnalysis, SpfAnalysis, SpfNode, TlsRptAnalysis } from '@mailyflex/core';
import { Badge, Code, RecordBlock, type Status } from './ui.tsx';

export function statusOf(s: string, opts: { missingIsFail?: boolean } = {}): { status: Status; label: string } {
  switch (s) {
    case 'ok':
      return { status: 'pass', label: 'Valid' };
    case 'missing':
      return opts.missingIsFail ? { status: 'fail', label: 'Missing' } : { status: 'neutral', label: 'Not set up' };
    case 'multiple':
      return { status: 'fail', label: 'Duplicate records' };
    case 'invalid':
      return { status: 'fail', label: 'Has problems' };
    case 'null-mx':
      return { status: 'info', label: 'Accepts no mail' };
    case 'error':
      return { status: 'warn', label: 'Lookup failed' };
    default:
      return { status: 'neutral', label: s };
  }
}

function Messages({ errors, warnings }: { errors: string[]; warnings: string[] }) {
  if (!errors.length && !warnings.length) return null;
  return (
    <ul className="space-y-1.5 text-[15px]">
      {errors.map((e) => (
        <li key={`e-${e}`} className="flex gap-2">
          <span className="mt-[7px] h-2 w-2 shrink-0 rounded-full bg-fail" aria-hidden />
          <span>
            <span className="sr-only">Error: </span>
            {e}
          </span>
        </li>
      ))}
      {warnings.map((w) => (
        <li key={`w-${w}`} className="flex gap-2 text-ink-soft">
          <span className="mt-[7px] h-2 w-2 shrink-0 rounded-full bg-warn" aria-hidden />
          <span>
            <span className="sr-only">Warning: </span>
            {w}
          </span>
        </li>
      ))}
    </ul>
  );
}

function RawRecord({ host, value }: { host: string; value: string }) {
  return (
    <div className="rounded-lg bg-ink px-4 py-3 font-mono text-[13.5px] leading-relaxed text-[#e6ebf5]">
      <div className="text-[#93a2c2]">{host}</div>
      <div className="break-all">{value}</div>
    </div>
  );
}

export function CheckPanel({ title, status, children }: { title: string; status: { status: Status; label: string }; children: ReactNode }) {
  return (
    <section className="space-y-4 border-t border-rule pt-6 first:border-t-0 first:pt-0">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-lg">{title}</h3>
        <Badge status={status.status}>{status.label}</Badge>
      </div>
      {children}
    </section>
  );
}

function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: Status }) {
  const color = tone === 'fail' ? 'text-fail' : tone === 'warn' ? 'text-warn' : tone === 'pass' ? 'text-pass' : 'text-ink';
  return (
    <div>
      <dt className="text-sm text-ink-soft">{label}</dt>
      <dd className={`font-display text-2xl font-semibold ${color}`}>{value}</dd>
    </div>
  );
}

function SpfTree({ node, depth = 0 }: { node: SpfNode; depth?: number }) {
  return (
    <li>
      <div className="flex flex-wrap items-baseline gap-x-2 py-1" style={{ paddingLeft: depth * 18 }}>
        <span className="font-mono text-sm">{depth === 0 ? node.domain : node.via}</span>
        {node.lookups > 0 && <span className="text-[13px] text-ink-faint">{node.lookups} lookup{node.lookups === 1 ? '' : 's'}</span>}
        {node.error && <span className="text-[13px] text-fail">{node.error}</span>}
      </div>
      {node.children.length > 0 && (
        <ul>
          {node.children.map((c, i) => (
            <SpfTree key={`${c.domain}-${i}`} node={c} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

export function SpfView({ a }: { a: SpfAnalysis }) {
  const lookTone: Status = a.lookupCount > 10 ? 'fail' : a.lookupCount > 8 ? 'warn' : 'pass';
  return (
    <CheckPanel title="SPF" status={statusOf(a.status, { missingIsFail: true })}>
      {a.records.map((r) => (
        <RawRecord key={r} host={a.domain} value={r} />
      ))}
      {a.record && (
        <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Stat label="DNS lookups" value={`${a.lookupCount} / 10`} tone={lookTone} />
          <Stat label="Void lookups" value={`${a.voidCount} / 2`} tone={a.voidCount > 2 ? 'fail' : undefined} />
          <Stat label="Authorised IPv4 ranges" value={a.ip4.length} />
          <Stat label="Ends with" value={a.allQualifier ? `${a.allQualifier}all` : 'nothing'} tone={a.allQualifier === '-' || a.allQualifier === '~' ? 'pass' : 'warn'} />
        </dl>
      )}
      <Messages errors={a.errors} warnings={a.warnings} />
      {a.tree && a.tree.children.length > 0 && (
        <details className="rounded-lg border border-rule bg-sheet px-4 py-2">
          <summary className="cursor-pointer py-1 text-[15px] font-medium">Include tree</summary>
          <ul className="pb-2">
            <SpfTree node={a.tree} />
          </ul>
        </details>
      )}
    </CheckPanel>
  );
}

export function DmarcView({ a }: { a: DmarcAnalysis }) {
  const r = a.parsed?.record;
  return (
    <CheckPanel title="DMARC" status={statusOf(a.status, { missingIsFail: true })}>
      {a.record && <RawRecord host={`_dmarc.${a.foundAt}`} value={a.record} />}
      {r && (
        <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Stat label="Policy" value={a.policy ?? '–'} tone={a.policy === 'reject' ? 'pass' : a.policy === 'quarantine' ? 'pass' : 'warn'} />
          <Stat label="Applied as" value={a.effectivePolicy ?? '–'} tone={a.testing ? 'warn' : undefined} />
          <Stat label="Reports to" value={r.rua.length || 'none'} tone={r.rua.length ? undefined : 'warn'} />
          <Stat label="Alignment" value={`${r.adkim === 's' ? 'strict' : 'relaxed'} / ${r.aspf === 's' ? 'strict' : 'relaxed'}`} />
        </dl>
      )}
      {a.inherited && (
        <p className="text-[15px] text-ink-soft">
          Inherited from <Code>{a.foundAt}</Code> through the DNS tree walk (RFC 9989).
        </p>
      )}
      <Messages errors={a.errors} warnings={a.warnings} />
    </CheckPanel>
  );
}

export function DkimView({ a }: { a: DkimAnalysis }) {
  return (
    <CheckPanel title="DKIM" status={statusOf(a.status, { missingIsFail: true })}>
      {a.selectors.length > 0 ? (
        <table className="w-full text-left text-[15px]">
          <thead className="text-sm text-ink-soft">
            <tr>
              <th className="py-1 font-normal">Selector</th>
              <th className="py-1 font-normal">Key</th>
              <th className="py-1 font-normal">Status</th>
            </tr>
          </thead>
          <tbody>
            {a.selectors.map((s) => (
              <tr key={s.selector} className="border-t border-rule">
                <td className="py-2 font-mono text-sm">{s.selector}</td>
                <td className="py-2">{s.parsed.revoked ? 'revoked' : `${s.parsed.keyType.toUpperCase()} ${s.parsed.keyBits ?? '?'}-bit`}</td>
                <td className="py-2">
                  {s.parsed.valid && !s.parsed.revoked ? (
                    <Badge status={s.parsed.warnings.length ? 'warn' : 'pass'}>{s.parsed.warnings.length ? 'Works, could be stronger' : 'Good'}</Badge>
                  ) : (
                    <Badge status="fail">Broken</Badge>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="text-[15px] text-ink-soft">Checked {a.probed} common selectors.</p>
      )}
      <Messages errors={a.errors} warnings={a.warnings} />
    </CheckPanel>
  );
}

export function MxView({ a }: { a: MxAnalysis }) {
  return (
    <CheckPanel title="MX" status={statusOf(a.status)}>
      {a.hosts.length > 0 && (
        <table className="w-full text-left text-[15px]">
          <thead className="text-sm text-ink-soft">
            <tr>
              <th className="w-20 py-1 pr-4 font-normal">Priority</th>
              <th className="py-1 pr-4 font-normal">Host</th>
              <th className="hidden py-1 font-normal sm:table-cell">IPv4</th>
            </tr>
          </thead>
          <tbody>
            {a.hosts.map((h) => {
              const v4 = h.addresses.filter((x) => !x.includes(':'));
              return (
                <tr key={h.host} className="border-t border-rule align-top">
                  <td className="py-2 pr-4 tabular-nums">{h.priority}</td>
                  <td className="py-2 pr-4 font-mono text-sm [overflow-wrap:anywhere]">{h.host}</td>
                  <td className="hidden py-2 font-mono text-sm sm:table-cell">
                    {v4.slice(0, 3).join(', ') || '–'}
                    {v4.length > 3 && <span className="text-ink-faint"> +{v4.length - 3} more</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {a.provider && <p className="text-[15px]">Mailbox provider: <strong>{a.provider}</strong></p>}
      <Messages errors={a.errors} warnings={a.warnings} />
    </CheckPanel>
  );
}

export function MtaStsView({ a, fetched }: { a: MtaStsAnalysis; fetched: boolean }) {
  return (
    <CheckPanel title="MTA-STS" status={statusOf(a.status)}>
      {a.txt && <RawRecord host={`_mta-sts.${a.domain}`} value={a.txt} />}
      {a.policyText && <RawRecord host={`https://mta-sts.${a.domain}/.well-known/mta-sts.txt`} value={a.policyText.trim()} />}
      {a.txt && !fetched && <p className="text-[15px] text-ink-soft">The policy file was not fetched in this check.</p>}
      <Messages errors={a.errors} warnings={a.warnings} />
    </CheckPanel>
  );
}

export function TlsRptView({ a }: { a: TlsRptAnalysis }) {
  return (
    <CheckPanel title="TLS-RPT" status={statusOf(a.status)}>
      {a.record && <RawRecord host={`_smtp._tls.${a.domain}`} value={a.record} />}
      <Messages errors={a.errors} warnings={a.warnings} />
    </CheckPanel>
  );
}

export function BimiView({ a }: { a: BimiAnalysis }) {
  return (
    <CheckPanel title="BIMI" status={statusOf(a.status)}>
      {a.record && <RawRecord host={`default._bimi.${a.domain}`} value={a.record} />}
      {a.logoUrl && (
        <div className="flex items-center gap-3">
          <img src={a.logoUrl} alt="BIMI logo" className="h-14 w-14 rounded-full border border-rule bg-sheet object-contain" referrerPolicy="no-referrer" />
          <span className="text-[15px] text-ink-soft break-all">{a.logoUrl}</span>
        </div>
      )}
      {a.status === 'missing' && <p className="text-[15px] text-ink-soft">BIMI shows your logo next to your emails in Gmail, Yahoo and Apple Mail once DMARC is enforced.</p>}
      <Messages errors={a.errors} warnings={a.warnings} />
    </CheckPanel>
  );
}

export function BlacklistView({ a }: { a: BlacklistAnalysis }) {
  const unknown = a.results.filter((r) => r.status === 'unknown').length;
  return (
    <CheckPanel title="Blocklists" status={a.listed.length ? { status: 'fail', label: `Listed on ${a.listed.length}` } : { status: 'pass', label: 'Not listed' }}>
      <p className="text-[15px] text-ink-soft">
        Checked the domain{a.checkedIps.length ? ` and ${a.checkedIps.length} mail server IP${a.checkedIps.length === 1 ? '' : 's'}` : ''} against {new Set(a.results.map((r) => r.zone)).size} lists.
        {unknown > 0 && ` ${unknown} lookup${unknown === 1 ? '' : 's'} could not be completed (some lists refuse public resolvers).`}
      </p>
      {a.listed.length > 0 && (
        <ul className="space-y-2">
          {a.listed.map((l) => (
            <li key={`${l.zone}-${l.target}`} className="text-[15px]">
              <strong>{l.target}</strong> on {l.name}.{' '}
              <a className="text-airmail-blue underline" href={l.delistUrl} target="_blank" rel="noreferrer">
                Removal process
              </a>
            </li>
          ))}
        </ul>
      )}
    </CheckPanel>
  );
}

const SEVERITY: Record<Fix['severity'], { status: Status; label: string }> = {
  critical: { status: 'fail', label: 'Fix now' },
  warning: { status: 'warn', label: 'Should fix' },
  info: { status: 'info', label: 'Improve' },
};

export function FixList({ fixes, limit }: { fixes: Fix[]; limit?: number }) {
  const shown = limit ? fixes.slice(0, limit) : fixes;
  if (!fixes.length) return <p className="text-ink-soft">Nothing to fix. This domain is set up well.</p>;
  return (
    <ol className="space-y-5">
      {shown.map((f) => (
        <li key={f.id} className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge status={SEVERITY[f.severity].status}>{SEVERITY[f.severity].label}</Badge>
            <span className="font-medium">{f.title}</span>
          </div>
          <p className="max-w-3xl text-[15px] text-ink-soft">{f.detail}</p>
          {f.record && <RecordBlock type={f.record.type} host={f.record.host} value={f.record.value} />}
        </li>
      ))}
    </ol>
  );
}
