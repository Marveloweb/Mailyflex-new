import { useEffect, useState } from 'react';
import { reportAddress, senderByKey } from '@mailyflex/core';
import { VolumeChart, type DayRow } from '../../components/VolumeChart.tsx';
import { Badge, Code, EmptyState, Section, Select, Spinner, type Status } from '../../components/ui.tsx';
import { hostedEnv } from '../../lib/config.ts';
import { formatDay, formatNumber, formatPercent } from '../../lib/format.ts';
import { db } from '../../lib/supabase.ts';
import type { SenderStat } from '../../lib/types.ts';
import { useDomain } from './domainContext.tsx';

interface ReportRow {
  id: number;
  org_name: string;
  date_begin: string;
  date_end: string;
  message_count: number;
  record_count: number;
}

function NoReports() {
  const { domain } = useDomain();
  return (
    <EmptyState title="No DMARC reports yet">
      Mailbox providers send reports once a day to the address in your DMARC record. Make sure it includes <Code>{`mailto:${reportAddress(domain.report_token, hostedEnv)}`}</Code>. The
      first reports usually arrive within 24–48 hours.
    </EmptyState>
  );
}

function Tile({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="border-l-2 border-rule pl-4">
      <p className="text-sm text-ink-soft">{label}</p>
      <p className="font-display text-3xl font-semibold tabular-nums">{value}</p>
      {detail && <p className="text-sm text-ink-soft">{detail}</p>}
    </div>
  );
}

export function DomainReports() {
  const { domain } = useDomain();
  const [days, setDays] = useState(30);
  const [rows, setRows] = useState<(DayRow & { dkim_aligned: number; spf_aligned: number })[] | null>(null);
  const [reports, setReports] = useState<ReportRow[]>([]);

  useEffect(() => {
    setRows(null);
    Promise.all([
      db().rpc('domain_daily_stats', { p_domain: domain.id, p_days: days }),
      db().from('dmarc_reports').select('id, org_name, date_begin, date_end, message_count, record_count').eq('domain_id', domain.id).order('date_begin', { ascending: false }).limit(10),
    ]).then(([stats, reps]) => {
      setRows(
        ((stats.data ?? []) as { day: string; total: number; passing: number; dkim_aligned: number; spf_aligned: number }[]).map((r) => ({
          day: r.day,
          total: Number(r.total),
          passing: Number(r.passing),
          dkim_aligned: Number(r.dkim_aligned),
          spf_aligned: Number(r.spf_aligned),
        })),
      );
      setReports((reps.data ?? []) as ReportRow[]);
    });
  }, [domain.id, days]);

  if (rows === null) return <Spinner />;
  if (rows.length === 0 && reports.length === 0) return <NoReports />;
  const total = rows.reduce((a, r) => a + r.total, 0);
  const passing = rows.reduce((a, r) => a + r.passing, 0);
  const dkim = rows.reduce((a, r) => a + r.dkim_aligned, 0);
  const spf = rows.reduce((a, r) => a + r.spf_aligned, 0);
  return (
    <div className="space-y-10">
      <div className="flex items-center justify-end gap-2">
        <label htmlFor="period" className="text-sm text-ink-soft">
          Period
        </label>
        <Select id="period" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
        </Select>
      </div>
      <dl className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <Tile label="Messages" value={formatNumber(total)} />
        <Tile label="Passed DMARC" value={formatPercent(total ? passing / total : null)} detail={`${formatNumber(total - passing)} failed`} />
        <Tile label="DKIM aligned" value={formatPercent(total ? dkim / total : null)} />
        <Tile label="SPF aligned" value={formatPercent(total ? spf / total : null)} />
      </dl>
      <Section title="Messages per day">
        <div className="rounded-xl border border-rule bg-sheet p-4">
          <VolumeChart rows={rows} />
        </div>
      </Section>
      <Section title="Latest reports received">
        <table className="w-full text-left text-[15px]">
          <thead className="text-sm text-ink-soft">
            <tr>
              <th className="py-1 font-normal">From</th>
              <th className="py-1 font-normal">Covers</th>
              <th className="py-1 text-right font-normal">Messages</th>
            </tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id} className="border-t border-rule">
                <td className="py-2">{r.org_name}</td>
                <td className="py-2 text-ink-soft">{formatDay(r.date_begin.slice(0, 10))}</td>
                <td className="py-2 text-right tabular-nums">{formatNumber(r.message_count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </div>
  );
}

function senderStatus(s: SenderStat): { status: Status; label: string } {
  const rate = s.total ? s.passing / s.total : 0;
  if (rate >= 0.98) return { status: 'pass', label: 'Authenticated' };
  if (!s.sender_key && rate < 0.05) return { status: 'fail', label: 'Unrecognised, failing' };
  if (rate === 0) return { status: 'fail', label: 'Failing' };
  return { status: 'warn', label: 'Partly failing' };
}

export function DomainSenders() {
  const { domain } = useDomain();
  const [rows, setRows] = useState<SenderStat[] | null>(null);
  useEffect(() => {
    db()
      .rpc('domain_sender_stats', { p_domain: domain.id, p_days: 30 })
      .then(({ data }) => setRows(((data ?? []) as SenderStat[]).map((r) => ({ ...r, total: Number(r.total), passing: Number(r.passing), dkim_aligned: Number(r.dkim_aligned), spf_aligned: Number(r.spf_aligned) }))));
  }, [domain.id]);
  if (rows === null) return <Spinner />;
  if (rows.length === 0) return <NoReports />;
  const grand = rows.reduce((a, r) => a + r.total, 0);
  return (
    <Section
      title="Who sends email as this domain"
      description="From the last 30 days of DMARC reports. Known services are named; anything unrecognised and failing may be someone spoofing you, or a service you forgot to set up."
    >
      <div className="overflow-x-auto rounded-xl border border-rule bg-sheet">
        <table className="w-full min-w-[640px] text-left text-[15px]">
          <thead className="border-b border-rule text-sm text-ink-soft">
            <tr>
              <th className="px-4 py-3 font-normal">Sender</th>
              <th className="px-4 py-3 text-right font-normal">Messages</th>
              <th className="px-4 py-3 text-right font-normal">DKIM</th>
              <th className="px-4 py-3 text-right font-normal">SPF</th>
              <th className="px-4 py-3 font-normal">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const known = r.sender_key ? senderByKey(r.sender_key) : undefined;
              const st = senderStatus(r);
              return (
                <tr key={r.sender} className="border-t border-rule first:border-t-0 align-top">
                  <td className="px-4 py-3">
                    <p className="font-medium">{known?.name ?? r.ptr ?? r.sample_ip}</p>
                    <p className="text-sm text-ink-soft">
                      {known ? `${r.ip_count} IP${r.ip_count === 1 ? '' : 's'}` : [r.sample_ip, r.as_name].filter(Boolean).join(', ')}
                      {known?.docsUrl && st.status !== 'pass' && (
                        <>
                          {', '}
                          <a href={known.docsUrl} target="_blank" rel="noreferrer" className="text-airmail-blue underline">
                            setup guide
                          </a>
                        </>
                      )}
                    </p>
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums">
                    {formatNumber(r.total)}
                    <p className="text-sm text-ink-soft">{formatPercent(grand ? r.total / grand : null)}</p>
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums">{formatPercent(r.total ? r.dkim_aligned / r.total : null, 0)}</td>
                  <td className="px-4 py-3 text-right tabular-nums">{formatPercent(r.total ? r.spf_aligned / r.total : null, 0)}</td>
                  <td className="px-4 py-3">
                    <Badge status={st.status}>{st.label}</Badge>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Section>
  );
}
