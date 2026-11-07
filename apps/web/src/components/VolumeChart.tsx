import { useEffect, useRef, useState } from 'react';
import { formatDay, formatNumber, formatPercent } from '../lib/format.ts';

export interface DayRow {
  day: string;
  total: number;
  passing: number;
}

const PASS = '#3d6fc4';
const FAIL = '#c3343f';

function niceMax(v: number): number {
  if (v <= 5) return 5;
  const mag = 10 ** Math.floor(Math.log10(v));
  const step = [1, 2, 2.5, 5, 10].find((s) => s * mag >= v / 4)! * mag;
  return Math.ceil(v / step) * step;
}

function tick(v: number): string {
  return v >= 10000 ? `${Math.round(v / 1000)}K` : formatNumber(v);
}

/** Daily DMARC volume as stacked columns: aligned (pass) below, failing above. */
export function VolumeChart({ rows }: { rows: DayRow[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);
  // Draw at the real pixel width so axis text stays legible on phones.
  const wrap = useRef<HTMLDivElement>(null);
  const [W, setW] = useState(720);
  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setW(Math.max(280, Math.round(e!.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, [table]);
  const H = W < 480 ? 200 : 240;
  const pad = { l: 48, r: 8, t: 12, b: 28 };
  const max = niceMax(Math.max(1, ...rows.map((r) => r.total)));
  const iw = W - pad.l - pad.r;
  const ih = H - pad.t - pad.b;
  const band = iw / Math.max(rows.length, 1);
  const bw = Math.min(24, band * 0.6);
  const y = (v: number) => pad.t + ih - (v / max) * ih;
  const ticks = [0, max / 4, max / 2, (3 * max) / 4, max];
  const labelEvery = Math.max(1, Math.ceil(rows.length / Math.max(2, Math.floor(iw / 70))));

  const column = (x: number, top: number, bottom: number, color: string, roundTop: boolean) => {
    const h = Math.max(0, bottom - top);
    if (h <= 0) return null;
    const r = roundTop ? Math.min(4, h, bw / 2) : 0;
    return (
      <path
        d={`M${x},${bottom} V${top + r} Q${x},${top} ${x + r},${top} H${x + bw - r} Q${x + bw},${top} ${x + bw},${top + r} V${bottom} Z`}
        fill={color}
      />
    );
  };

  const h = hover !== null ? rows[hover] : null;
  return (
    <figure className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <ul className="flex gap-4 text-sm text-ink-soft" aria-label="Legend">
          <li className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-sm" style={{ background: PASS }} aria-hidden />
            Passed DMARC
          </li>
          <li className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-sm" style={{ background: FAIL }} aria-hidden />
            Failed DMARC
          </li>
        </ul>
        <button className="text-sm text-ink-soft underline hover:text-ink" onClick={() => setTable((t) => !t)} aria-pressed={table}>
          {table ? 'Show chart' : 'Show as table'}
        </button>
      </div>
      {table ? (
        <table className="w-full text-left text-[15px]">
          <thead className="text-sm text-ink-soft">
            <tr>
              <th className="py-1 font-normal">Day</th>
              <th className="py-1 text-right font-normal">Messages</th>
              <th className="py-1 text-right font-normal">Passed</th>
              <th className="py-1 text-right font-normal">Failed</th>
              <th className="py-1 text-right font-normal">Pass rate</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.day} className="border-t border-rule">
                <td className="py-1.5">{formatDay(r.day)}</td>
                <td className="py-1.5 text-right tabular-nums">{formatNumber(r.total)}</td>
                <td className="py-1.5 text-right tabular-nums">{formatNumber(r.passing)}</td>
                <td className="py-1.5 text-right tabular-nums">{formatNumber(r.total - r.passing)}</td>
                <td className="py-1.5 text-right tabular-nums">{formatPercent(r.total ? r.passing / r.total : null)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="relative" ref={wrap}>
          <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} className="block max-w-full" role="img" aria-label={`Daily messages over ${rows.length} days`} onMouseLeave={() => setHover(null)}>
            {ticks.map((t) => (
              <g key={t}>
                <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} stroke="#e7ebf2" strokeWidth={1} />
                <text x={pad.l - 8} y={y(t) + 4} textAnchor="end" fontSize="11" fill="#6b7790">
                  {tick(t)}
                </text>
              </g>
            ))}
            {rows.map((r, i) => {
              const x = pad.l + i * band + (band - bw) / 2;
              const failing = r.total - r.passing;
              const passTop = y(r.passing);
              const gap = r.passing > 0 && failing > 0 ? 2 : 0;
              return (
                <g key={r.day} opacity={hover === null || hover === i ? 1 : 0.55}>
                  {column(x, passTop, y(0), PASS, failing === 0)}
                  {column(x, y(r.total), passTop - gap, FAIL, true)}
                  {i % labelEvery === 0 && (
                    <text x={x + bw / 2} y={H - 8} textAnchor="middle" fontSize="11" fill="#6b7790">
                      {formatDay(r.day)}
                    </text>
                  )}
                  <rect x={pad.l + i * band} y={pad.t} width={band} height={ih} fill="transparent" onMouseEnter={() => setHover(i)} onFocus={() => setHover(i)} tabIndex={-1} />
                </g>
              );
            })}
          </svg>
          {h && hover !== null && (
            <div
              className="pointer-events-none absolute top-2 rounded-lg border border-rule bg-sheet px-3 py-2 text-sm shadow-sm"
              style={{ left: `${Math.min(70, ((pad.l + hover * band) / W) * 100)}%` }}
            >
              <p className="font-medium">{formatDay(h.day)}</p>
              <p className="tabular-nums text-ink-soft">
                {formatNumber(h.passing)} passed, {formatNumber(h.total - h.passing)} failed ({formatPercent(h.total ? h.passing / h.total : null)})
              </p>
            </div>
          )}
        </div>
      )}
    </figure>
  );
}
