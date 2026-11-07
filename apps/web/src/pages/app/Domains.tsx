import { useEffect, useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router';
import { isValidDomain, normalizeDomain } from '@mailyflex/core';
import { Badge, Button, EmptyState, Field, Input, Notice, Spinner } from '../../components/ui.tsx';
import { atLeast, useOrg } from '../../lib/org.tsx';
import { db, errorMessage } from '../../lib/supabase.ts';
import { timeAgo } from '../../lib/format.ts';
import type { DomainRow } from '../../lib/types.ts';

function scoreTone(score: number | null) {
  if (score === null) return 'text-ink-faint';
  return score >= 75 ? 'text-pass' : score >= 50 ? 'text-warn' : 'text-fail';
}

export function Domains() {
  const { current } = useOrg();
  const [domains, setDomains] = useState<DomainRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!current) return;
    setDomains(null);
    db()
      .from('domains')
      .select('*')
      .eq('org_id', current.id)
      .order('name')
      .then(({ data, error: err }) => {
        if (err) setError(err.message);
        setDomains((data ?? []) as DomainRow[]);
      });
  }, [current]);

  const canAdd = atLeast(current?.role, 'admin');
  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl">Domains</h1>
          <p className="mt-1 text-ink-soft">{current?.name}</p>
        </div>
        {canAdd && (
          <Link to="/app/domains/new" className="rounded-lg bg-ink px-4 py-2 font-medium text-white hover:bg-[#1f3157]">
            Add domain
          </Link>
        )}
      </div>
      {error && <Notice status="fail">{error}</Notice>}
      {domains === null ? (
        <Spinner />
      ) : domains.length === 0 ? (
        <EmptyState
          title="Add your first domain"
          action={
            canAdd && (
              <Link to="/app/domains/new" className="rounded-lg bg-ink px-4 py-2 font-medium text-white">
                Add domain
              </Link>
            )
          }
        >
          We&apos;ll check it straight away, then watch it every six hours.
        </EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-rule bg-sheet">
          <table className="w-full text-left">
            <thead className="border-b border-rule text-sm text-ink-soft">
              <tr>
                <th className="px-4 py-3 font-normal">Domain</th>
                <th className="px-4 py-3 font-normal">Health</th>
                <th className="px-4 py-3 font-normal">Hosted by Maily Flex</th>
                <th className="px-4 py-3 font-normal">Last checked</th>
              </tr>
            </thead>
            <tbody>
              {domains.map((d) => (
                <tr key={d.id} className="border-t border-rule first:border-t-0 hover:bg-paper/60">
                  <td className="px-4 py-3">
                    <Link to={`/app/domains/${d.id}`} className="font-medium hover:text-airmail-blue">
                      {d.name}
                    </Link>
                    {!d.verified_at && (
                      <span className="ml-2">
                        <Badge status="warn">Not verified</Badge>
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`font-display text-xl font-semibold ${scoreTone(d.health_score)}`}>{d.health_score ?? '–'}</span>
                    {d.grade && <span className="ml-2 text-sm text-ink-soft">Grade {d.grade}</span>}
                  </td>
                  <td className="px-4 py-3 text-[15px] text-ink-soft">
                    {[d.hosted_dmarc && 'DMARC', d.hosted_spf && 'SPF', d.hosted_mta_sts && 'MTA-STS'].filter(Boolean).join(', ') || 'Nothing yet'}
                  </td>
                  <td className="px-4 py-3 text-[15px] text-ink-soft">{timeAgo(d.last_scan_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function AddDomain() {
  const { current } = useOrg();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const domain = normalizeDomain(name);
    if (!isValidDomain(domain)) {
      setError('Enter a domain like yourcompany.com.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const { data, error: err } = await db().from('domains').insert({ org_id: current!.id, name: domain }).select('id').single();
      if (err) throw err.code === '23505' ? new Error(`${domain} is already in this organization.`) : err;
      navigate(`/app/domains/${data.id}`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  if (!atLeast(current?.role, 'admin')) return <Notice status="warn">Only admins can add domains.</Notice>;
  return (
    <div className="max-w-lg">
      <h1 className="text-3xl">Add a domain</h1>
      <p className="mt-2 text-ink-soft">Add the domain you send email from. You&apos;ll prove you own it with one DNS record.</p>
      <form onSubmit={submit} className="mt-8 space-y-5">
        <Field label="Domain" htmlFor="new-domain">
          <Input id="new-domain" value={name} onChange={(e) => setName(e.target.value)} placeholder="yourcompany.com" autoFocus autoCapitalize="none" spellCheck={false} />
        </Field>
        {error && <Notice status="fail">{error}</Notice>}
        <Button type="submit" busy={busy}>
          Add domain
        </Button>
      </form>
    </div>
  );
}
