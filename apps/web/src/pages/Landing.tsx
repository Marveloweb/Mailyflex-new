import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import type { ScanResult } from '@mailyflex/core';
import { ScoreStamp } from '../components/ScoreStamp.tsx';
import { FixList } from '../components/checks.tsx';
import { Notice } from '../components/ui.tsx';
import { DomainForm } from './tools/shared.tsx';
import { runFullScan } from './tools/checkers.tsx';
import { errorMessage } from '../lib/supabase.ts';

const STEPS = [
  {
    title: 'Check',
    text: 'We read your SPF, DKIM, DMARC, MTA-STS and BIMI records, count SPF lookups, and test your servers against blocklists. Every problem comes with the exact record to paste.',
  },
  {
    title: 'See who sends as you',
    text: 'Point your DMARC reports at Maily Flex. We read the daily reports from Gmail, Outlook and Yahoo and name each service: Google Workspace, Mailchimp, SendGrid, or a stranger.',
  },
  {
    title: 'Lock it down',
    text: 'Add a few CNAME records once. From then on we host your DMARC, SPF and MTA-STS, flatten SPF under the 10-lookup limit, and step you to p=reject only when the data says it is safe.',
  },
];

export function Landing() {
  const navigate = useNavigate();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const check = async (domain: string) => {
    setBusy(true);
    setError(null);
    try {
      setResult(await runFullScan(domain));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <section className="mx-auto max-w-6xl px-5 pb-16 pt-14 sm:pt-20">
        <div className="max-w-3xl">
          <h1 className="text-[2.75rem] leading-[1.05] sm:text-[4.25rem]">Get your email out of spam.</h1>
          <p className="mt-5 max-w-2xl text-lg text-ink-soft sm:text-xl">
            Gmail, Yahoo and Outlook now reject mail that isn&apos;t properly authenticated. Maily Flex checks your domain, tells you exactly what to change, and keeps it right as your
            senders change.
          </p>
        </div>
        <div className="airmail mt-10 max-w-4xl">
          <div className="airmail-inner p-5 sm:p-8">
            <h2 className="text-xl">Check a domain</h2>
            <p className="mb-4 mt-1 text-ink-soft">Free, no sign-up. Takes a few seconds.</p>
            <DomainForm initial="" busy={busy} onSubmit={check} large />
            {error && (
              <div className="mt-4">
                <Notice status="fail" title="The check could not finish">
                  {error}
                </Notice>
              </div>
            )}
            {result && (
              <div className="mt-8 grid gap-8 border-t border-rule pt-8 md:grid-cols-[auto_1fr]" aria-live="polite">
                <ScoreStamp score={result.score} grade={result.grade} animate />
                <div className="space-y-5">
                  <div>
                    <p className="font-display text-2xl font-semibold">{result.domain}</p>
                    <p className="text-ink-soft">
                      {result.fixes.length === 0
                        ? 'Nothing to fix.'
                        : `${result.fixes.length} thing${result.fixes.length === 1 ? '' : 's'} to improve. The most important:`}
                    </p>
                  </div>
                  <FixList fixes={result.fixes} limit={3} />
                  <div className="flex flex-wrap gap-3">
                    <Link to={`/tools/domain?domain=${encodeURIComponent(result.domain)}`} className="rounded-lg border border-rule bg-sheet px-4 py-2 font-medium hover:border-ink-faint">
                      See the full report
                    </Link>
                    <button onClick={() => navigate('/signup')} className="rounded-lg bg-ink px-4 py-2 font-medium text-white hover:bg-[#1f3157]">
                      Monitor and fix it for me
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="border-t border-rule bg-sheet">
        <div className="mx-auto grid max-w-6xl gap-12 px-5 py-16 md:grid-cols-[1fr_1.4fr]">
          <div>
            <h2 className="text-3xl">From spam folder to p=reject, in three steps</h2>
            <p className="mt-3 text-ink-soft">Most domains fail on the same few things. We find them, then take over the parts that are tedious to keep right by hand.</p>
          </div>
          <ol className="space-y-8">
            {STEPS.map((s, i) => (
              <li key={s.title} className="grid grid-cols-[2.5rem_1fr] gap-4">
                <span className="font-display text-3xl font-bold text-airmail-red">{i + 1}</span>
                <div>
                  <h3 className="text-xl">{s.title}</h3>
                  <p className="mt-1 text-ink-soft">{s.text}</p>
                </div>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-5 py-16">
        <div className="grid gap-10 md:grid-cols-2">
          <div>
            <h2 className="text-3xl">Too many SPF lookups is the quiet killer</h2>
            <p className="mt-3 text-ink-soft">
              Every service you add to SPF costs DNS lookups, and receivers give up after 10. Past that, SPF fails for all of your mail, not just the new service. Maily Flex counts nested
              includes for you and can host a flattened record that stays under the limit as providers change their IPs.
            </p>
            <Link to="/tools/spf" className="mt-4 inline-block font-medium text-airmail-blue underline">
              Count your SPF lookups
            </Link>
          </div>
          <div className="rounded-xl bg-ink p-6 font-mono text-[13.5px] leading-relaxed text-[#e6ebf5]">
            <p className="text-[#93a2c2]">yourcompany.com TXT</p>
            <p className="break-all">
              v=spf1 include:_spf.google.com include:spf.protection.outlook.com include:sendgrid.net include:servers.mcsv.net include:mail.zendesk.com include:_spf.salesforce.com
              include:mailgun.org ~all
            </p>
            <p className="mt-4 text-[#f3a7ad]">13 of 10 lookups: SPF fails for every message</p>
            <p className="mt-4 text-[#93a2c2]">with Maily Flex hosted SPF</p>
            <p className="break-all">v=spf1 include:7f3a…._s.dns.mailyflex.com ~all</p>
            <p className="mt-4 text-[#9fd9b8]">5 of 10 lookups, re-resolved every 6 hours</p>
          </div>
        </div>
      </section>
    </>
  );
}
