import { Link } from 'react-router';

const TOOLS = [
  { to: '/tools/domain', name: 'Domain health check', text: 'Every check at once, with a score and a fix list.' },
  { to: '/tools/dmarc', name: 'DMARC checker', text: 'Policy, reporting and RFC 9989 tags.' },
  { to: '/tools/spf', name: 'SPF checker', text: 'Nested lookup counter and include tree.' },
  { to: '/tools/dkim', name: 'DKIM checker', text: 'Finds keys on common selectors and checks their size.' },
  { to: '/tools/mx', name: 'MX lookup', text: 'Inbound mail servers and provider.' },
  { to: '/tools/mta-sts', name: 'MTA-STS checker', text: 'Record, policy file and MX coverage.' },
  { to: '/tools/tls-rpt', name: 'TLS-RPT checker', text: 'Where TLS failure reports go.' },
  { to: '/tools/bimi', name: 'BIMI checker', text: 'Logo record and certificate.' },
  { to: '/tools/blacklist', name: 'Blocklist checker', text: 'Domain and mail server IPs on DNS blocklists.' },
  { to: '/tools/spf-generator', name: 'SPF generator', text: 'Pick your services, see the lookup count live.' },
  { to: '/tools/dmarc-generator', name: 'DMARC generator', text: 'A correct record in a minute.' },
];

export function ToolsHub() {
  return (
    <div className="mx-auto max-w-5xl px-5 py-12">
      <h1 className="text-4xl">Free email authentication tools</h1>
      <p className="mt-3 max-w-2xl text-lg text-ink-soft">No sign-up. Lookups run from your browser over DNS-over-HTTPS, so results are live.</p>
      <ul className="mt-10 divide-y divide-rule border-y border-rule">
        {TOOLS.map((t) => (
          <li key={t.to}>
            <Link to={t.to} className="group flex flex-col gap-1 py-4 sm:flex-row sm:items-baseline sm:gap-6">
              <span className="font-display text-lg font-semibold group-hover:text-airmail-blue sm:w-64">{t.name}</span>
              <span className="text-ink-soft">{t.text}</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
