import { useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';

const VARIANTS: Record<Variant, string> = {
  primary: 'bg-ink text-white hover:bg-[#1f3157] disabled:bg-ink-faint',
  secondary: 'bg-sheet text-ink border border-rule hover:border-ink-faint disabled:text-ink-faint',
  ghost: 'text-ink-soft hover:text-ink hover:bg-rule/50',
  danger: 'bg-sheet text-fail border border-fail/40 hover:bg-fail-bg',
};

export function Button({ variant = 'primary', busy, className = '', children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  return (
    <button
      {...rest}
      disabled={rest.disabled || busy}
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-[15px] font-medium transition-colors disabled:cursor-not-allowed ${VARIANTS[variant]} ${className}`}
    >
      {busy && <Spinner />}
      {children}
    </button>
  );
}

export function Spinner({ className = '' }: { className?: string }) {
  return <span aria-hidden className={`inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-r-transparent ${className}`} />;
}

export function Input({ className = '', ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...rest}
      className={`w-full rounded-lg border border-rule bg-sheet px-3 py-2 text-[15px] text-ink placeholder:text-ink-faint focus:border-airmail-blue focus:outline-none ${className}`}
    />
  );
}

export function Select({ className = '', children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select {...rest} className={`rounded-lg border border-rule bg-sheet px-3 py-2 text-[15px] text-ink focus:border-airmail-blue focus:outline-none ${className}`}>
      {children}
    </select>
  );
}

export function Field({ label, hint, children, htmlFor }: { label: string; hint?: ReactNode; children: ReactNode; htmlFor?: string }) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-sm font-medium text-ink">
        {label}
      </label>
      {children}
      {hint && <p className="text-sm text-ink-soft">{hint}</p>}
    </div>
  );
}

export type Status = 'pass' | 'warn' | 'fail' | 'info' | 'neutral';

const STATUS_STYLE: Record<Status, string> = {
  pass: 'bg-pass-bg text-pass',
  warn: 'bg-warn-bg text-warn',
  fail: 'bg-fail-bg text-fail',
  info: 'bg-[#e8eefb] text-airmail-blue',
  neutral: 'bg-rule/60 text-ink-soft',
};

export function Badge({ status, children }: { status: Status; children: ReactNode }) {
  return <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[13px] font-medium ${STATUS_STYLE[status]}`}>{children}</span>;
}

export function Notice({ status = 'info', title, children }: { status?: Status; title?: string; children?: ReactNode }) {
  const bar: Record<Status, string> = { pass: 'border-pass', warn: 'border-warn', fail: 'border-fail', info: 'border-airmail-blue', neutral: 'border-rule' };
  return (
    <div role={status === 'fail' ? 'alert' : undefined} className={`rounded-lg border-l-4 bg-sheet px-4 py-3 ${bar[status]}`}>
      {title && <p className="font-medium">{title}</p>}
      {children && <div className="text-[15px] text-ink-soft">{children}</div>}
    </div>
  );
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          /* clipboard blocked */
        }
      }}
      className="shrink-0 rounded-md border border-rule bg-sheet px-2.5 py-1 text-[13px] font-medium text-ink-soft hover:text-ink"
    >
      {copied ? 'Copied' : label}
    </button>
  );
}

/** A DNS record the user can copy into their provider. */
export function RecordBlock({ type, host, value, note }: { type: string; host: string; value: string; note?: string }) {
  return (
    <div className="rounded-lg border border-rule bg-paper/60">
      <dl className="grid grid-cols-[5.5rem_1fr_auto] items-start gap-x-3 gap-y-2 p-3 text-sm">
        <dt className="text-ink-soft">Type</dt>
        <dd className="font-mono">{type}</dd>
        <span />
        <dt className="text-ink-soft">Host</dt>
        <dd className="font-mono break-all">{host}</dd>
        <CopyButton value={host} />
        <dt className="text-ink-soft">Value</dt>
        <dd className="font-mono break-all">{value}</dd>
        <CopyButton value={value} />
      </dl>
      {note && <p className="border-t border-rule px-3 py-2 text-sm text-ink-soft">{note}</p>}
    </div>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return <code className="rounded bg-rule/50 px-1.5 py-0.5 font-mono text-[0.9em] break-all">{children}</code>;
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="rounded-xl border border-dashed border-rule bg-sheet px-6 py-10 text-center">
      <p className="font-display text-lg font-semibold">{title}</p>
      {children && <div className="mx-auto mt-2 max-w-md text-ink-soft">{children}</div>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function Section({ title, description, children, actions }: { title: string; description?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-xl">{title}</h2>
          {description && <p className="mt-1 max-w-2xl text-ink-soft">{description}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}
