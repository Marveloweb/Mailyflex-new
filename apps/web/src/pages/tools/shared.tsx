import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import { isValidDomain, normalizeDomain } from '@mailyflex/core';
import { Button, Input, Notice } from '../../components/ui.tsx';
import { errorMessage } from '../../lib/supabase.ts';

/** Runs a check for the ?domain= in the URL; the form updates the URL so results are shareable. */
export function useDomainCheck<T>(run: (domain: string, extra: string) => Promise<T>, extraParam?: string) {
  const [params, setParams] = useSearchParams();
  const domain = params.get('domain') ?? '';
  const extra = extraParam ? (params.get(extraParam) ?? '') : '';
  const [result, setResult] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const runRef = useRef(run);
  runRef.current = run;

  useEffect(() => {
    if (!domain) {
      setResult(null);
      return;
    }
    if (!isValidDomain(domain)) {
      setError(`"${domain}" is not a valid domain name.`);
      setResult(null);
      return;
    }
    let cancelled = false;
    setBusy(true);
    setError(null);
    runRef
      .current(normalizeDomain(domain), extra)
      .then((r) => !cancelled && setResult(r))
      .catch((e) => !cancelled && setError(errorMessage(e)))
      .finally(() => !cancelled && setBusy(false));
    return () => {
      cancelled = true;
    };
  }, [domain, extra]);

  const submit = useCallback(
    (d: string, x?: string) => {
      const next = new URLSearchParams();
      next.set('domain', normalizeDomain(d));
      if (extraParam && x) next.set(extraParam, x.trim());
      setParams(next);
    },
    [extraParam, setParams],
  );
  return { domain, extra, result, error, busy, submit };
}

export function DomainForm({
  initial,
  busy,
  onSubmit,
  cta = 'Check domain',
  extra,
  large,
}: {
  initial: string;
  busy: boolean;
  onSubmit: (domain: string, extra?: string) => void;
  cta?: string;
  extra?: { label: string; placeholder: string; initial: string };
  large?: boolean;
}) {
  const [value, setValue] = useState(initial);
  const [extraValue, setExtraValue] = useState(extra?.initial ?? '');
  const [invalid, setInvalid] = useState(false);
  useEffect(() => setValue(initial), [initial]);
  const handle = (e: FormEvent) => {
    e.preventDefault();
    if (!isValidDomain(value)) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    onSubmit(value, extraValue);
  };
  return (
    <form onSubmit={handle} className="space-y-2" noValidate>
      <div className="flex flex-col gap-2 sm:flex-row">
        <label htmlFor="domain-input" className="sr-only">
          Domain
        </label>
        <Input
          id="domain-input"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="yourcompany.com"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          inputMode="url"
          aria-invalid={invalid}
          aria-describedby={invalid ? 'domain-error' : undefined}
          className={large ? 'py-3 text-lg' : ''}
        />
        {extra && (
          <>
            <label htmlFor="extra-input" className="sr-only">
              {extra.label}
            </label>
            <Input id="extra-input" value={extraValue} onChange={(e) => setExtraValue(e.target.value)} placeholder={extra.placeholder} className={`sm:max-w-56 ${large ? 'py-3 text-lg' : ''}`} />
          </>
        )}
        <Button type="submit" busy={busy} className={`whitespace-nowrap ${large ? 'px-6 py-3 text-base' : ''}`}>
          {cta}
        </Button>
      </div>
      {invalid && (
        <p id="domain-error" className="text-sm text-fail">
          Enter a domain like yourcompany.com.
        </p>
      )}
    </form>
  );
}

export function ToolPage({ title, intro, children, wide }: { title: string; intro: ReactNode; children: ReactNode; wide?: boolean }) {
  return (
    <div className={`mx-auto px-5 py-12 ${wide ? 'max-w-5xl' : 'max-w-3xl'}`}>
      <h1 className="text-4xl sm:text-[2.6rem]">{title}</h1>
      <div className="mt-3 max-w-2xl text-lg text-ink-soft">{intro}</div>
      <div className="mt-8 space-y-8">{children}</div>
    </div>
  );
}

export function CheckError({ error }: { error: string | null }) {
  return error ? <Notice status="fail" title="The check could not finish">{error}</Notice> : null;
}
