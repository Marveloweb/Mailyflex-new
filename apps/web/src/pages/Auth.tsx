import { useState, type FormEvent } from 'react';
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router';
import { Button, Field, Input, Notice } from '../components/ui.tsx';
import { useAuth } from '../lib/auth.tsx';
import { backendConfigured } from '../lib/config.ts';
import { errorMessage, supabase } from '../lib/supabase.ts';

export function AuthPage({ mode }: { mode: 'login' | 'signup' }) {
  const { session } = useAuth();
  const [params] = useSearchParams();
  const next = params.get('next') && params.get('next')!.startsWith('/') ? params.get('next')! : '/app';
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState<string | null>(null);

  if (!backendConfigured) return <Navigate to="/setup-required" replace />;
  if (session) return <Navigate to={next} replace />;

  const redirectTo = `${window.location.origin}${next}`;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === 'signup') {
        const { data, error: err } = await supabase!.auth.signUp({ email, password, options: { data: { full_name: name }, emailRedirectTo: redirectTo } });
        if (err) throw err;
        if (!data.session) setSent(`We sent a confirmation link to ${email}. Open it to finish signing up.`);
        else navigate(next);
      } else {
        const { error: err } = await supabase!.auth.signInWithPassword({ email, password });
        if (err) throw err;
        navigate(next);
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const magicLink = async () => {
    if (!email) {
      setError('Enter your email address first.');
      return;
    }
    setBusy(true);
    setError(null);
    const { error: err } = await supabase!.auth.signInWithOtp({ email, options: { emailRedirectTo: redirectTo } });
    setBusy(false);
    if (err) setError(err.message);
    else setSent(`We sent a sign-in link to ${email}.`);
  };

  return (
    <div className="mx-auto max-w-md px-5 py-16">
      <h1 className="text-3xl">{mode === 'signup' ? 'Create your account' : 'Sign in'}</h1>
      <p className="mt-2 text-ink-soft">
        {mode === 'signup' ? (
          <>
            Already have one? <Link className="text-airmail-blue underline" to={`/login?next=${encodeURIComponent(next)}`}>Sign in</Link>
          </>
        ) : (
          <>
            New here? <Link className="text-airmail-blue underline" to={`/signup?next=${encodeURIComponent(next)}`}>Create an account</Link>
          </>
        )}
      </p>
      {sent ? (
        <div className="mt-8">
          <Notice status="pass" title="Check your inbox">
            {sent}
          </Notice>
        </div>
      ) : (
        <form onSubmit={submit} className="mt-8 space-y-5">
          {mode === 'signup' && (
            <Field label="Your name" htmlFor="name">
              <Input id="name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
            </Field>
          )}
          <Field label="Work email" htmlFor="email">
            <Input id="email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
          </Field>
          <Field label="Password" htmlFor="password" hint={mode === 'signup' ? 'At least 8 characters.' : undefined}>
            <Input
              id="password"
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
            />
          </Field>
          {error && <Notice status="fail">{error}</Notice>}
          <Button type="submit" busy={busy} className="w-full">
            {mode === 'signup' ? 'Create account' : 'Sign in'}
          </Button>
          {mode === 'login' && (
            <button type="button" onClick={magicLink} className="w-full text-center text-[15px] text-ink-soft underline hover:text-ink">
              Email me a sign-in link instead
            </button>
          )}
        </form>
      )}
    </div>
  );
}

export function SetupRequired() {
  return (
    <div className="mx-auto max-w-2xl px-5 py-16">
      <h1 className="text-3xl">The dashboard isn&apos;t connected yet</h1>
      <p className="mt-3 text-ink-soft">
        This build has no Supabase project configured, so accounts and monitoring are switched off. The <Link className="text-airmail-blue underline" to="/tools">free tools</Link> still
        work.
      </p>
      <p className="mt-3 text-ink-soft">
        To enable the dashboard, set <code className="font-mono">VITE_SUPABASE_URL</code> and <code className="font-mono">VITE_SUPABASE_ANON_KEY</code> and rebuild. See the README.
      </p>
    </div>
  );
}
