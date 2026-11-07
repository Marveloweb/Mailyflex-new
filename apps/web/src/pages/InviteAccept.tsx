import { useEffect, useRef, useState } from 'react';
import { Link, Navigate, useNavigate, useParams } from 'react-router';
import { Notice, Spinner } from '../components/ui.tsx';
import { useAuth } from '../lib/auth.tsx';
import { useOrg } from '../lib/org.tsx';
import { db, errorMessage } from '../lib/supabase.ts';

export function InviteAccept() {
  const { token } = useParams();
  const { session, loading } = useAuth();
  const { reload, select } = useOrg();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    // An invite token is single-use: never send it twice (StrictMode and context updates re-run effects).
    if (!session || !token || started.current) return;
    started.current = true;
    db()
      .rpc('accept_invite', { p_token: token })
      .then(async ({ data, error: err }) => {
        if (err) {
          setError(errorMessage(err));
          return;
        }
        select(data as string);
        await reload();
        navigate('/app', { replace: true });
      });
  }, [session, token, navigate, reload, select]);

  if (loading) return <Spinner />;
  if (!session) return <Navigate to={`/signup?next=${encodeURIComponent(`/invite/${token}`)}`} replace />;
  return (
    <div className="mx-auto max-w-md px-5 py-16">
      <h1 className="text-3xl">Joining your team</h1>
      <div className="mt-6">
        {error ? (
          <Notice status="fail" title="We couldn't add you">
            {error} You are signed in as {session.user.email}. <Link className="underline" to="/app">Go to your dashboard</Link>.
          </Notice>
        ) : (
          <Spinner />
        )}
      </div>
    </div>
  );
}
