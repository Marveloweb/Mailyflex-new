import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { Button, Field, Input, Notice } from '../../components/ui.tsx';
import { useOrg } from '../../lib/org.tsx';
import { db, errorMessage } from '../../lib/supabase.ts';

export function NewOrg() {
  const { orgs, reload, select } = useOrg();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { data, error: err } = await db().rpc('create_organization', { p_name: name });
      if (err) throw err;
      select(data as string);
      await reload();
      navigate('/app/domains/new');
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="max-w-lg">
      <h1 className="text-3xl">{orgs.length ? 'New organization' : 'Name your organization'}</h1>
      <p className="mt-2 text-ink-soft">Domains, reports and teammates belong to an organization. Use your company or client name.</p>
      <form onSubmit={submit} className="mt-8 space-y-5">
        <Field label="Organization name" htmlFor="org-name">
          <Input id="org-name" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Ltd" autoFocus />
        </Field>
        {error && <Notice status="fail">{error}</Notice>}
        <Button type="submit" busy={busy} disabled={!name.trim()}>
          Create organization
        </Button>
      </form>
    </div>
  );
}
