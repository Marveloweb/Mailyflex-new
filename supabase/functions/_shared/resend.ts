import { env } from './env.ts';

// Overridable for local end-to-end tests; production uses the default.
const API = (Deno.env.get('RESEND_API_BASE') ?? 'https://api.resend.com').replace(/\/$/, '');

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${env('RESEND_API_KEY')}`, 'Content-Type': 'application/json', ...(init.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`Resend ${path} failed: HTTP ${res.status} ${(await res.text()).slice(0, 300)}`);
  return (await res.json()) as T;
}

export interface ReceivedAttachment {
  id: string;
  filename: string;
  content_type: string;
  size?: number;
  download_url: string;
}

export async function listReceivedAttachments(emailId: string): Promise<ReceivedAttachment[]> {
  const r = await call<{ data: ReceivedAttachment[] }>(`/emails/receiving/${encodeURIComponent(emailId)}/attachments`);
  return r.data ?? [];
}

export async function downloadAttachment(a: ReceivedAttachment, maxBytes = 25 * 1024 * 1024): Promise<Uint8Array> {
  const res = await fetch(a.download_url);
  if (!res.ok) throw new Error(`Attachment download failed: HTTP ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length > maxBytes) throw new Error('Attachment too large');
  return buf;
}

export async function sendEmail(msg: { from: string; to: string[]; subject: string; html: string; text: string; idempotencyKey?: string }) {
  const { idempotencyKey, ...body } = msg;
  return call<{ id: string }>('/emails', {
    method: 'POST',
    body: JSON.stringify(body),
    headers: idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {},
  });
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/** Minimal branded wrapper for transactional emails. */
export function layout(title: string, bodyHtml: string): string {
  return `<!doctype html><html><body style="margin:0;background:#f6f7f9;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111827">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;padding:32px">
<tr><td style="font-weight:700;font-size:18px;color:#0f766e;padding-bottom:16px">Maily Flex</td></tr>
<tr><td style="font-size:20px;font-weight:600;padding-bottom:12px">${escapeHtml(title)}</td></tr>
<tr><td style="font-size:15px;line-height:1.6">${bodyHtml}</td></tr>
</table></td></tr></table></body></html>`;
}
