// Resend inbound webhook (email.received) → DMARC aggregate reports stored per domain.
import { DohResolver } from '@mailyflex/core';
import { env, hostedEnv } from '../_shared/env.ts';
import { handler, HttpError, json } from '../_shared/http.ts';
import { downloadAttachment, listReceivedAttachments } from '../_shared/resend.ts';
import { serviceClient } from '../_shared/supabase.ts';
import { verifySvix } from '../_shared/svix.ts';
import { processInbound, type InboundEvent } from './process.ts';

Deno.serve(
  handler(async (req) => {
    if (req.method !== 'POST') throw new HttpError(405, 'POST only');
    const body = await req.text();
    if (body.length > 1_000_000) throw new HttpError(413, 'Too large');
    const ok = await verifySvix(
      env('RESEND_WEBHOOK_SECRET'),
      { id: req.headers.get('svix-id'), timestamp: req.headers.get('svix-timestamp'), signature: req.headers.get('svix-signature') },
      body,
    );
    if (!ok) throw new HttpError(401, 'Invalid signature');
    const event = JSON.parse(body) as InboundEvent;
    if (event.type !== 'email.received' || !event.data?.email_id) return json(req, { ignored: true });

    const db = serviceClient();
    const emailId = event.data.email_id;
    const recipient = Array.isArray(event.data.to) ? event.data.to.join(',') : (event.data.to ?? '');
    // Idempotency: Resend retries; the unique email id makes the second delivery a no-op.
    const { error: logErr } = await db.from('inbound_log').insert({ resend_email_id: emailId, recipient: recipient.slice(0, 500), status: 'processing' });
    if (logErr) {
      if (logErr.code === '23505') return json(req, { duplicate: true });
      throw logErr;
    }
    try {
      const result = await processInbound(event, {
        ruaDomain: hostedEnv().ruaDomain,
        resolver: new DohResolver(),
        listAttachments: async (id) =>
          (await listReceivedAttachments(id)).map((a) => ({ filename: a.filename, content_type: a.content_type, bytes: () => downloadAttachment(a) })),
        ingest: async (token, report) => {
          const { data, error } = await db.rpc('ingest_dmarc_report', { p_report_token: token, p_report: report });
          if (error) throw error;
          return data as { status: string };
        },
        getIntel: async (ips) => {
          const { data } = await db.from('ip_intel').select('*').in('ip', ips.slice(0, 500));
          return new Map((data ?? []).map((r: { ip: string; ptr: string | null; asn: number | null; as_name: string | null; country: string | null; sender_key: string | null; updated_at: string }) => [
            r.ip,
            { ip: r.ip, ptr: r.ptr, asn: r.asn, asName: r.as_name, country: r.country, sender_key: r.sender_key, updated_at: r.updated_at },
          ]));
        },
        saveIntel: async (rows) => {
          await db.from('ip_intel').upsert(
            rows.map((r) => ({ ip: r.ip, ptr: r.ptr, asn: r.asn, as_name: r.asName, country: r.country, sender_key: r.sender_key, updated_at: new Date().toISOString() })),
          );
        },
      });
      const status = !result.token ? 'no_token' : result.reports.some((r) => r.status === 'stored') ? 'stored' : result.reports.map((r) => r.status).join(',') || 'no_attachments';
      await db.from('inbound_log').update({ status, detail: JSON.stringify(result).slice(0, 4000) }).eq('resend_email_id', emailId);
      return json(req, result);
    } catch (e) {
      // Transient failure (Resend API, database): forget this delivery so the retry is processed.
      await db.from('inbound_log').delete().eq('resend_email_id', emailId);
      throw e;
    }
  }),
);
