import type { HostedEnv } from '@mailyflex/core';

export const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL as string | undefined;
export const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;
export const backendConfigured = !!SUPABASE_URL && !!SUPABASE_ANON_KEY;

export const hostedEnv: HostedEnv = {
  zone: import.meta.env.VITE_HOSTED_DNS_ZONE || 'dns.mailyflex.com',
  ruaDomain: import.meta.env.VITE_RUA_DOMAIN || 'rua.mailyflex.com',
  tlsRptDomain: import.meta.env.VITE_TLSRPT_DOMAIN || 'tls.mailyflex.com',
  mtaStsTarget: import.meta.env.VITE_MTA_STS_TARGET || 'sts.dns.mailyflex.com',
};
