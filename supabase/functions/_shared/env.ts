import type { HostedEnv } from '@mailyflex/core';

export function env(name: string, fallback?: string): string {
  const v = Deno.env.get(name) ?? fallback;
  if (v === undefined || v === '') throw new Error(`Missing environment variable ${name}`);
  return v;
}

export function optionalEnv(name: string): string | undefined {
  const v = Deno.env.get(name);
  return v === '' ? undefined : v;
}

export function hostedEnv(): HostedEnv {
  return {
    zone: env('HOSTED_DNS_ZONE', 'dns.mailyflex.com'),
    ruaDomain: env('RUA_DOMAIN', 'rua.mailyflex.com'),
    tlsRptDomain: env('TLSRPT_DOMAIN', 'tls.mailyflex.com'),
    mtaStsTarget: env('MTA_STS_TARGET', 'sts.dns.mailyflex.com'),
  };
}

export const appUrl = () => env('APP_URL', 'https://app.mailyflex.com').replace(/\/$/, '');
export const mailFrom = () => env('MAIL_FROM', 'Maily Flex <alerts@mailyflex.com>');
