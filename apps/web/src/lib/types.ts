import type { ScanResult } from '@mailyflex/core';

export interface DomainRow {
  id: string;
  org_id: string;
  name: string;
  verification_token: string;
  verified_at: string | null;
  report_token: string;
  health_score: number | null;
  grade: string | null;
  last_scan_at: string | null;
  dkim_selectors: string[];
  hosted_dmarc: boolean;
  hosted_spf: boolean;
  hosted_mta_sts: boolean;
  created_at: string;
}

export interface ScanRow {
  id: number;
  score: number;
  grade: string;
  result: ScanResult;
  created_at: string;
}

export interface DmarcPolicyRow {
  domain_id: string;
  p: 'none' | 'quarantine' | 'reject';
  sp: 'none' | 'quarantine' | 'reject' | null;
  np: 'none' | 'quarantine' | 'reject' | null;
  adkim: 'r' | 's';
  aspf: 'r' | 's';
  t: boolean;
  extra_rua: string[];
}

export interface SpfConfigRow {
  domain_id: string;
  includes: string[];
  ip4: string[];
  ip6: string[];
  all_qualifier: '-' | '~';
  flattened: { host: string; value: string }[] | null;
  lookup_count: number | null;
  flattened_at: string | null;
  last_error: string | null;
}

export interface MtaStsConfigRow {
  domain_id: string;
  mode: 'none' | 'testing' | 'enforce';
  mx: string[];
  max_age: number;
  policy_id: string;
  tlsrpt_enabled: boolean;
}

export interface SenderStat {
  sender: string;
  sender_key: string | null;
  ip_count: number;
  total: number;
  passing: number;
  dkim_aligned: number;
  spf_aligned: number;
  sample_ip: string;
  ptr: string | null;
  as_name: string | null;
  last_seen: string;
}

export interface AlertRow {
  id: number;
  org_id: string;
  domain_id: string | null;
  kind: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  body: string;
  created_at: string;
  read_at: string | null;
}
