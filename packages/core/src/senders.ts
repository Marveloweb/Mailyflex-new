/**
 * Sender identification: map a sending IP (via PTR + ASN) or DKIM/SPF domains seen in DMARC
 * reports to a known email service.
 */
import { reverseIpName, type Resolver } from './dns.ts';
import { isIPv4 } from './ip.ts';

export interface KnownSender {
  key: string;
  name: string;
  category: 'mailbox' | 'marketing' | 'transactional' | 'crm' | 'support' | 'security' | 'other';
  ptrSuffixes: string[];
  asns: number[];
  /** Domains seen as DKIM d= or envelope-from / SPF domain. */
  authDomains: string[];
  spfInclude?: string;
  docsUrl?: string;
}

export const KNOWN_SENDERS: KnownSender[] = [
  { key: 'google', name: 'Google Workspace', category: 'mailbox', ptrSuffixes: ['google.com', 'googlemail.com'], asns: [15169, 396982], authDomains: ['google.com', 'gappssmtp.com', 'googlemail.com'], spfInclude: '_spf.google.com', docsUrl: 'https://support.google.com/a/answer/174124' },
  { key: 'microsoft', name: 'Microsoft 365', category: 'mailbox', ptrSuffixes: ['outbound.protection.outlook.com', 'protection.outlook.com', 'outlook.com'], asns: [8075], authDomains: ['onmicrosoft.com', 'outlook.com'], spfInclude: 'spf.protection.outlook.com', docsUrl: 'https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure' },
  { key: 'sendgrid', name: 'SendGrid', category: 'transactional', ptrSuffixes: ['sendgrid.net'], asns: [11377], authDomains: ['sendgrid.net', 'sendgrid.info'], spfInclude: 'sendgrid.net', docsUrl: 'https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication' },
  { key: 'mailchimp', name: 'Mailchimp / Mandrill', category: 'marketing', ptrSuffixes: ['mcsv.net', 'mcdlv.net', 'rsgsv.net', 'mandrillapp.com'], asns: [], authDomains: ['mcsv.net', 'mcdlv.net', 'rsgsv.net', 'mandrillapp.com', 'mailchimpapp.net'], spfInclude: 'servers.mcsv.net', docsUrl: 'https://mailchimp.com/help/set-up-email-domain-authentication/' },
  { key: 'amazonses', name: 'Amazon SES', category: 'transactional', ptrSuffixes: ['amazonses.com', 'smtp-out.amazonses.com'], asns: [16509, 14618], authDomains: ['amazonses.com'], spfInclude: 'amazonses.com', docsUrl: 'https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication.html' },
  { key: 'mailgun', name: 'Mailgun', category: 'transactional', ptrSuffixes: ['mailgun.net', 'mailgun.org'], asns: [], authDomains: ['mailgun.org', 'mailgun.net'], spfInclude: 'mailgun.org', docsUrl: 'https://documentation.mailgun.com/docs/mailgun/user-manual/get-started/' },
  { key: 'postmark', name: 'Postmark', category: 'transactional', ptrSuffixes: ['mtasv.net'], asns: [], authDomains: ['mtasv.net', 'pm.mtasv.net'], spfInclude: 'spf.mtasv.net', docsUrl: 'https://postmarkapp.com/support/article/1046-how-do-i-add-dkim-to-my-domain' },
  { key: 'resend', name: 'Resend', category: 'transactional', ptrSuffixes: [], asns: [], authDomains: ['resend.dev', 'resend.com'], spfInclude: 'amazonses.com', docsUrl: 'https://resend.com/docs/dashboard/domains/introduction' },
  { key: 'brevo', name: 'Brevo (Sendinblue)', category: 'marketing', ptrSuffixes: ['sendinblue.com', 'brevo.com', 'sender-sib.com'], asns: [200484], authDomains: ['sendinblue.com', 'brevo.com', 'sender-sib.com'], spfInclude: 'spf.brevo.com', docsUrl: 'https://help.brevo.com/hc/en-us/articles/12163873383186' },
  { key: 'hubspot', name: 'HubSpot', category: 'crm', ptrSuffixes: ['hubspotemail.net', 'hubspot.net'], asns: [], authDomains: ['hubspotemail.net', 'hubspot.com', 'hs-email.net'], docsUrl: 'https://knowledge.hubspot.com/marketing-email/manage-email-authentication-in-hubspot' },
  { key: 'salesforce', name: 'Salesforce', category: 'crm', ptrSuffixes: ['salesforce.com', 'exacttarget.com'], asns: [14340, 22606], authDomains: ['salesforce.com', 'exacttarget.com', 'force.com'], spfInclude: '_spf.salesforce.com' },
  { key: 'zendesk', name: 'Zendesk', category: 'support', ptrSuffixes: ['zendesk.com'], asns: [], authDomains: ['zendesk.com', 'zdsys.com'], spfInclude: 'mail.zendesk.com' },
  { key: 'freshdesk', name: 'Freshdesk', category: 'support', ptrSuffixes: ['freshdesk.com', 'freshemail.io'], asns: [], authDomains: ['freshdesk.com', 'freshemail.io'], spfInclude: 'email.freshdesk.com' },
  { key: 'zoho', name: 'Zoho Mail', category: 'mailbox', ptrSuffixes: ['zoho.com', 'zohomail.com', 'zoho.eu', 'zoho.in'], asns: [2639], authDomains: ['zoho.com', 'zohomail.com', 'zoho.eu', 'zoho.in'], spfInclude: 'zohomail.com' },
  { key: 'klaviyo', name: 'Klaviyo', category: 'marketing', ptrSuffixes: ['klaviyomail.com'], asns: [], authDomains: ['klaviyomail.com', 'klaviyo.com', 'kmail-lists.com'] },
  { key: 'constantcontact', name: 'Constant Contact', category: 'marketing', ptrSuffixes: ['constantcontact.com', 'ccsend.com'], asns: [], authDomains: ['constantcontact.com', 'ccsend.com', 'ccsend.com'], spfInclude: 'spf.constantcontact.com' },
  { key: 'campaignmonitor', name: 'Campaign Monitor', category: 'marketing', ptrSuffixes: ['createsend.com', 'cmail19.com', 'cmail20.com'], asns: [], authDomains: ['createsend.com', 'cmail19.com', 'cmail20.com'], spfInclude: '_spf.createsend.com' },
  { key: 'proton', name: 'Proton Mail', category: 'mailbox', ptrSuffixes: ['protonmail.ch', 'proton.ch'], asns: [62371], authDomains: ['protonmail.ch', 'proton.ch'], spfInclude: '_spf.protonmail.ch' },
  { key: 'fastmail', name: 'Fastmail', category: 'mailbox', ptrSuffixes: ['messagingengine.com', 'fastmail.com'], asns: [], authDomains: ['messagingengine.com', 'fastmail.com'], spfInclude: 'spf.messagingengine.com' },
  { key: 'mimecast', name: 'Mimecast', category: 'security', ptrSuffixes: ['mimecast.com'], asns: [30031], authDomains: ['mimecast.com'] },
  { key: 'proofpoint', name: 'Proofpoint', category: 'security', ptrSuffixes: ['pphosted.com', 'ppe-hosted.com'], asns: [22843, 26211], authDomains: ['pphosted.com'] },
];

const BY_KEY = new Map(KNOWN_SENDERS.map((s) => [s.key, s]));

export function senderByKey(key: string): KnownSender | undefined {
  return BY_KEY.get(key);
}

function matchesSuffix(host: string, suffix: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return h === suffix || h.endsWith(`.${suffix}`);
}

export interface SenderEvidence {
  ptr?: string | null;
  asn?: number | null;
  /** DKIM d= domains and SPF/envelope domains from the report record. */
  authDomains?: string[];
}

export function identifySender(e: SenderEvidence): KnownSender | undefined {
  const domains = (e.authDomains ?? []).map((d) => d.toLowerCase());
  // Strongest signal first: authenticated domains (DKIM d= / SPF), then PTR, then ASN.
  for (const s of KNOWN_SENDERS) if (domains.some((d) => s.authDomains.some((a) => matchesSuffix(d, a)))) return s;
  if (e.ptr) for (const s of KNOWN_SENDERS) if (s.ptrSuffixes.some((p) => matchesSuffix(e.ptr!, p))) return s;
  if (e.asn) for (const s of KNOWN_SENDERS) if (s.asns.includes(e.asn)) return s;
  return undefined;
}

export interface IpIntel {
  ip: string;
  ptr: string | null;
  asn: number | null;
  asName: string | null;
  country: string | null;
}

/** PTR + ASN (via Team Cymru's DNS service) for an IP. */
export async function lookupIpIntel(ip: string, resolver: Resolver): Promise<IpIntel> {
  const rev = reverseIpName(ip);
  const out: IpIntel = { ip, ptr: null, asn: null, asName: null, country: null };
  if (!rev) return out;
  const v4 = isIPv4(ip);
  const [ptr, origin] = await Promise.all([
    resolver.query(`${rev}.${v4 ? 'in-addr' : 'ip6'}.arpa`, 'PTR'),
    resolver.query(`${rev}.${v4 ? 'origin' : 'origin6'}.asn.cymru.com`, 'TXT'),
  ]);
  out.ptr = ptr.answers[0]?.data ?? null;
  const o = origin.answers[0]?.data;
  if (o) {
    const [asnPart, , country] = o.split('|').map((s) => s.trim());
    const asn = Number(asnPart?.split(' ')[0]);
    if (Number.isFinite(asn) && asn > 0) {
      out.asn = asn;
      out.country = country || null;
      const name = await resolver.query(`AS${asn}.asn.cymru.com`, 'TXT');
      const parts = name.answers[0]?.data.split('|').map((s) => s.trim());
      out.asName = parts?.[4] ?? null;
    }
  }
  return out;
}
