export const GOOGLE_REPORT_XML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>4865322011347193701</report_id>
    <date_range>
      <begin>1730937600</begin>
      <end>1731023999</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>209.85.220.41</source_ip>
      <count>120</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <result>pass</result>
        <selector>google</selector>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.23</source_ip>
      <count>7</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
        <reason><type>forwarded</type><comment>looks forwarded</comment></reason>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>spammer.test</domain>
        <result>softfail</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>167.89.0.10</source_ip>
      <count>40</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <result>pass</result>
        <selector>s1</selector>
      </dkim>
      <dkim>
        <domain>sendgrid.net</domain>
        <result>pass</result>
        <selector>smtpapi</selector>
      </dkim>
      <spf>
        <domain>em123.example.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>`;

export const RFC9990_REPORT_XML = `<?xml version="1.0" encoding="UTF-8"?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <version>1.0</version>
  <report_metadata>
    <org_name>Example Receiver</org_name>
    <email>dmarc@receiver.example</email>
    <report_id>abc-123</report_id>
    <date_range><begin>1762560000</begin><end>1762646399</end></date_range>
    <error>one record skipped</error>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain>
    <p>reject</p>
    <sp>quarantine</sp>
    <np>reject</np>
    <testing>n</testing>
    <discovery_method>treewalk</discovery_method>
  </policy_published>
  <record>
    <row>
      <source_ip>2001:db8::25</source_ip>
      <count>3</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from><envelope_from>bounce.example.org</envelope_from></identifiers>
    <auth_results><spf><domain>bounce.example.org</domain><scope>mfrom</scope><result>fail</result></spf></auth_results>
  </record>
</feedback>`;

export async function rsaSpki(bits: number): Promise<string> {
  const key = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', key.publicKey));
  let bin = '';
  for (const b of spki) bin += String.fromCharCode(b);
  return btoa(bin);
}
