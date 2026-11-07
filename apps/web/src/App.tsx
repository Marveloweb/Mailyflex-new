import { BrowserRouter, Route, Routes } from 'react-router';
import { AuthProvider } from './lib/auth.tsx';
import { OrgProvider } from './lib/org.tsx';
import { PublicLayout } from './components/PublicLayout.tsx';
import { AppShell } from './components/AppShell.tsx';
import { Landing } from './pages/Landing.tsx';
import { AuthPage, SetupRequired } from './pages/Auth.tsx';
import { InviteAccept } from './pages/InviteAccept.tsx';
import { ToolsHub } from './pages/tools/ToolsHub.tsx';
import { BimiCheckPage, BlacklistCheckPage, DkimCheckPage, DmarcCheckPage, DomainCheckPage, MtaStsCheckPage, MxCheckPage, SpfCheckPage, TlsRptCheckPage } from './pages/tools/checkers.tsx';
import { DmarcGeneratorPage, SpfGeneratorPage } from './pages/tools/generators.tsx';
import { NewOrg } from './pages/app/NewOrg.tsx';
import { AddDomain, Domains } from './pages/app/Domains.tsx';
import { DomainLayout, DomainOverview } from './pages/app/DomainDetail.tsx';
import { DomainReports, DomainSenders } from './pages/app/DomainReports.tsx';
import { DomainHosted } from './pages/app/DomainHosted.tsx';
import { DomainEnforcement } from './pages/app/DomainEnforcement.tsx';
import { Alerts } from './pages/app/Alerts.tsx';
import { Settings } from './pages/app/Settings.tsx';
import { Link } from 'react-router';

function NotFound() {
  return (
    <div className="mx-auto max-w-xl px-5 py-20">
      <h1 className="text-3xl">This page doesn&apos;t exist</h1>
      <p className="mt-3 text-ink-soft">
        Check the address, or go back to the <Link className="text-airmail-blue underline" to="/">home page</Link>.
      </p>
    </div>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <OrgProvider>
          <Routes>
            <Route element={<PublicLayout />}>
              <Route index element={<Landing />} />
              <Route path="tools" element={<ToolsHub />} />
              <Route path="tools/domain" element={<DomainCheckPage />} />
              <Route path="tools/spf" element={<SpfCheckPage />} />
              <Route path="tools/dkim" element={<DkimCheckPage />} />
              <Route path="tools/dmarc" element={<DmarcCheckPage />} />
              <Route path="tools/bimi" element={<BimiCheckPage />} />
              <Route path="tools/mta-sts" element={<MtaStsCheckPage />} />
              <Route path="tools/tls-rpt" element={<TlsRptCheckPage />} />
              <Route path="tools/mx" element={<MxCheckPage />} />
              <Route path="tools/blacklist" element={<BlacklistCheckPage />} />
              <Route path="tools/spf-generator" element={<SpfGeneratorPage />} />
              <Route path="tools/dmarc-generator" element={<DmarcGeneratorPage />} />
              <Route path="login" element={<AuthPage mode="login" />} />
              <Route path="signup" element={<AuthPage mode="signup" />} />
              <Route path="invite/:token" element={<InviteAccept />} />
              <Route path="setup-required" element={<SetupRequired />} />
              <Route path="*" element={<NotFound />} />
            </Route>
            <Route path="app" element={<AppShell />}>
              <Route index element={<Domains />} />
              <Route path="new-org" element={<NewOrg />} />
              <Route path="domains/new" element={<AddDomain />} />
              <Route path="domains/:id" element={<DomainLayout />}>
                <Route index element={<DomainOverview />} />
                <Route path="reports" element={<DomainReports />} />
                <Route path="senders" element={<DomainSenders />} />
                <Route path="hosted" element={<DomainHosted />} />
                <Route path="enforcement" element={<DomainEnforcement />} />
              </Route>
              <Route path="alerts" element={<Alerts />} />
              <Route path="settings" element={<Settings />} />
            </Route>
          </Routes>
        </OrgProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
