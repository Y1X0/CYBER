// The console shell: identity, navigation, and the routing table.

import { useState } from "react";
import { AttackGraph } from "./AttackGraph";
import { CompliancePanel } from "./Compliance";
import { api, getToken, setToken } from "./api";
import { navigate, useRoute } from "./router";
import { AssetsScreen } from "./screens/Assets";
import { AuthorizationScreen } from "./screens/Authorization";
import { DashboardScreen } from "./screens/Dashboard";
import { DiscoveryScreen } from "./screens/Discovery";
import { FindingDetailScreen, FindingsScreen } from "./screens/Findings";
import { NotificationsScreen } from "./screens/Notifications";
import { AuthScreen } from "./screens/Onboarding";
import { OwnershipScreen } from "./screens/Ownership";
import { RemediationScreen } from "./screens/Remediation";
import { ReportsScreen } from "./screens/Reports";
import { ScanDetailScreen, ScansScreen } from "./screens/Scans";
import { Async, useAsync } from "./ui";

const NAV = [
  { screen: "dashboard", label: "Dashboard" },
  { screen: "assets", label: "Assets" },
  { screen: "ownership", label: "Domains" },
  { screen: "authorization", label: "Authorization" },
  { screen: "discovery", label: "Discovery" },
  { screen: "scans", label: "Scans" },
  { screen: "findings", label: "Findings" },
  { screen: "remediation", label: "Remediation" },
  { screen: "reports", label: "Reports" },
  { screen: "compliance", label: "Compliance" },
  { screen: "attack-paths", label: "Attack paths" },
  { screen: "notifications", label: "Notifications" },
];

export function App() {
  const [authed, setAuthed] = useState<boolean>(!!getToken());
  if (!authed) return <AuthScreen onAuthed={() => setAuthed(true)} />;
  return <Console onSignOut={() => { setToken(null); setAuthed(false); }} />;
}

function Console({ onSignOut }: { onSignOut: () => void }) {
  const route = useRoute();
  const me = useAsync(() => api.me(), []);

  return (
    <div className="app">
      <header>
        <h2 onClick={() => navigate("dashboard")} className="brand">🛡️ Security Guardian</h2>
        <div className="header-right">
          {me.data && <span className="muted">{me.data.email}</span>}
          <button onClick={onSignOut}>Sign out</button>
        </div>
      </header>

      <nav className="tabs">
        {NAV.map((item) => (
          <button
            key={item.screen}
            className={route.screen === item.screen ? "tab on" : "tab"}
            onClick={() => navigate(item.screen)}
          >
            {item.label}
          </button>
        ))}
      </nav>

      <main>
        {/* An expired session must not render as a set of empty screens. */}
        <Async loader={me}>{() => <Screen screen={route.screen} id={route.id} />}</Async>
      </main>
    </div>
  );
}

function Screen({ screen, id }: { screen: string; id: string | null }) {
  switch (screen) {
    case "dashboard": return <DashboardScreen />;
    case "assets": return <AssetsScreen />;
    case "ownership": return <OwnershipScreen />;
    case "authorization": return <AuthorizationScreen />;
    case "discovery": return <DiscoveryScreen />;
    case "scans": return id ? <ScanDetailScreen id={id} /> : <ScansScreen />;
    case "findings": return id ? <FindingDetailScreen id={id} /> : <FindingsScreen />;
    case "remediation": return <RemediationScreen />;
    case "reports": return <ReportsScreen />;
    case "compliance": return <CompliancePanel />;
    case "attack-paths": return <AttackGraph />;
    case "notifications": return <NotificationsScreen />;
    default:
      return (
        <div className="state state-empty">
          <h4>Nothing here</h4>
          <p>That screen does not exist. Pick one from the navigation above.</p>
        </div>
      );
  }
}
