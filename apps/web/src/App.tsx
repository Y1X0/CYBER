// The console shell: identity, navigation, routing, and the atmosphere everything sits inside.
//
// The shell is where the product says what it is in the first three seconds, so it carries the
// boot sequence, the backdrop, the telemetry strip and the route transition. Everything below it
// — the thirteen screens — is unchanged logic rendering through restyled primitives.

import { useCallback, useEffect, useState } from "react";
import { AttackGraph } from "./AttackGraph";
import { CompliancePanel } from "./Compliance";
import { api, getToken, setToken } from "./api";
import {
  Backdrop, BootSequence, RouteTransition, SystemClock, TargetingCursor,
} from "./design/fx";
import { navigate, useRoute } from "./router";
import { AssetsScreen } from "./screens/Assets";
import { AuthorizationScreen } from "./screens/Authorization";
import { DashboardScreen } from "./screens/Dashboard";
import { DiscoveryScreen } from "./screens/Discovery";
import { FindingDetailScreen, FindingsScreen } from "./screens/Findings";
import { NotificationsScreen } from "./screens/Notifications";
import { AuthScreen } from "./screens/Onboarding";
import { OrganizationScreen } from "./screens/Organization";
import { OwnershipScreen } from "./screens/Ownership";
import { RemediationScreen } from "./screens/Remediation";
import { ReportsScreen } from "./screens/Reports";
import { ScanDetailScreen, ScansScreen } from "./screens/Scans";
import { Async, useAsync } from "./ui";

const NAV = [
  { screen: "dashboard", label: "Dashboard" },
  { screen: "organization", label: "Organization" },
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

  // The boot sequence runs once per browser session, not once per sign-in and not on every
  // reload of a screen an operator is working in. Cinema on first contact; out of the way after.
  const [booted, setBooted] = useState<boolean>(() => {
    try { return sessionStorage.getItem("guardian.booted") === "1"; } catch { return false; }
  });
  const finishBoot = useCallback(() => {
    setBooted(true);
    try { sessionStorage.setItem("guardian.booted", "1"); } catch { /* private mode: replay it */ }
  }, []);

  return (
    <>
      <Backdrop />
      <TargetingCursor />
      {!booted && <BootSequence onDone={finishBoot} />}
      {authed
        ? <Console onSignOut={() => { setToken(null); setAuthed(false); }} />
        : <AuthScreen onAuthed={() => setAuthed(true)} />}
    </>
  );
}

function Console({ onSignOut }: { onSignOut: () => void }) {
  const route = useRoute();
  const me = useAsync(() => api.me(), []);

  // Keep the document title tracking the route: browser history and tab switching are navigation
  // too, and a console that is always called "Security Guardian" is unusable with ten tabs open.
  useEffect(() => {
    const item = NAV.find((n) => n.screen === route.screen);
    document.title = item ? `${item.label} · Security Guardian` : "Security Guardian";
  }, [route.screen]);

  return (
    <div className="app">
      <div className="shell-brand hud-corners" onClick={() => navigate("dashboard")}
           role="button" tabIndex={0}
           onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") navigate("dashboard"); }}>
        <span className="mark" aria-hidden="true">◆</span>
        <span className="wordmark">Guardian<em>//</em>OPS</span>
      </div>

      <header className="shell-top">
        <div className="telemetry">
          <span className="live-dot" />
          <b>LINK SECURE</b>
          <span className="sep opt">│</span>
          <span className="opt">TLS 1.3 · AES-256-GCM</span>
          <span className="sep opt">│</span>
          <span className="opt">SESSION <SystemClock /></span>
        </div>
        <div className="telemetry">
          {me.data && <span className="opt">{me.data.email}</span>}
          <button onClick={onSignOut}>Sign out</button>
        </div>
      </header>

      <nav className="shell-nav" aria-label="Sections">
        {NAV.map((item, i) => (
          <button
            key={item.screen}
            className={route.screen === item.screen ? "nav-item on" : "nav-item"}
            aria-current={route.screen === item.screen ? "page" : undefined}
            onClick={() => navigate(item.screen)}
          >
            <span className="idx" aria-hidden="true">{String(i + 1).padStart(2, "0")}</span>
            {item.label}
          </button>
        ))}
      </nav>

      <main className="shell-main">
        {/* An expired session must not render as a set of empty screens. */}
        <Async loader={me}>
          {() => (
            <RouteTransition routeKey={`${route.screen}/${route.id ?? ""}`}>
              <Screen screen={route.screen} id={route.id} />
            </RouteTransition>
          )}
        </Async>
      </main>
    </div>
  );
}

function Screen({ screen, id }: { screen: string; id: string | null }) {
  switch (screen) {
    case "dashboard": return <DashboardScreen />;
    case "organization": return <OrganizationScreen />;
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
