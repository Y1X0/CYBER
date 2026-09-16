// The security dashboard. Every number is served by GET /dashboard; nothing is computed from a
// guess and nothing is hardcoded. Where a value has no data behind it the screen says so.

import { Dashboard, api } from "../api";
import {
  Counter, EdgeAlert, Radar, SecurityGauge, TerminalPanel, TermLine, ThreatBar,
} from "../design/fx";
import { navigate } from "../router";
import { SCAN_TYPES } from "../scanCatalog";
import { Async, Bars, Card, SEVERITIES, SEV_COLOR, Stat, StatusPill, useAsync, when } from "../ui";

export function DashboardScreen() {
  const loader = useAsync(() => api.dashboard(), []);
  const queue = useAsync(() => api.queueHealth(), []);

  return (
    <Async loader={loader}>
      {(d: Dashboard) => {
        // The score is only a score once something has been measured. With no completed scan
        // there is no evidence behind it, so the gauge gets null and renders a dash.
        //
        // This is the same rule as `engine_outcome()` in the scanner, one layer up: "nothing was
        // found" and "nothing was looked for" must not render alike. A 100/100 on a tenant that
        // has never run a scan is the interface telling a customer they are secure on the
        // strength of having asked nothing — and the number is what people remember, not the
        // sentence under it.
        const measured = d.scans_completed > 0 && d.last_successful_scan_at !== null;
        const score = measured ? d.security_score : null;

        const criticals = d.open_severity_counts.critical ?? 0;

        // A brand-new account has nothing to summarise. Rather than a technical dashboard of zeroes,
        // it gets a welcome that answers the only question it has yet: what would you like to scan?
        // The moment the first asset or scan exists, this gives way to the security overview.
        const firstRun = d.assets_total === 0 && d.scans_completed === 0 && d.scans_active === 0;
        if (firstRun) return <FirstRun />;

        return (
          <>
            {/* Only while unresolved criticals exist. A frame that is always red is wallpaper. */}
            <EdgeAlert active={criticals > 0} />

            <ThreatBar
              counts={d.open_severity_counts}
              measured={measured}
              note={measured
                ? `${d.assets_total} asset(s) · ${d.scans_completed} scan(s) completed`
                : "run a scan to establish a baseline"}
            />

            {queue.data?.state === "stalled" && (
              <div className="state state-blocked" role="alert">
                <h4>Your scans are queued but nothing is running</h4>
                <p>{queue.data.detail}</p>
              </div>
            )}

            <div className="stats">
              <Stat label="Open findings" value={<Counter value={d.open_findings} />}
                    tone={d.open_severity_counts.critical ? "bad" : undefined}
                    hint="Findings still needing a decision" />
              <Stat label="Critical" value={<Counter value={d.open_severity_counts.critical ?? 0} />}
                    tone="bad" />
              <Stat label="High" value={<Counter value={d.open_severity_counts.high ?? 0} />}
                    tone="warn" />
              <Stat label="Assets" value={<Counter value={d.assets_total} />} />
              <Stat label="Active scans" value={<Counter value={d.scans_active} />}
                    hint={d.scans_active ? "queued or running" : "nothing in flight"} />
              <Stat label="Completed scans" value={<Counter value={d.scans_completed} />} />
            </div>

            <div className="grid-2">
              <Card title="Security posture">
                <div style={{ display: "flex", gap: "var(--s-5)", alignItems: "center",
                              flexWrap: "wrap" }}>
                  <SecurityGauge value={score} caption={measured ? "score" : "no data"} />
                  <Radar blips={d.assets_total} />
                  <div style={{ flex: "1 1 200px", minWidth: 0 }}>
                    {measured ? (
                      <p className="muted">
                        {d.security_score}/100, computed from open findings by the deterministic
                        risk engine. It reflects what has been checked, not everything that exists.
                      </p>
                    ) : (
                      <p className="warn-text">
                        Not calculated. No scan has completed, so there is no evidence to score.
                        This is not a 100 and not a 0 — it is unknown.
                      </p>
                    )}
                    {d.total_findings === 0 ? (
                      <p className="muted">
                        No findings recorded yet. That is not a clean bill of health until a scan
                        has actually run — check the scan history.
                      </p>
                    ) : (
                      <Bars
                        series={SEVERITIES.map((s) =>
                          ({ key: s, value: d.open_severity_counts[s] ?? 0 }))}
                        colors={SEV_COLOR}
                      />
                    )}
                  </div>
                </div>
              </Card>

              <Card title="Scan health">
                <dl className="kv">
                  <dt>Last successful scan</dt>
                  <dd>{d.last_successful_scan_at ? when(d.last_successful_scan_at) : (
                    <span className="warn-text">never — nothing has completed yet</span>
                  )}</dd>
                  <dt>Scanner</dt>
                  <dd>
                    {queue.data
                      ? <StatusPill tone={queue.data.state === "stalled" ? "bad"
                          : queue.data.state === "working" ? "wait" : "ok"}>
                          {queue.data.state}
                        </StatusPill>
                      : <span className="muted">unknown</span>}
                  </dd>
                </dl>

                {/* Real scan records as a log stream. The terminal prints what the API returned
                    and nothing else — a console that invents plausible-looking events teaches
                    its operator to stop reading it. */}
                <TerminalPanel
                  title="scan.log"
                  live={d.scans_active > 0}
                  lines={toLog(d)}
                />

                {Object.keys(d.engine_runs_unresolved).length > 0 && (
                  <div className="notice">
                    {/* The point of the whole dashboard: these are not clean results. */}
                    <strong>Some engines did not answer in the last 30 days.</strong>
                    <ul>
                      {Object.entries(d.engine_runs_unresolved).map(([state, n]) => (
                        <li key={state}>{n} engine run(s) {state}</li>
                      ))}
                    </ul>
                    <p className="muted">
                      An engine that failed, was skipped or was deferred found nothing and proved
                      nothing. Treat its silence as unknown, not clean.
                    </p>
                  </div>
                )}
              </Card>
            </div>

            <div className="grid-2">
              <Card title={`New findings (last ${d.trend_days} days)`}>
                <TrendTable
                  rows={d.risk_trend.map((r) => ({ day: r.day, key: r.severity, count: r.count }))}
                  keyLabel="Severity"
                  empty="No findings were recorded in this window."
                />
              </Card>
              <Card title={`Attack surface added (last ${d.trend_days} days)`}>
                <TrendTable
                  rows={d.exposure_trend.map((r) => ({ day: r.day, key: r.exposure, count: r.count }))}
                  keyLabel="Exposure"
                  empty="No assets were added in this window."
                />
                <p className="muted">
                  Assets by the day they were first seen. This is surface growth, not a risk score
                  over time — that was never recorded, so it is not shown.
                </p>
              </Card>
            </div>

            <Card title="Remediation">
              {Object.keys(d.remediation_by_status).length === 0 ? (
                <p className="muted">
                  No remediation work has been opened. Open findings do not track themselves —
                  open work from the Remediation screen.
                </p>
              ) : (
                <>
                  <Bars series={Object.entries(d.remediation_by_status)
                    .map(([k, v]) => ({ key: k, value: v }))} />
                  {d.remediation_overdue > 0 && (
                    <p className="warn-text">{d.remediation_overdue} item(s) past their due date.</p>
                  )}
                </>
              )}
            </Card>

            <Card title="Recent scans" actions={
              <button onClick={() => navigate("scans")}>All scans</button>
            }>
              {d.recent_scans.length === 0 ? (
                <p className="muted">No scans yet.</p>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr><th>Started</th><th>Status</th><th>Engines</th><th>Findings</th><th /></tr>
                    </thead>
                    <tbody>
                      {d.recent_scans.map((s) => (
                        <tr key={s.id}>
                          <td>{when(s.created_at)}</td>
                          <td>{s.status}</td>
                          <td>{s.requested_engines.join(", ")}</td>
                          <td>{s.stats?.total ?? 0}</td>
                          <td>
                            <button onClick={() => navigate(`scans/${s.id}`)}>Open</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </>
        );
      }}
    </Async>
  );
}

/** The first thing a new account sees: a welcome, and the one question it can answer — what to
 *  scan. Each tile opens the guided flow pre-set to that kind. Gone the moment there is a scan. */
function FirstRun() {
  return (
    <div className="welcome">
      <div className="welcome-hero hud-corners">
        <span className="welcome-eyebrow">◆ Security Guardian</span>
        <h1 className="welcome-title">Protect what you own.</h1>
        <p className="welcome-sub">
          Guardian assesses things you tell it about — a website, an app, a server, a cloud account,
          your code. Choose what you'd like to check and it sets up the target and runs the right
          engines for you.
        </p>
      </div>

      <h2 className="welcome-q">What would you like to scan?</h2>
      <div className="scan-type-grid">
        {SCAN_TYPES.map((t) => (
          <button key={t.id} className="scan-type hud-corners"
                  onClick={() => navigate(`new-scan/${t.id}`)}>
            <span className="scan-type-icon" aria-hidden="true">{t.icon}</span>
            <span className="scan-type-label">{t.label}</span>
            <span className="scan-type-blurb">{t.blurb}</span>
            {t.network && <span className="scan-type-tag">needs authorization</span>}
          </button>
        ))}
      </div>

      <div className="welcome-cta">
        <button className="btn-primary" onClick={() => navigate("new-scan")}>
          Start your first scan →
        </button>
      </div>
    </div>
  );
}

/** Real scan history as terminal lines. Derived from the same records the table below shows —
 *  one source, two presentations, no third set of numbers to disagree with them. */
function toLog(d: Dashboard): TermLine[] {
  return d.recent_scans.slice(0, 8).map((s) => ({
    t: (s.created_at ?? "").slice(11, 19),
    text: `scan ${s.id.slice(0, 8)} ${s.status} · ${s.requested_engines.join(",") || "no engines"}`
          + ` · ${s.stats?.total ?? 0} finding(s)`,
    tone: s.status === "failed" ? "bad"
        : s.status === "partial" ? "warn"
        : s.status === "completed" ? "ok"
        : undefined,
  }));
}

function TrendTable({ rows, keyLabel, empty }:
  { rows: { day: string; key: string; count: number }[]; keyLabel: string; empty: string }) {
  if (rows.length === 0) return <p className="muted">{empty}</p>;
  const byDay = new Map<string, { key: string; count: number }[]>();
  for (const r of rows) {
    byDay.set(r.day, [...(byDay.get(r.day) ?? []), { key: r.key, count: r.count }]);
  }
  const days = [...byDay.keys()].sort().reverse();
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Day</th><th>{keyLabel}</th><th>Count</th></tr></thead>
        <tbody>
          {days.flatMap((day) =>
            (byDay.get(day) ?? []).map((entry) => (
              <tr key={`${day}-${entry.key}`}>
                <td>{day}</td><td>{entry.key}</td><td>{entry.count}</td>
              </tr>
            )))}
        </tbody>
      </table>
    </div>
  );
}
