// The security dashboard. Every number is served by GET /dashboard; nothing is computed from a
// guess and nothing is hardcoded. Where a value has no data behind it the screen says so.

import { Dashboard, api } from "../api";
import { navigate } from "../router";
import { Async, Bars, Card, SEVERITIES, SEV_COLOR, Stat, StatusPill, useAsync, when } from "../ui";

export function DashboardScreen() {
  const loader = useAsync(() => api.dashboard(), []);
  const queue = useAsync(() => api.queueHealth(), []);

  return (
    <Async loader={loader}>
      {(d: Dashboard) => (
        <>
          {queue.data?.state === "stalled" && (
            <div className="state state-blocked" role="alert">
              <h4>Your scans are queued but nothing is running</h4>
              <p>{queue.data.detail}</p>
            </div>
          )}

          <div className="stats">
            <Stat label="Open findings" value={d.open_findings}
                  tone={d.open_severity_counts.critical ? "bad" : undefined}
                  hint="Findings still needing a decision" />
            <Stat label="Critical" value={d.open_severity_counts.critical ?? 0} tone="bad" />
            <Stat label="High" value={d.open_severity_counts.high ?? 0} tone="warn" />
            <Stat label="Assets" value={d.assets_total} />
            <Stat label="Active scans" value={d.scans_active}
                  hint={d.scans_active ? "queued or running" : "nothing in flight"} />
            <Stat label="Completed scans" value={d.scans_completed} />
          </div>

          <div className="grid-2">
            <Card title="Findings by severity">
              {d.total_findings === 0 ? (
                <p className="muted">
                  No findings recorded yet. That is not a clean bill of health until a scan has
                  actually run — check the scan history.
                </p>
              ) : (
                <Bars
                  series={SEVERITIES.map((s) => ({ key: s, value: d.open_severity_counts[s] ?? 0 }))}
                  colors={SEV_COLOR}
                />
              )}
              <p className="muted">
                Security score {d.security_score}/100, computed from open findings by the
                deterministic risk engine.
              </p>
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
            )}
          </Card>
        </>
      )}
    </Async>
  );
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
  );
}
