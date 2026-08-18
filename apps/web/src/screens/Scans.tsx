// Scan history and scan detail.
//
// The load-bearing rule: a scan that completed with no findings is only "clean" for the engines
// that actually ran. Every engine's outcome is shown, and an empty finding list is captioned by
// what was and was not checked.

import { EngineRun, Finding, Scan, api } from "../api";
import { navigate } from "../router";
import {
  Async, Card, EmptyState, ENGINE_STATE, SCAN_STATE, SeverityBadge, StatusPill,
  ago, useAsync, when,
} from "../ui";

export function ScansScreen() {
  const loader = useAsync(() => api.scans(), []);
  const queue = useAsync(() => api.queueHealth(), []);

  return (
    <>
      {queue.data && queue.data.state !== "idle" && (
        <Card title="Scanner">
          <p className={queue.data.state === "stalled" ? "err" : "muted"}>{queue.data.detail}</p>
          {queue.data.oldest_waiting_seconds > 0 && (
            <p className="muted">
              Oldest waiting scan: {ago(queue.data.oldest_waiting_seconds)}.
            </p>
          )}
        </Card>
      )}
      <Card title="Scan history">
        <Async
          loader={loader}
          empty={<EmptyState
            title="No scans yet"
            body="Start a scan from the Assets screen. Nothing is scanned automatically until you
                  ask for it."
            action={<button onClick={() => navigate("assets")}>Go to assets</button>}
          />}
        >
          {(page) => (
            <table>
              <thead>
                <tr><th>Started</th><th>Status</th><th>Engines</th><th>Findings</th>
                    <th>Finished</th><th /></tr>
              </thead>
              <tbody>
                {page.rows.map((s: Scan) => {
                  const state = SCAN_STATE[s.status] ?? { label: s.status, tone: "wait" };
                  return (
                    <tr key={s.id}>
                      <td>{when(s.created_at)}</td>
                      <td><StatusPill tone={state.tone}>{state.label}</StatusPill></td>
                      <td>{s.requested_engines.join(", ")}</td>
                      <td>{s.stats?.total ?? 0}</td>
                      <td>{when(s.finished_at)}</td>
                      <td><button onClick={() => navigate(`scans/${s.id}`)}>Open</button></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Async>
      </Card>
    </>
  );
}

export function ScanDetailScreen({ id }: { id: string }) {
  const scan = useAsync(() => api.scan(id), [id]);
  const engines = useAsync(() => api.scanEngines(id), [id]);
  const findings = useAsync(() => api.findings({ scan_id: id }), [id]);
  const queue = useAsync(() => api.queueHealth(), []);

  return (
    <Async loader={scan}>
      {(s: Scan) => {
        const state = SCAN_STATE[s.status] ?? {
          label: s.status, tone: "wait", meaning: "",
        };
        const waiting = s.status === "queued" || s.status === "running";
        return (
          <>
            <Card title={
              <>Scan <span className="mono">{s.id.slice(0, 8)}</span>{" "}
                <StatusPill tone={state.tone}>{state.label}</StatusPill></>
            } actions={<button onClick={() => scan.reload()}>Refresh</button>}>
              <p>{state.meaning}</p>
              <dl className="kv">
                <dt>Requested engines</dt><dd>{s.requested_engines.join(", ")}</dd>
                <dt>Started</dt><dd>{when(s.created_at)}</dd>
                <dt>Finished</dt><dd>{when(s.finished_at)}</dd>
                <dt>Trigger</dt><dd>{s.trigger}</dd>
              </dl>

              {waiting && queue.data && (
                <div className={queue.data.state === "stalled" ? "state state-blocked" : "notice"}>
                  <strong>
                    {queue.data.state === "stalled"
                      ? "This scan is waiting and nothing is executing"
                      : "This scan is waiting its turn"}
                  </strong>
                  <p>{queue.data.detail}</p>
                  {/* Never a fake progress bar. There is no progress to report. */}
                  <p className="muted">
                    No result has been produced. Guardian will not show findings for a scan that
                    has not run.
                  </p>
                </div>
              )}
            </Card>

            <Card title="What was actually checked">
              <Async
                loader={engines}
                empty={<p className="muted">
                  No engine has started yet, so nothing has been checked.
                </p>}
              >
                {(runs: EngineRun[]) => (
                  <table>
                    <thead>
                      <tr><th>Engine</th><th>Outcome</th><th>What it means</th></tr>
                    </thead>
                    <tbody>
                      {runs.map((r) => {
                        const tone = ENGINE_STATE[r.customer_state] ?? {
                          label: r.customer_state, tone: "wait",
                        };
                        return (
                          <tr key={r.engine}>
                            <td>{r.engine}</td>
                            <td><StatusPill tone={tone.tone}>{tone.label}</StatusPill></td>
                            <td>
                              {r.meaning}
                              {r.error && <div className="err">{r.error}</div>}
                              {r.missing.length > 0 && (
                                <div className="muted">Missing: {r.missing.join(", ")}</div>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </Async>
            </Card>

            <Card title="Findings">
              <Async
                loader={findings}
                empty={<UncheckedAwareEmpty engines={engines.data ?? []} scanStatus={s.status} />}
              >
                {(page) => (
                  <table>
                    <thead>
                      <tr><th>Severity</th><th>Risk</th><th>Finding</th><th>Status</th><th /></tr>
                    </thead>
                    <tbody>
                      {page.rows.map((f: Finding) => (
                        <tr key={f.id}>
                          <td><SeverityBadge severity={f.severity} /></td>
                          <td>{f.risk_score}</td>
                          <td>{f.title}</td>
                          <td>{f.status}</td>
                          <td>
                            <button onClick={() => navigate(`findings/${f.id}`)}>Open</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </Async>
            </Card>
          </>
        );
      }}
    </Async>
  );
}

/**
 * An empty findings list, captioned by what was actually checked.
 *
 * This component is the whole point of the scan screen. "0 findings" from a scan where three
 * engines failed is not a clean result, and a customer cannot be expected to work that out from a
 * separate table.
 */
function UncheckedAwareEmpty({ engines, scanStatus }:
  { engines: EngineRun[]; scanStatus: string }) {
  const unchecked = engines.filter((e) => e.customer_state === "not_checked");
  const inconclusive = engines.filter((e) => e.customer_state === "inconclusive");
  const checked = engines.filter((e) => e.customer_state === "checked");

  if (scanStatus === "queued" || scanStatus === "running") {
    return <EmptyState
      title="No findings yet"
      body="This scan has not finished. An empty list here means nothing has been reported so far,
            not that there is nothing to report."
    />;
  }

  if (unchecked.length || inconclusive.length) {
    return (
      <div className="state state-blocked" role="status">
        <h4>No findings were reported — but this scan is not a clean result</h4>
        <p>
          {checked.length} engine(s) ran and reported nothing.{" "}
          {unchecked.length > 0 && (
            <>{unchecked.length} did not run at all ({unchecked.map((e) => e.engine).join(", ")}).{" "}</>
          )}
          {inconclusive.length > 0 && (
            <>{inconclusive.length} ran with reduced coverage
              ({inconclusive.map((e) => e.engine).join(", ")}).{" "}</>
          )}
        </p>
        <p className="muted">
          What those engines would have found is unknown. Fix the cause above and scan again before
          treating this asset as clear.
        </p>
      </div>
    );
  }

  return <EmptyState
    title="No findings"
    body={`All ${checked.length} requested engine(s) ran and reported nothing. For what these
           engines cover, this asset is clean.`}
  />;
}
