// Discovery: find what else is out there, from a domain you have named.

import { useState } from "react";
import { api } from "../api";
import { Async, Card, EmptyState, StatusPill, useAsync, when } from "../ui";

const TONE: Record<string, string> = {
  completed: "ok", running: "wait", queued: "wait", failed: "bad", partial: "warn",
};

export function DiscoveryScreen() {
  const runs = useAsync(() => api.discoveryRuns(), []);
  const customers = useAsync(() => api.customers(), []);
  const queue = useAsync(() => api.queueHealth(), []);
  const services = useAsync(() => api.services(), []);
  const [domains, setDomains] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  async function start(e: React.FormEvent) {
    e.preventDefault();
    const customerId = customers.data?.rows[0]?.id;
    if (!customerId) { setErr("No customer record found."); return; }
    setBusy(true); setErr(""); setMsg("");
    try {
      await api.startDiscovery(
        customerId, domains.split(",").map((d) => d.trim()).filter(Boolean));
      setMsg("Discovery queued. Results appear below when it runs.");
      setDomains("");
      runs.reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Card title="Discover assets">
        <p className="muted">
          Passive discovery only: public DNS records for the domains you name. Guardian does not
          probe hosts here, and nothing found by discovery is scanned until you add it as an asset
          and authorize it.
        </p>
        <form className="inline-form" onSubmit={start}>
          <label>Domains (comma separated)
            <input value={domains} onChange={(e) => setDomains(e.target.value)}
                   placeholder="example.com" required />
          </label>
          {err && <p className="err" role="alert">{err}</p>}
          {msg && <p className="muted">{msg}</p>}
          <button type="submit" disabled={busy}>{busy ? "Starting…" : "Start discovery"}</button>
        </form>
        {queue.data?.state === "stalled" && (
          <div className="state state-blocked">
            <h4>Discovery will queue but not run</h4>
            <p>{queue.data.detail}</p>
          </div>
        )}
      </Card>

      <Card title="Discovery runs">
        <Async
          loader={runs}
          empty={<EmptyState title="No discovery runs"
                             body="Start one above to map what is exposed for a domain." />}
        >
          {(page) => (
            <table>
              <thead><tr><th>Started</th><th>Status</th><th>Result</th></tr></thead>
              <tbody>
                {page.rows.map((r) => (
                  <tr key={r.id}>
                    <td>{when(r.created_at)}</td>
                    <td><StatusPill tone={TONE[r.status] ?? "wait"}>{r.status}</StatusPill></td>
                    <td className="muted">
                      {r.stats && Object.keys(r.stats as object).length > 0
                        ? JSON.stringify(r.stats)
                        : (r.status === "queued" ? "not started" : "—")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Async>
      </Card>

      <Card title="Exposed services (open ports)">
        <p className="muted">
          Open, internet-reachable ports discovery has observed, worst exposure first. A port that
          is closed or filtered is not listed — this is the honest "what is open" view. A{" "}
          <StatusPill tone="bad">shadow</StatusPill> service is live but was never declared: the
          highest-value exposure to look at first.
        </p>
        <Async
          loader={services}
          empty={<EmptyState title="No exposed services recorded"
                             body="Active service discovery has not run, or nothing was found open."
          />}
        >
          {(data) => data.services.length === 0 ? (
            <p className="muted">No open services have been observed.</p>
          ) : (
            <table>
              <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Exposure</th>
                  <th>State</th><th>Last seen</th></tr></thead>
              <tbody>
                {data.services.map((s) => (
                  <tr key={s.id}>
                    <td className="mono">{s.host}</td>
                    <td className="mono">{s.port ?? "—"}</td>
                    <td>
                      {[s.product, s.service].filter(Boolean).join(" · ") || "—"}
                      {s.sensitive && <> <StatusPill tone="bad">{s.sensitive}</StatusPill></>}
                    </td>
                    <td>
                      <StatusPill tone={s.exposure_score >= 70 ? "bad"
                        : s.exposure_score >= 40 ? "warn" : "ok"}>{s.exposure_score}</StatusPill>
                    </td>
                    <td>{s.state === "shadow"
                      ? <StatusPill tone="bad">shadow</StatusPill>
                      : <span className="muted">{s.state}</span>}</td>
                    <td className="muted">{when(s.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Async>
      </Card>
    </>
  );
}
