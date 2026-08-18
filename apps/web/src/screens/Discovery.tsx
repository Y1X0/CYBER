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
    </>
  );
}
