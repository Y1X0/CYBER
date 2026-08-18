// Outbound webhooks: where Guardian tells you something happened, and proof it tried.

import { useState } from "react";
import { WebhookEndpoint, api } from "../api";
import { Async, Card, EmptyState, StatusPill, useAsync, when } from "../ui";

export function NotificationsScreen() {
  const endpoints = useAsync(() => api.webhooks(), []);
  const events = useAsync(() => api.webhookEvents(), []);
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [secret, setSecret] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      const created = await api.createWebhook(url, selected, description);
      // Shown once, and said plainly. There is no endpoint that returns it again.
      setSecret(created.secret ?? null);
      setUrl(""); setDescription(""); setSelected([]);
      endpoints.reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Card title="Add a notification endpoint">
        <form className="inline-form" onSubmit={create}>
          <label>URL
            <input value={url} onChange={(e) => setUrl(e.target.value)} required
                   placeholder="https://hooks.example.com/guardian" />
            <small>https only. Guardian will not send to a loopback or credential-bearing URL.</small>
          </label>
          <label>Description
            <input value={description} onChange={(e) => setDescription(e.target.value)}
                   placeholder="Security channel" />
          </label>
          <fieldset>
            <legend>Events</legend>
            <Async loader={events}>
              {(e) => (
                <>
                  {e.events.map((name) => (
                    <label key={name} className="check">
                      <input type="checkbox" checked={selected.includes(name)}
                             onChange={(ev) => setSelected(ev.target.checked
                               ? [...selected, name]
                               : selected.filter((s) => s !== name))} />
                      {name}
                    </label>
                  ))}
                  <p className="muted">{e.note}</p>
                </>
              )}
            </Async>
          </fieldset>
          {err && <p className="err" role="alert">{err}</p>}
          <button type="submit" disabled={busy || selected.length === 0}>
            {busy ? "Saving…" : "Add endpoint"}
          </button>
        </form>

        {secret && (
          <div className="notice">
            <strong>Copy this signing secret now.</strong>
            <p className="mono">{secret}</p>
            <p>
              It signs every delivery and Guardian will not show it again. Verify the
              <code> X-Guardian-Signature</code> header over <code>&lt;timestamp&gt;.&lt;body&gt;</code>
              and reject anything older than five minutes — a signature alone only proves the
              payload came from Guardian at some point.
            </p>
            <button onClick={() => setSecret(null)}>I have stored it</button>
          </div>
        )}
      </Card>

      <Card title="Endpoints">
        <Async
          loader={endpoints}
          empty={<EmptyState
            title="No endpoints"
            body="Guardian will not notify anyone until you add somewhere to send to. Scans still
                  run and findings are still recorded — you just have to come and look."
          />}
        >
          {(page) => (
            <div>
              {page.rows.map((e: WebhookEndpoint) => (
                <EndpointRow key={e.id} endpoint={e} onChange={endpoints.reload} />
              ))}
            </div>
          )}
        </Async>
      </Card>
    </>
  );
}

function EndpointRow({ endpoint, onChange }:
  { endpoint: WebhookEndpoint; onChange: () => void }) {
  const [showing, setShowing] = useState(false);
  const deliveries = useAsync(
    () => showing ? api.webhookDeliveries(endpoint.id) : Promise.resolve([]), [showing]);

  return (
    <div className="record">
      <div className="record-head">
        <strong className="mono">{endpoint.url}</strong>
        <StatusPill tone={endpoint.enabled ? "ok" : "bad"}>
          {endpoint.enabled ? "enabled" : "disabled"}
        </StatusPill>
        <span className="muted">{endpoint.events.join(", ")}</span>
        <button onClick={() => setShowing((v) => !v)}>
          {showing ? "Hide deliveries" : "Deliveries"}
        </button>
        <button onClick={async () => { await api.deleteWebhook(endpoint.id); onChange(); }}>
          Remove
        </button>
      </div>
      {endpoint.disabled_reason && <p className="err">{endpoint.disabled_reason}</p>}
      {endpoint.consecutive_failures > 0 && (
        <p className="warn-text">
          {endpoint.consecutive_failures} consecutive failure(s). Last success:{" "}
          {when(endpoint.last_success_at)}
        </p>
      )}
      {showing && (
        <Async loader={deliveries} empty={<p className="muted">No deliveries yet.</p>}>
          {(rows) => (
            <table>
              <thead>
                <tr><th>Event</th><th>Status</th><th>Attempts</th><th>Response</th>
                    <th>Next attempt</th></tr>
              </thead>
              <tbody>
                {rows.map((d) => (
                  <tr key={d.id}>
                    <td>{d.event}</td>
                    <td>{d.status}</td>
                    <td>{d.attempts}</td>
                    <td>
                      {d.response_status === 0 ? "no response" : d.response_status}
                      {d.error && <div className="err">{d.error}</div>}
                    </td>
                    <td>{when(d.next_attempt_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Async>
      )}
    </div>
  );
}
