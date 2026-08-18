// "What am I authorizing Guardian to scan?" — answered in one place, with the state, the scope,
// the responsible identity and the expiry of every grant.

import { useState } from "react";
import { Authorization, api } from "../api";
import { Async, Card, EmptyState, StatusPill, useAsync, when } from "../ui";

const STATE_TONE: Record<string, string> = {
  active: "ok", pending: "wait", expired: "bad", revoked: "bad",
};

export function AuthorizationScreen() {
  const loader = useAsync(() => api.authorizations(), []);
  const methods = useAsync(() => api.authorizationMethods(), []);
  const customers = useAsync(() => api.customers(), []);
  const [open, setOpen] = useState(false);

  return (
    <>
      <Card title="What Guardian may do">
        <Async loader={methods}>
          {(m) => (
            <>
              <p className="muted">{m.note}</p>
              <div className="grid-2">
                {m.methods.map((method) => (
                  <div className="record" key={method.method}>
                    <div className="record-head">
                      <strong>{method.label}</strong>
                      <StatusPill tone={method.permits_network ? "warn" : "ok"}>
                        {method.permits_network ? "touches your systems" : "artifacts only"}
                      </StatusPill>
                    </div>
                    <p>{method.summary}</p>
                    <p className="muted">Requires: {method.requires}</p>
                  </div>
                ))}
              </div>
            </>
          )}
        </Async>
      </Card>

      <Card title="Authorizations" actions={
        <button onClick={() => setOpen((v) => !v)}>{open ? "Cancel" : "Record authorization"}</button>
      }>
        {open && customers.data && (
          <NewAuthorization
            customers={customers.data.rows.map((c) => ({ id: c.id, name: c.name }))}
            onDone={() => { setOpen(false); loader.reload(); }}
          />
        )}
        <Async
          loader={loader}
          empty={<EmptyState
            title="Nothing is authorized"
            body="Guardian will not scan anything until you say what it may scan. Artifact
                  scanning needs your written consent; network testing additionally needs a
                  verified domain."
            action={<button onClick={() => setOpen(true)}>Record an authorization</button>}
          />}
        >
          {(page) => (
            <table>
              <thead>
                <tr>
                  <th>Scope</th><th>Permits</th><th>Targets</th><th>State</th>
                  <th>Valid until</th><th>Authorized by</th><th />
                </tr>
              </thead>
              <tbody>
                {page.rows.map((a: Authorization) => (
                  <tr key={a.id}>
                    <td>{a.scope}<div className="muted">{a.method}</div></td>
                    <td>
                      {/* Never "authorized ✓". The two planes are different promises. */}
                      {a.permits_network
                        ? <StatusPill tone="warn">network + artifacts</StatusPill>
                        : <StatusPill tone="ok">artifacts only</StatusPill>}
                    </td>
                    <td className="mono">
                      {a.targets.length
                        ? a.targets.map((t) => t.value).join(", ")
                        : (a.asset_id ? "one asset" : "—")}
                    </td>
                    <td><StatusPill tone={STATE_TONE[a.state] ?? "wait"}>{a.state}</StatusPill></td>
                    <td>{when(a.valid_until)}</td>
                    <td>{a.authorized_by}</td>
                    <td>
                      {a.state === "active" && (
                        <RevokeButton id={a.id} onDone={loader.reload} />
                      )}
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

function NewAuthorization({ customers, onDone }:
  { customers: { id: string; name: string }[]; onDone: () => void }) {
  const [form, setForm] = useState({
    customer_id: customers[0]?.id ?? "", method: "written_consent", scope: "",
    domains: "", validity_days: 90, reference: "",
  });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.createAuthorization({
        customer_id: form.customer_id,
        method: form.method,
        scope: form.scope,
        domains: form.domains.split(",").map((d) => d.trim()).filter(Boolean),
        validity_days: Number(form.validity_days),
        reference: form.reference,
      });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const network = form.method === "active_recon";
  return (
    <form className="inline-form" onSubmit={submit}>
      <label>Customer
        <select value={form.customer_id}
                onChange={(e) => setForm({ ...form, customer_id: e.target.value })}>
          {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </label>
      <label>What is being authorized
        <select value={form.method} onChange={(e) => setForm({ ...form, method: e.target.value })}>
          <option value="written_consent">Artifact scanning (code, images, templates)</option>
          <option value="active_recon">Active network testing</option>
        </select>
      </label>
      <label>Scope description
        <input value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })}
               required minLength={3} placeholder="Production estate, Q3 assessment" />
      </label>
      <label>Domains (comma separated)
        <input value={form.domains} onChange={(e) => setForm({ ...form, domains: e.target.value })}
               placeholder="example.com, api.example.com" />
      </label>
      <label>Valid for (days)
        <input type="number" min={1} max={365} value={form.validity_days}
               onChange={(e) => setForm({ ...form, validity_days: Number(e.target.value) })} />
      </label>
      <label>Reference
        <input value={form.reference}
               onChange={(e) => setForm({ ...form, reference: e.target.value })}
               placeholder="Signed engagement letter 2026-04-01" />
      </label>

      {network && (
        <div className="notice">
          <strong>This permits Guardian to connect to your running systems.</strong>
          <p>
            It is accepted only for domains you have already verified. If a domain here is not
            verified, this will be refused and will tell you which one.
          </p>
        </div>
      )}
      <label className="check">
        <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
        I am authorized to grant this on behalf of the organization that owns these systems.
      </label>

      {err && <p className="err" role="alert">{err}</p>}
      <button type="submit" disabled={busy || !confirmed}>
        {busy ? "Recording…" : "Record authorization"}
      </button>
    </form>
  );
}

function RevokeButton({ id, onDone }: { id: string; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  return (
    <>
      <button disabled={busy} onClick={async () => {
        setBusy(true);
        setErr("");
        try { await api.revokeAuthorization(id); onDone(); }
        catch (e) { setErr((e as Error).message); }
        finally { setBusy(false); }
      }}>{busy ? "Revoking…" : "Revoke"}</button>
      {err && <span className="err">{err}</span>}
    </>
  );
}
