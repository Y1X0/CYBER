// The organization: who you are, what business units you assess, and what Guardian may currently
// do on your behalf.
//
// The last part is the reason this screen exists rather than being a settings page. "What is
// Guardian allowed to do to us right now?" is a question a customer should be able to answer in one
// place, and the honest answer has two independent halves — domains you have proved you control,
// and authorizations you have granted. Neither implies the other, so both are counted separately.

import { useState } from "react";
import { Authorization, Customer, Verification, api } from "../api";
import { navigate } from "../router";
import { Async, Card, EmptyState, Stat, StatusPill, useAsync, when } from "../ui";

const CRITICALITY = ["low", "medium", "high", "critical"];

export function OrganizationScreen() {
  const me = useAsync(() => api.me(), []);
  const customers = useAsync(() => api.customers(), []);
  const assets = useAsync(() => api.assets(), []);
  const verifications = useAsync(() => api.verifications(), []);
  const authorizations = useAsync(() => api.authorizations(), []);
  const [adding, setAdding] = useState(false);

  const verified = (verifications.data ?? []).filter(
    (v: Verification) => v.status === "verified").length;
  const active = (authorizations.data?.rows ?? []).filter(
    (a: Authorization) => a.state === "active");

  return (
    <>
      <Card title="Your organization">
        <Async loader={me}>
          {(who) => (
            <dl className="kv">
              <dt>Signed in as</dt><dd>{who.email}{who.name ? ` (${who.name})` : ""}</dd>
              <dt>Organization</dt><dd className="mono">{who.tenant_id}</dd>
              <dt>Role</dt><dd>{who.staff_role ?? (who.portal_customer_id ? "portal" : "owner")}</dd>
            </dl>
          )}
        </Async>
      </Card>

      <Card title="What Guardian may currently do">
        <div className="stats">
          <Stat label="Business units" value={customers.data?.rows.length ?? "—"} />
          <Stat label="Assets" value={assets.data?.rows.length ?? "—"} />
          <Stat label="Verified domains" value={verifications.data ? verified : "—"}
                hint="Domains you have proved you control" />
          <Stat label="Active authorizations" value={authorizations.data ? active.length : "—"}
                hint="Grants you have recorded" />
        </div>
        {/* Stated rather than left to be inferred from two numbers sitting next to each other. */}
        <p className="muted">
          These two are separate on purpose. Verifying a domain proves you control it and
          authorizes nothing on its own; an authorization records what you asked for, and only an
          authorization backed by a verified domain permits Guardian to connect to a running
          system. With no active authorization Guardian scans nothing at all.
        </p>
        <div className="row-actions">
          <button onClick={() => navigate("ownership")}>Verify a domain</button>
          <button onClick={() => navigate("authorization")}>Record an authorization</button>
        </div>
        {authorizations.data && active.length === 0 && (
          <p className="warn-text">
            Nothing is authorized. Assets can be added, but no scan will run until you authorize
            one.
          </p>
        )}
      </Card>

      <Card title="Business units" actions={
        <button onClick={() => setAdding((v) => !v)}>{adding ? "Cancel" : "Add business unit"}</button>
      }>
        <p className="muted">
          Assets, scans and reports hang off a business unit. One was created with your
          organization; add more if you assess several estates separately.
        </p>
        {adding && (
          <NewCustomer onDone={() => { setAdding(false); customers.reload(); }} />
        )}
        <Async
          loader={customers}
          empty={<EmptyState
            title="No business units"
            body="Add one to attach assets to."
            action={<button onClick={() => setAdding(true)}>Add business unit</button>}
          />}
        >
          {(page) => (
            <table>
              <thead><tr><th>Name</th><th>Criticality</th><th>Assets</th></tr></thead>
              <tbody>
                {page.rows.map((c: Customer) => (
                  <tr key={c.id}>
                    <td>{c.name}</td>
                    <td><StatusPill tone={c.criticality === "critical" ? "bad"
                      : c.criticality === "high" ? "warn" : "ok"}>{c.criticality}</StatusPill></td>
                    <td>
                      {assets.data
                        ? assets.data.rows.filter((a) => a.customer_id === c.id).length
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Async>
      </Card>

      <Card title="Domains">
        <Async
          loader={verifications}
          empty={<EmptyState
            title="No domains"
            body="Active network testing requires a verified domain. Artifact scanning does not."
            action={<button onClick={() => navigate("ownership")}>Verify a domain</button>}
          />}
        >
          {(rows: Verification[]) => (
            <table>
              <thead><tr><th>Domain</th><th>State</th><th>Verified</th></tr></thead>
              <tbody>
                {rows.map((v) => (
                  <tr key={v.id}>
                    <td className="mono">{v.domain}</td>
                    <td><StatusPill tone={v.status === "verified" ? "ok" : "wait"}>
                      {v.status}
                    </StatusPill></td>
                    <td>{when(v.verified_at)}</td>
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

function NewCustomer({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [criticality, setCriticality] = useState("high");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  return (
    <form className="inline-form" onSubmit={async (e) => {
      e.preventDefault();
      setBusy(true); setErr("");
      try { await api.createCustomer(name, criticality); setName(""); onDone(); }
      catch (e) { setErr((e as Error).message); }
      finally { setBusy(false); }
    }}>
      <label>Name
        <input value={name} onChange={(e) => setName(e.target.value)} required
               placeholder="Acme Production" />
      </label>
      <label>Criticality
        <select value={criticality} onChange={(e) => setCriticality(e.target.value)}>
          {CRITICALITY.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <small>Feeds the deterministic risk score and the remediation deadline.</small>
      </label>
      {err && <p className="err" role="alert">{err}</p>}
      <button type="submit" disabled={busy}>{busy ? "Adding…" : "Add business unit"}</button>
    </form>
  );
}
