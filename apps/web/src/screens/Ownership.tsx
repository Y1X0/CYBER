// Domain ownership: the machine-checked proof that active testing depends on.

import { useState } from "react";
import { Verification, api } from "../api";
import { Async, Card, EmptyState, StatusPill, useAsync, when } from "../ui";

const TONE: Record<string, string> = {
  verified: "ok", pending: "wait", failed: "bad", expired: "bad", revoked: "bad",
};

export function OwnershipScreen() {
  const loader = useAsync(() => api.verifications(), []);
  const customers = useAsync(() => api.customers(), []);
  const [domain, setDomain] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function issue(e: React.FormEvent) {
    e.preventDefault();
    const customerId = customers.data?.rows[0]?.id;
    if (!customerId) { setErr("No customer record to attach this to."); return; }
    setBusy(true);
    setErr("");
    try {
      await api.createVerification(customerId, domain, "dns_txt");
      setDomain("");
      loader.reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Domain ownership">
      <p className="muted">
        Publishing a DNS record proves you control a domain. Guardian will not connect to a running
        system on any weaker basis — a form you filled in is a claim, and a claim is not proof.
        Verifying a domain does not by itself authorize every kind of scan; you still choose what to
        authorize on the Authorization screen.
      </p>

      <form className="inline-form" onSubmit={issue}>
        <label>Domain
          <input value={domain} onChange={(e) => setDomain(e.target.value)}
                 placeholder="example.com" required />
        </label>
        {err && <p className="err" role="alert">{err}</p>}
        <button type="submit" disabled={busy}>{busy ? "Issuing…" : "Start verification"}</button>
      </form>

      <Async
        loader={loader}
        empty={<EmptyState
          title="No domains verified"
          body="Verify a domain to enable active network testing. Artifact scanning — code,
                containers, infrastructure templates — does not require this."
        />}
      >
        {(rows: Verification[]) => (
          <div>
            {rows.map((v) => (
              <div className="record" key={v.id}>
                <div className="record-head">
                  <strong className="mono">{v.domain}</strong>
                  <StatusPill tone={TONE[v.status] ?? "wait"}>{v.status}</StatusPill>
                  <span className="muted">
                    {v.status === "verified"
                      ? `verified ${when(v.verified_at)}`
                      : `expires ${when(v.expires_at)}`}
                  </span>
                  {v.status !== "verified" && <RecheckButton id={v.id} onDone={loader.reload} />}
                </div>

                {v.instructions && (
                  <div className="instructions">
                    <p>Publish this record, then re-check:</p>
                    <table>
                      <tbody>
                        <tr><th>Type</th><td className="mono">{v.instructions.record_type}</td></tr>
                        <tr><th>Name</th><td className="mono">{v.instructions.record_name}</td></tr>
                        <tr><th>Value</th><td className="mono">{v.instructions.record_value}</td></tr>
                      </tbody>
                    </table>
                    <p className="muted">{v.instructions.note}</p>
                  </div>
                )}

                {v.last_error && (
                  // The reason the check failed, verbatim. "Not verified" with no cause is the
                  // single most common support ticket a flow like this generates.
                  <p className="err">Last check: {v.last_error}</p>
                )}
                {v.status === "verified" && v.authorization_id && (
                  <p className="muted">
                    This proof issued an authorization for the domain and its subdomains. Review it
                    on the Authorization screen.
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </Async>
    </Card>
  );
}

function RecheckButton({ id, onDone }: { id: string; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  return (
    <>
      <button
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setErr("");
          try { await api.checkVerification(id); onDone(); }
          catch (e) { setErr((e as Error).message); }
          finally { setBusy(false); }
        }}
      >
        {busy ? "Checking…" : "Check now"}
      </button>
      {err && <span className="err">{err}</span>}
    </>
  );
}
