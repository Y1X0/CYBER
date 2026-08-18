// Remediation: the work list, its clock, and the retest that closes it.
//
// The one thing a person cannot do here is mark something verified. A human sets `fixed`; only a
// scan that re-checks and does not re-report sets `verified`. That is deliberate and the screen
// says so, because otherwise it reads as a missing button.

import { useState } from "react";
import { RemediationItem, api } from "../api";
import { navigate } from "../router";
import { Async, Card, EmptyState, SeverityBadge, StatusPill, useAsync, when } from "../ui";

const HUMAN_STATUSES = ["open", "in_progress", "fixed", "wont_fix", "reopened"];

const TONE: Record<string, string> = {
  verified: "ok", fixed: "wait", open: "warn", in_progress: "wait",
  reopened: "bad", wont_fix: "muted",
};

export function RemediationScreen() {
  const items = useAsync(() => api.remediation(), []);
  const customers = useAsync(() => api.customers(), []);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function openWork() {
    const customerId = customers.data?.rows[0]?.id;
    if (!customerId) { setErr("No customer record found."); return; }
    setBusy(true); setErr(""); setMsg("");
    try {
      const r = await api.openRemediation(customerId);
      // The API answers 200 with a reason when it created nothing. Showing that reason is the
      // difference between "it worked" and "nothing happened and here is why".
      setMsg(r.opened > 0
        ? `Opened ${r.opened} item(s).`
        : (r.reason ?? "Nothing to open."));
      items.reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Remediation" actions={
      <button onClick={openWork} disabled={busy}>
        {busy ? "Opening…" : "Open work for open findings"}
      </button>
    }>
      {msg && <p className="muted">{msg}</p>}
      {err && <p className="err" role="alert">{err}</p>}
      <p className="muted">
        A person can mark an item fixed. Only a scan that re-checks the finding and does not report
        it again marks it verified — a fix certified by the person under deadline is a to-do list,
        not evidence.
      </p>

      <Async
        loader={items}
        empty={<EmptyState
          title="No remediation work"
          body="Nothing is being tracked yet. Open work for your current open findings, and each
                item gets an owner and a due date based on severity and exposure."
        />}
      >
        {(rows: RemediationItem[]) => (
          <table>
            <thead>
              <tr><th>Severity</th><th>Finding</th><th>Status</th><th>Due</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.id}>
                  <td><SeverityBadge severity={item.severity} /></td>
                  <td>
                    <button className="link"
                            onClick={() => navigate(`findings/${item.finding_id}`)}>
                      {item.finding_title || item.finding_id.slice(0, 8)}
                    </button>
                  </td>
                  <td>
                    <StatusPill tone={TONE[item.status] ?? "wait"}>{item.status}</StatusPill>
                    {item.verified_by_scan_id && (
                      <div className="muted">verified by a scan</div>
                    )}
                  </td>
                  <td className={item.overdue ? "warn-text" : ""}>
                    {when(item.due_at)}{item.overdue ? " · overdue" : ""}
                  </td>
                  <td className="row-actions">
                    <ItemActions item={item} onDone={items.reload} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Async>
    </Card>
  );
}

function ItemActions({ item, onDone }: { item: RemediationItem; onDone: () => void }) {
  const [status, setStatus] = useState(item.status);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");

  return (
    <>
      <select value={status} onChange={(e) => setStatus(e.target.value)}>
        {HUMAN_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
      {status === "wont_fix" && (
        <input value={note} onChange={(e) => setNote(e.target.value)}
               placeholder="Why (required)" />
      )}
      <button
        disabled={busy || status === item.status || (status === "wont_fix" && !note.trim())}
        onClick={async () => {
          setBusy(true); setErr("");
          try {
            await api.updateRemediation(item.id, { status, justification: note });
            onDone();
          } catch (e) { setErr((e as Error).message); }
          finally { setBusy(false); }
        }}
      >{busy ? "Saving…" : "Update"}</button>
      <RetestLink findingId={item.finding_id} onDone={onDone} />
      {err && <span className="err">{err}</span>}
    </>
  );
}

function RetestLink({ findingId, onDone }: { findingId: string; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  return (
    <>
      <button disabled={busy} onClick={async () => {
        setBusy(true); setErr(""); setMsg("");
        try {
          await api.retest(findingId);
          setMsg("Retest queued");
          onDone();
        } catch (e) { setErr((e as Error).message); }
        finally { setBusy(false); }
      }}>{busy ? "…" : "Retest"}</button>
      {msg && <span className="muted">{msg}</span>}
      {err && <span className="err">{err}</span>}
    </>
  );
}
