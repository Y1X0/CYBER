// Remediation: the work list, its clock, and the retest that closes it.
//
// The one thing a person cannot do here is mark something verified. A human sets `fixed`; only a
// scan that re-checks and does not re-report sets `verified`. That is deliberate and the screen
// says so, because otherwise it reads as a missing button.

import { useState } from "react";
import { RemediationItem, api } from "../api";
import { navigate } from "../router";
import { Async, Card, EmptyState, SeverityBadge, Stat, StatusPill, useAsync, when } from "../ui";

const HUMAN_STATUSES = ["open", "in_progress", "fixed", "wont_fix", "reopened"];

const TONE: Record<string, string> = {
  verified: "ok", fixed: "wait", open: "warn", in_progress: "wait",
  reopened: "bad", wont_fix: "muted",
};

export function RemediationScreen() {
  const items = useAsync(() => api.remediation(), []);
  const customers = useAsync(() => api.customers(), []);
  const sla = useAsync(() => api.remediationSla(), []);
  const me = useAsync(() => api.me(), []);
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

  const refresh = () => { items.reload(); sla.reload(); };

  return (
    <>
      {sla.error && (
        // Not silently absent: a missing panel reads as "nothing to report", and this one carries
        // the overdue count.
        <Card title="Against the clock">
          <p className="err" role="alert">
            The remediation clock could not be loaded: {sla.error.message}. Nothing below should be
            read as on time.
          </p>
        </Card>
      )}
      {sla.data && sla.data.total > 0 && (
        <Card title="Against the clock">
          <div className="stats">
            <Stat label="Tracked" value={sla.data.total} />
            <Stat label="Still open" value={sla.data.active} />
            <Stat label="Overdue" value={sla.data.overdue}
                  tone={sla.data.overdue ? "bad" : undefined} />
            <Stat label="Verified by a scan" value={sla.data.verified} tone="ok"
                  hint="Re-checked and not reported again" />
            <Stat label="Accepted" value={sla.data.accepted}
                  hint="Closed by a decision, not a fix" />
            <Stat label="On time" value={`${sla.data.on_time_rate}%`} />
          </div>
          <p className="muted">
            Due dates come from severity and exposure, not from a target anyone negotiated. An item
            counted as verified was re-checked by a scan; an accepted one was closed by a person
            with a stated reason.
          </p>
        </Card>
      )}

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
                <tr><th>Severity</th><th>Finding</th><th>Status</th><th>Owner</th><th>Due</th>
                    <th>Actions</th></tr>
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
                    <td>
                      <Owner item={item} meId={me.data?.id ?? null} onDone={refresh} />
                    </td>
                    <td className={item.overdue ? "warn-text" : ""}>
                      {when(item.due_at)}{item.overdue ? " · overdue" : ""}
                      <DueDate item={item} onDone={refresh} />
                    </td>
                    <td className="row-actions">
                      <ItemActions item={item} onDone={refresh} />
                      <TicketButton id={item.id} />
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

/**
 * Ownership, limited to what the platform can honestly offer.
 *
 * There is no directory endpoint, so there is no list of colleagues to choose from — and inventing
 * one would mean guessing at names. What a person can do is take an item or put it back down, which
 * is the part of "assign" that answers "who is dealing with this?".
 */
function Owner({ item, meId, onDone }:
  { item: RemediationItem; meId: string | null; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const mine = !!meId && item.assignee_id === meId;

  async function set(assignee: string | null) {
    setBusy(true); setErr("");
    try { await api.updateRemediation(item.id, { assignee_id: assignee }); onDone(); }
    catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  }

  return (
    <>
      {item.assignee_id
        ? <span>{mine ? "you" : "another member"}</span>
        : <span className="muted">nobody</span>}
      <button disabled={busy || !meId} onClick={() => set(mine ? null : meId)}>
        {mine ? "Release" : "Take"}
      </button>
      {err && <div className="err">{err}</div>}
    </>
  );
}

function DueDate({ item, onDone }: { item: RemediationItem; onDone: () => void }) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState((item.due_at ?? "").slice(0, 10));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  if (!editing) {
    return <button className="link" onClick={() => setEditing(true)}>change</button>;
  }
  return (
    <div>
      <input type="date" value={value} onChange={(e) => setValue(e.target.value)}
             aria-label="Due date" />
      <button disabled={busy || !value} onClick={async () => {
        setBusy(true); setErr("");
        try {
          await api.updateRemediation(item.id, { due_at: `${value}T00:00:00Z` });
          setEditing(false);
          onDone();
        } catch (e) { setErr((e as Error).message); }
        finally { setBusy(false); }
      }}>{busy ? "Saving…" : "Save"}</button>
      <button onClick={() => setEditing(false)}>Cancel</button>
      {err && <div className="err">{err}</div>}
    </div>
  );
}

/**
 * The ticket body, rendered for the customer's own tracker.
 *
 * Guardian files nothing itself and holds no ticketing credential. Showing the payload is the
 * honest version of an integration: the customer's automation posts it under their own identity,
 * and the evidence in it is scrubbed on the way out because it lands in a system with a different
 * audience.
 */
function TicketButton({ id }: { id: string }) {
  const [body, setBody] = useState<{ title: string; body: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  return (
    <>
      <button disabled={busy} onClick={async () => {
        setBusy(true); setErr("");
        try { const t = await api.remediationTicket(id); setBody({ title: t.title, body: t.body }); }
        catch (e) { setErr((e as Error).message); }
        finally { setBusy(false); }
      }}>{busy ? "…" : "Ticket text"}</button>
      {err && <span className="err">{err}</span>}
      {body && (
        <div className="popover">
          <p><strong>{body.title}</strong></p>
          <textarea readOnly rows={10} value={body.body} aria-label="Ticket body" />
          <p className="muted">
            Paste this into your tracker. Guardian does not file it — evidence has been scrubbed
            for a system with a different audience.
          </p>
          <button onClick={() => setBody(null)}>Close</button>
        </div>
      )}
    </>
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
