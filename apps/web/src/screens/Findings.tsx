// The findings workbench and the finding dossier.
//
// Everything the API knows about a finding is on the detail screen — evidence, provenance, the
// risk rationale, exploit intelligence, correlation, verification history and remediation. A
// customer should never need to call the API to understand why Guardian thinks something matters.

import { useState } from "react";
import { Finding, FindingDossier, api } from "../api";
import { navigate } from "../router";
import {
  Async, Card, EmptyState, SEVERITIES, SeverityBadge, StatusPill, useAsync, when,
} from "../ui";

const STATUSES = ["open", "triaged", "confirmed", "resolved", "false_positive", "accepted_risk"];

export function FindingsScreen() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [sort, setSort] = useState("risk");

  const params: Record<string, string> = {};
  if (severity) params.severity = severity;
  if (status) params.status = status;

  const loader = useAsync(() => api.findings(params), [severity, status]);
  const summary = useAsync(() => api.findingSummary(), []);

  return (
    <>
      <Card title="Findings">
        <div className="filters">
          <label>Severity
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label>Status
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">All</option>
              {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label>Sort
            <select value={sort} onChange={(e) => setSort(e.target.value)}>
              <option value="risk">Risk (highest first)</option>
              <option value="recent">Most recent</option>
              <option value="title">Title</option>
            </select>
          </label>
        </div>

        {summary.data && (
          <p className="muted">
            {summary.data.total} finding(s) · {summary.data.exploitable} with known exploit
            activity · {summary.data.correlated} correlated · {summary.data.unverified} never
            re-checked
          </p>
        )}

        <Async
          loader={loader}
          empty={<EmptyState
            title="No findings match"
            body={severity || status
              ? "No finding matches these filters. Clear them to see everything."
              : "Nothing has been reported. If no scan has completed, that is not the same as " +
                "being clean — check your scan history."}
            action={<button onClick={() => navigate("scans")}>Scan history</button>}
          />}
        >
          {(page) => {
            const rows = [...page.rows].sort((a, b) => {
              if (sort === "risk") return b.risk_score - a.risk_score;
              if (sort === "title") return a.title.localeCompare(b.title);
              return (b.created_at ?? "").localeCompare(a.created_at ?? "");
            });
            return (
              <>
                <table>
                  <thead>
                    <tr><th>Severity</th><th>Risk</th><th>Finding</th><th>Status</th>
                        <th>Standards</th><th /></tr>
                  </thead>
                  <tbody>
                    {rows.map((f: Finding) => (
                      <tr key={f.id}>
                        <td><SeverityBadge severity={f.severity} /></td>
                        <td>{f.risk_score}</td>
                        <td>{f.title}</td>
                        <td>{f.status}</td>
                        <td className="muted">
                          {[f.cwe_id, f.owasp_ref].filter(Boolean).join(" · ") || "—"}
                        </td>
                        <td>
                          <button onClick={() => navigate(`findings/${f.id}`)}>Open</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {page.hasMore && (
                  <p className="muted">
                    More findings exist than are shown. Narrow the filters to see them.
                  </p>
                )}
              </>
            );
          }}
        </Async>
      </Card>
    </>
  );
}

export function FindingDetailScreen({ id }: { id: string }) {
  const loader = useAsync(() => api.finding(id), [id]);

  return (
    <Async loader={loader}>
      {(d: FindingDossier) => (
        <>
          <Card title={
            <><SeverityBadge severity={d.finding.severity} /> {d.finding.title}</>
          } actions={<button onClick={() => navigate("findings")}>Back to findings</button>}>
            <dl className="kv">
              <dt>Risk score</dt>
              <dd>{d.finding.risk_score}/100 — computed by the deterministic risk engine</dd>
              <dt>Status</dt><dd>{d.finding.status}</dd>
              <dt>Asset</dt>
              <dd>
                {d.asset.name
                  ? <>{d.asset.name} <span className="muted">({d.asset.kind}, {d.asset.exposure})
                      </span><div className="mono">{d.asset.identifier}</div></>
                  : "—"}
              </dd>
              <dt>Found by</dt>
              <dd>{d.engine ?? "—"}{d.scan.id && <> in scan{" "}
                <button className="link" onClick={() => navigate(`scans/${d.scan.id}`)}>
                  {String(d.scan.id).slice(0, 8)}
                </button></>}</dd>
              <dt>Standards</dt>
              <dd>{[d.finding.cwe_id, d.finding.owasp_ref].filter(Boolean).join(" · ") || "—"}</dd>
            </dl>
          </Card>

          <div className="grid-2">
            <Card title="Why this score">
              {d.risk_rationale.length === 0
                ? <p className="muted">No rationale was recorded for this finding.</p>
                : <ul>{d.risk_rationale.map((r, i) => <li key={i}>{r}</li>)}</ul>}
              <dl className="kv">
                <dt>Known exploited</dt>
                <dd>{d.exploit.kev ? "yes — in CISA KEV" : "not listed"}</dd>
                <dt>Exploit maturity</dt><dd>{d.exploit.maturity ?? "unknown"}</dd>
                <dt>Ransomware linked</dt><dd>{d.exploit.ransomware ? "yes" : "no"}</dd>
                <dt>EPSS</dt>
                <dd>{d.exploit.epss !== null ? d.exploit.epss.toFixed(4) : "—"}</dd>
                <dt>CVSS base</dt>
                <dd>{d.exploit.cvss_base !== null ? d.exploit.cvss_base : "—"}</dd>
              </dl>
            </Card>

            <Card title="Evidence">
              {Object.keys(d.finding.evidence ?? {}).length === 0 ? (
                <p className="muted">No evidence was recorded with this finding.</p>
              ) : (
                <table>
                  <tbody>
                    {Object.entries(d.finding.evidence).map(([k, v]) => (
                      <tr key={k}>
                        <th>{k}</th>
                        <td className="mono">{typeof v === "string" ? v : JSON.stringify(v)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <p className="muted">
                Credentials are masked before they leave the platform, so an excerpt may be partly
                redacted. That is deliberate.
              </p>
            </Card>
          </div>

          {d.correlation && (
            <Card title="This is one issue seen several ways">
              <p>
                {d.correlation.member_count} finding(s) describe the same underlying problem
                ({d.correlation.rule}).
              </p>
              {d.correlation.rationale.map((r, i) => <p key={i} className="muted">{r}</p>)}
              {d.related.length > 0 && (
                <ul>
                  {d.related.map((r) => (
                    <li key={r.id}>
                      <button className="link" onClick={() => navigate(`findings/${r.id}`)}>
                        {r.title}
                      </button>{" "}
                      <SeverityBadge severity={r.severity} />
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          )}

          <Card title="Verification history" actions={<RetestButton id={id} onDone={loader.reload} />}>
            {d.verifications.length === 0 ? (
              <p className="muted">
                This finding has never been re-checked. It has not been disproved — nobody has
                looked again.
              </p>
            ) : (
              <table>
                <thead><tr><th>When</th><th>Verdict</th><th>Engine</th><th>Reasoning</th></tr></thead>
                <tbody>
                  {d.verifications.map((v, i) => (
                    <tr key={i}>
                      <td>{when(v.checked_at)}</td>
                      <td>
                        <StatusPill tone={
                          v.verdict === "resolved" ? "ok"
                            : v.verdict === "still_present" ? "bad" : "warn"
                        }>{v.verdict}</StatusPill>
                      </td>
                      <td>{v.engine ?? "—"}</td>
                      <td className="muted">{v.rationale}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          <Card title="Triage">
            <Triage id={id} current={d.finding.status} onDone={loader.reload} />
          </Card>

          <Card title="History">
            {d.timeline.length === 0 ? <p className="muted">No status changes recorded.</p> : (
              <ul>
                {d.timeline.map((t, i) => (
                  <li key={i}>
                    {when(t.at)} — {t.from_status ?? "new"} → {t.to_status}
                    {t.note && <> · <span className="muted">{t.note}</span></>}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}
    </Async>
  );
}

function RetestButton({ id, onDone }: { id: string; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  return (
    <>
      <button disabled={busy} onClick={async () => {
        setBusy(true); setErr(""); setMsg("");
        try {
          const r = await api.retest(id);
          setMsg(`Retest queued — the ${r.engine} engine will re-check this. The verdict appears
                  here when that scan completes.`);
          onDone();
        } catch (e) { setErr((e as Error).message); }
        finally { setBusy(false); }
      }}>{busy ? "Requesting…" : "Retest this finding"}</button>
      {msg && <p className="muted">{msg}</p>}
      {err && <p className="err" role="alert">{err}</p>}
    </>
  );
}

function Triage({ id, current, onDone }:
  { id: string; current: string; onDone: () => void }) {
  const [status, setStatus] = useState(current);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const needsNote = status === "false_positive" || status === "accepted_risk";

  return (
    <form className="inline-form" onSubmit={async (e) => {
      e.preventDefault();
      setBusy(true); setErr("");
      try { await api.triage(id, status, note); setNote(""); onDone(); }
      catch (e) { setErr((e as Error).message); }
      finally { setBusy(false); }
    }}>
      <label>Decision
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </label>
      <label>Justification{needsNote ? " (required)" : ""}
        <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2}
                  placeholder={needsNote
                    ? "Why is this not a risk? This is recorded against the finding."
                    : "Optional"} />
      </label>
      {needsNote && (
        <p className="muted">
          Closing a finding as a false positive or an accepted risk requires a reason. It is kept
          with the finding so the decision can be reviewed later.
        </p>
      )}
      {err && <p className="err" role="alert">{err}</p>}
      <button type="submit" disabled={busy || (needsNote && !note.trim())}>
        {busy ? "Saving…" : "Apply"}
      </button>
    </form>
  );
}
