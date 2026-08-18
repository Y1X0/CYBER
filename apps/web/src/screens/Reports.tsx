// Reports: choose a scan, generate, download.

import { useState } from "react";
import { Report, Scan, api } from "../api";
import { Async, Card, EmptyState, StatusPill, useAsync, when } from "../ui";

export function ReportsScreen() {
  const reports = useAsync(() => api.reports(), []);
  const scans = useAsync(() => api.scans(), []);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [scanId, setScanId] = useState("");
  const [title, setTitle] = useState("Security assessment");

  const finished = (scans.data?.rows ?? []).filter(
    (s: Scan) => s.status === "completed" || s.status === "partial");

  async function generate(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      await api.createReport(scanId || finished[0]?.id, title);
      reports.reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Card title="Generate a report">
        {finished.length === 0 ? (
          <p className="muted">
            A report covers one completed scan, and no scan has completed yet. Run a scan first —
            a report of a scan that never ran would describe nothing.
          </p>
        ) : (
          <form className="inline-form" onSubmit={generate}>
            <label>Scope (scan)
              <select value={scanId} onChange={(e) => setScanId(e.target.value)}>
                {finished.map((s: Scan) => (
                  <option key={s.id} value={s.id}>
                    {when(s.created_at)} · {s.requested_engines.join(", ")} ·{" "}
                    {s.stats?.total ?? 0} findings{s.status === "partial" ? " (partial)" : ""}
                  </option>
                ))}
              </select>
            </label>
            <label>Title
              <input value={title} onChange={(e) => setTitle(e.target.value)} required />
            </label>
            {err && <p className="err" role="alert">{err}</p>}
            <button type="submit" disabled={busy}>{busy ? "Generating…" : "Generate report"}</button>
            <p className="muted">
              A report of a partial scan is labelled as partial. It describes what was checked, not
              what exists.
            </p>
          </form>
        )}
      </Card>

      <Card title="Reports">
        <Async
          loader={reports}
          empty={<EmptyState title="No reports yet"
                             body="Generate one from a completed scan above." />}
        >
          {(page) => (
            <table>
              <thead>
                <tr><th>Title</th><th>Status</th><th>Findings</th><th>Created</th><th /></tr>
              </thead>
              <tbody>
                {page.rows.map((r: Report) => (
                  <tr key={r.id}>
                    <td>{r.title}</td>
                    <td><StatusPill tone={r.status === "published" ? "ok" : "wait"}>
                      {r.status}
                    </StatusPill></td>
                    <td>{String((r.summary as { total_findings?: number })?.total_findings ?? "—")}</td>
                    <td>{when(r.created_at)}</td>
                    <td className="row-actions">
                      <DownloadButton id={r.id} format="html" label="View HTML" />
                      <DownloadButton id={r.id} format="pdf" label="Download PDF" />
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

function DownloadButton({ id, format, label }:
  { id: string; format: string; label: string }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function go() {
    setBusy(true); setErr("");
    try {
      // Fetched rather than linked: the export needs the bearer token, which a plain anchor
      // cannot send.
      const blob = await api.downloadReport(id, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `guardian-report-${id.slice(0, 8)}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button onClick={go} disabled={busy}>{busy ? "Preparing…" : label}</button>
      {err && <span className="err">{err}</span>}
    </>
  );
}
