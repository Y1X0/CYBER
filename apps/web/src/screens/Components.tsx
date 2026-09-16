// Components & SBOM as a first-class Results view, instead of a card hidden inside one scan.
//
// It reuses the existing per-scan SBOM endpoints (no new API): pick a scan, see the inventory it
// produced — every component, its version and ecosystem, and which ones a vulnerability touches —
// and download the CycloneDX document. Frontend-only; the data is exactly what the backend already
// stores per scan.

import { useState } from "react";
import { Scan, SbomComponent, SbomDocument, SbomMeta, api } from "../api";
import { Async, Card, EmptyState, useAsync, when } from "../ui";

export function ComponentsScreen() {
  const scans = useAsync(() => api.scans(), []);
  return (
    <Card title="Components & SBOM">
      <p className="muted">
        The software inventory each scan resolved — dependencies, packages and bundled libraries —
        with the vulnerable ones flagged. Exportable as CycloneDX.
      </p>
      <Async
        loader={scans}
        empty={<EmptyState title="No scans yet"
                           body="Run a scan and its component inventory will appear here." />}
      >
        {(page) => <Picker scans={page.rows} />}
      </Async>
    </Card>
  );
}

function Picker({ scans }: { scans: Scan[] }) {
  const [selected, setSelected] = useState<string>(scans[0]?.id ?? "");
  return (
    <>
      <label className="components-pick">Scan
        <select value={selected} onChange={(e) => setSelected(e.target.value)}>
          {scans.map((s) => (
            <option key={s.id} value={s.id}>
              {s.id.slice(0, 8)} · {s.status} · {when(s.created_at)}
            </option>
          ))}
        </select>
      </label>
      {selected && <ScanComponents scanId={selected} />}
    </>
  );
}

function ScanComponents({ scanId }: { scanId: string }) {
  const meta = useAsync<SbomMeta>(() => api.sbomMeta(scanId), [scanId]);
  return (
    <Async loader={meta}>
      {(m) => m.available
        ? <Table scanId={scanId} meta={m} />
        : <p className="muted" style={{ marginTop: "var(--s-3)" }}>
            This scan produced no SBOM. It runs for scans that resolve components — source
            dependencies, a container image, server packages, or a mobile app.
          </p>}
    </Async>
  );
}

function purlType(purl: string): string {
  // pkg:pypi/flask@2.0.1 -> "pypi"; pkg:deb/openssl@3 -> "deb"
  const m = /^pkg:([^/]+)\//.exec(purl || "");
  return m ? m[1] : "—";
}

function Table({ scanId, meta }: { scanId: string; meta: SbomMeta }) {
  const doc = useAsync<SbomDocument>(() => api.sbomDocument(scanId), [scanId]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function download() {
    setBusy(true); setErr("");
    try {
      const blob = await api.downloadSbom(scanId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `sbom-${scanId.slice(0, 8)}.cdx.json`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }

  return (
    <div className="components">
      <div className="components-head">
        <div className="components-counts">
          <span><b>{meta.component_count ?? 0}</b> components</span>
          <span className={meta.vulnerable_count ? "vuln" : ""}>
            <b>{meta.vulnerable_count ?? 0}</b> vulnerable
          </span>
          <span className="muted">{meta.format} {meta.spec_version}</span>
        </div>
        <div>
          {err && <span className="err" role="alert">{err}</span>}
          <button onClick={download} disabled={busy}>
            {busy ? "Preparing…" : "Download SBOM (CycloneDX)"}
          </button>
        </div>
      </div>

      <Async loader={doc}>
        {(d) => {
          const vulnRefs = new Set<string>();
          for (const v of d.vulnerabilities ?? [])
            for (const a of v.affects ?? []) if (a.ref) vulnRefs.add(a.ref);
          const comps = (d.components ?? []);
          const shown = comps.slice(0, 1000);
          return (
            <>
              <table>
                <thead>
                  <tr><th>Component</th><th>Version</th><th>Ecosystem</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {shown.map((c: SbomComponent) => {
                    const vulnerable = vulnRefs.has(c.purl);
                    return (
                      <tr key={c.purl}>
                        <td>{c.name}</td>
                        <td className="mono">{c.version || <span className="muted">—</span>}</td>
                        <td className="mono">{purlType(c.purl)}</td>
                        <td>{vulnerable
                          ? <span className="tag-vuln">vulnerable</span>
                          : <span className="muted">ok</span>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {comps.length > shown.length && (
                <p className="muted">Showing the first {shown.length} of {comps.length} components.
                  Download the SBOM for the full inventory.</p>
              )}
            </>
          );
        }}
      </Async>
    </div>
  );
}
