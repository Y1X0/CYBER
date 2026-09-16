// The front door: "What do you want to scan?" A task-first flow that turns a plain choice into the
// asset + scan the backend already understands. No new capability — it calls createAsset + startScan
// exactly as the Assets screen does, then routes to the live scan.

import { useState } from "react";
import { ARTIFACT_MAX_BYTES, Customer, api } from "../api";
import { navigate } from "../router";
import { SCAN_TYPES, ScanType } from "../scanCatalog";
import { Async, Card, useAsync } from "../ui";

function humanSize(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  return mb >= 1 ? `${mb.toFixed(1)} MB` : `${(bytes / 1024).toFixed(0)} KB`;
}

// Client-side pre-check so an obviously-wrong file is caught before any upload. The server re-checks
// authoritatively (type by content, size by hard cap), so this is UX, not the security boundary.
function localArtifactError(file: File, upload: NonNullable<ScanType["upload"]>): string | null {
  if (!file.name.toLowerCase().endsWith(`.${upload.ext}`)) {
    return `This needs a .${upload.ext} file. That looks like a different kind of file.`;
  }
  if (file.size === 0) return "That file is empty.";
  if (file.size > ARTIFACT_MAX_BYTES) {
    return `That file is ${humanSize(file.size)}; the limit is ${humanSize(ARTIFACT_MAX_BYTES)}.`;
  }
  return null;
}

export function NewScanScreen({ preselect }: { preselect?: string | null }) {
  const customers = useAsync(() => api.customers(), []);
  const [type, setType] = useState<ScanType | null>(
    () => (preselect ? SCAN_TYPES.find((t) => t.id === preselect) ?? null : null));

  return (
    <Async loader={customers}>
      {(page) => (page.rows.length === 0
        ? <NoCustomer />
        : type
          ? <ScanForm type={type} customers={page.rows} onBack={() => setType(null)} />
          : <ChooseType onPick={setType} />)}
    </Async>
  );
}

function ChooseType({ onPick }: { onPick: (t: ScanType) => void }) {
  return (
    <Card title="What do you want to scan?">
      <p className="muted">
        Pick what you own or are authorized to assess. Guardian sets up the target and runs the
        right engines for it — you don't need to know which.
      </p>
      <div className="scan-type-grid">
        {SCAN_TYPES.map((t) => (
          <button key={t.id} className="scan-type hud-corners" onClick={() => onPick(t)}>
            <span className="scan-type-icon" aria-hidden="true">{t.icon}</span>
            <span className="scan-type-label">{t.label}</span>
            <span className="scan-type-blurb">{t.blurb}</span>
            {t.network && <span className="scan-type-tag">needs authorization</span>}
          </button>
        ))}
      </div>
    </Card>
  );
}

function ScanForm({ type, customers, onBack }:
  { type: ScanType; customers: Customer[]; onBack: () => void }) {
  const [form, setForm] = useState({
    customer_id: customers[0]?.id ?? "",
    name: "",
    identifier: "",
    exposure: type.exposure,
  });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const needsUpload = Boolean(type.upload);

  function pickFile(f: File | null) {
    setErr("");
    if (f && type.upload) {
      const problem = localArtifactError(f, type.upload);
      if (problem) { setErr(problem); setFile(null); return; }
    }
    setFile(f);
  }

  async function start(e: React.FormEvent) {
    e.preventDefault();
    if (needsUpload && !file) { setErr("Choose a file to upload first."); return; }
    setBusy(true); setErr(""); setProgress(needsUpload ? 0 : null);
    try {
      const asset = await api.createAsset({
        customer_id: form.customer_id, name: form.name || type.label,
        kind: type.assetKind, identifier: form.identifier, exposure: form.exposure,
      });
      // For an upload type the artifact must be attached before the scan will start (the server
      // rejects a scan of an asset with no artifact), so upload first, then scan.
      if (needsUpload && file) {
        await api.uploadArtifact(asset.id, file, (frac) => setProgress(frac));
      }
      const scan = await api.startScan(asset.id, type.engines);
      navigate(`scans/${scan.id}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  return (
    <Card title={<>{type.icon} Scan a {type.label.toLowerCase()}</>}
          actions={<button onClick={onBack}>← Change</button>}>
      <p className="muted">{type.inputHint}</p>
      <form className="inline-form" onSubmit={start}>
        {customers.length > 1 && (
          <label>Customer
            <select value={form.customer_id}
                    onChange={(e) => setForm({ ...form, customer_id: e.target.value })}>
              {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
        )}
        <label>Name
          <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                 placeholder={type.label} />
        </label>
        <label>{type.identifierLabel}
          <input value={form.identifier} required={!needsUpload}
                 placeholder={type.identifierPlaceholder}
                 onChange={(e) => setForm({ ...form, identifier: e.target.value })} />
        </label>

        {type.upload && (
          <label>{type.upload.label}
            <input type="file" accept={type.upload.accept} data-testid="artifact-file"
                   onChange={(e) => pickFile(e.target.files?.[0] ?? null)} />
            <span className="muted">
              {file
                ? `${file.name} — ${humanSize(file.size)}`
                : `Select the ${type.upload.label} to analyse (up to `
                  + `${humanSize(ARTIFACT_MAX_BYTES)}). It is read statically and never run.`}
            </span>
          </label>
        )}

        {progress !== null && (
          <div className="upload-progress" role="progressbar" aria-valuemin={0} aria-valuemax={100}
               aria-valuenow={Math.round(progress * 100)}>
            <div className="upload-progress-bar" style={{ width: `${Math.round(progress * 100)}%` }} />
            <span className="muted">Uploading… {Math.round(progress * 100)}%</span>
          </div>
        )}
        <label>Exposure
          <select value={form.exposure}
                  onChange={(e) => setForm({ ...form, exposure: e.target.value })}>
            <option value="public">Internet-facing</option>
            <option value="internal">Internal</option>
            <option value="isolated">Isolated</option>
          </select>
        </label>

        <div className="scan-engines-note">
          <span className="muted">Engines</span>
          <div className="chips">
            {type.engines.map((k) => <span key={k} className="chip">{k}</span>)}
          </div>
          {type.network && (
            <p className="muted">
              Active network testing runs only when an authorization covers this asset; otherwise it
              is skipped and the scan tells you so.
            </p>
          )}
        </div>

        {err && <p className="err" role="alert">{err}</p>}
        <button type="submit"
                disabled={busy || (needsUpload ? !file : !form.identifier)}>
          {busy
            ? (needsUpload ? "Uploading…" : "Starting…")
            : (needsUpload ? "Upload & scan" : "Start scan")}
        </button>
      </form>
    </Card>
  );
}

function NoCustomer() {
  return (
    <Card title="What do you want to scan?">
      <p className="err">
        There is no customer record to attach an asset to. One is created with your organization;
        if you are seeing this, add one on the Organization screen first.
      </p>
      <button onClick={() => navigate("organization")}>Go to Organization</button>
    </Card>
  );
}
