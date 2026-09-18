// The front door: "What do you want to scan?" A task-first flow that turns a plain choice into the
// asset + scan the backend already understands. No new capability — it calls createAsset + startScan
// exactly as the Assets screen does, then routes to the live scan.

import { useState } from "react";
import { ApiError, ARTIFACT_MAX_BYTES, Customer, api } from "../api";
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

  // Owner-direct: only relevant for network/active scans, and only offered when the server says
  // this caller may use it (tenant owner + feature enabled). The checkbox is UX; the server
  // re-checks the owner role on dispatch regardless of what the client sends.
  const ownerDirect = useAsync(
    () => (type.network ? api.ownerDirectPreflight().catch(() => null) : Promise.resolve(null)), []);
  const [direct, setDirect] = useState(false);
  // When the first owner-direct scan of a target needs the legal affirmation, the server returns
  // it here; the modal below captures it and re-launches with affirm=true against the SAME asset.
  const [affirmModal, setAffirmModal] =
    useState<{ target: string; text: string; assetId: string } | null>(null);
  const [affirmChecked, setAffirmChecked] = useState(false);

  async function launch(assetId: string, affirmed: boolean) {
    const scan = direct
      ? await api.startScan(assetId, type.engines, { direct: true, affirm: affirmed })
      : await api.startScan(assetId, type.engines);
    navigate(`scans/${scan.id}`);
  }

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
    let createdAssetId: string | null = null;
    try {
      // Scanning a target you already have should just work: if createAsset reports the asset
      // already exists (409), reuse the existing one the server names instead of dead-ending.
      let assetId: string;
      try {
        const asset = await api.createAsset({
          customer_id: form.customer_id, name: form.name || type.label,
          kind: type.assetKind, identifier: form.identifier, exposure: form.exposure,
        });
        assetId = asset.id;
      } catch (e) {
        const ae = e as ApiError;
        const d = ae.detail as { code?: string; asset_id?: string } | undefined;
        if (ae.status === 409 && d?.code === "asset_exists" && d.asset_id) {
          assetId = d.asset_id;
        } else {
          throw e;
        }
      }
      createdAssetId = assetId;
      // For an upload type the artifact must be attached before the scan will start (the server
      // rejects a scan of an asset with no artifact), so upload first, then scan.
      if (needsUpload && file) {
        await api.uploadArtifact(assetId, file, (frac) => setProgress(frac));
      }
      await launch(assetId, false);
    } catch (e) {
      // The first owner-direct scan of a target needs a legal affirmation: the server says so with
      // a 409, and we show the affirmation modal rather than a raw error. The asset is already
      // created, so the modal re-launches against the same asset id (no duplicate asset).
      const ae = e as ApiError;
      const detail = ae.detail as { code?: string; target?: string; affirmation?: string } | undefined;
      if (direct && ae.status === 409 && detail?.code === "owner_direct_affirmation_required") {
        setAffirmModal({
          target: detail.target ?? form.identifier,
          text: detail.affirmation ?? "I affirm I have the legal right to scan this target.",
          assetId: (createdAssetId ?? ""),
        });
        setAffirmChecked(false);
      } else {
        setErr((e as Error).message);
      }
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  async function confirmAffirmation() {
    if (!affirmModal || !affirmChecked) return;
    setBusy(true); setErr("");
    try {
      await launch(affirmModal.assetId, true);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
      setAffirmModal(null);
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

        {ownerDirect.data?.eligible && (
          <label className="owner-direct-toggle">
            <input type="checkbox" checked={direct}
                   onChange={(e) => setDirect(e.target.checked)} data-testid="owner-direct" />
            <span>
              Run as owner-direct — scan this target without verified ownership.
              <span className="muted">
                {" "}Owner-only. You will affirm you have the legal right to scan it, and the scan is
                recorded as owner-direct in the audit log.
              </span>
            </span>
          </label>
        )}

        {err && <p className="err" role="alert">{err}</p>}
        <button type="submit"
                disabled={busy || (needsUpload ? !file : !form.identifier)}>
          {busy
            ? (needsUpload ? "Uploading…" : "Starting…")
            : (needsUpload ? "Upload & scan" : "Start scan")}
        </button>
      </form>

      {affirmModal && (
        <div className="modal-backdrop" role="dialog" aria-modal="true"
             aria-label="Owner-direct scan affirmation">
          <div className="modal">
            <h3>Confirm owner-direct scan</h3>
            <p>
              You are about to run an active security scan against <strong>{affirmModal.target}</strong>{" "}
              without verified ownership, under your authority as the tenant owner.
            </p>
            <label className="affirm-check">
              <input type="checkbox" checked={affirmChecked} data-testid="affirm-check"
                     onChange={(e) => setAffirmChecked(e.target.checked)} />
              <span>{affirmModal.text}</span>
            </label>
            <p className="muted">
              This affirmation and the scan are written to the audit log, which cannot be edited or
              deleted.
            </p>
            <div className="modal-actions">
              <button type="button" onClick={() => setAffirmModal(null)}>Cancel</button>
              <button type="button" disabled={!affirmChecked || busy}
                      onClick={confirmAffirmation}>
                {busy ? "Starting…" : "Affirm & scan"}
              </button>
            </div>
          </div>
        </div>
      )}
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
