// The front door: "What do you want to scan?" A task-first flow that turns a plain choice into the
// asset + scan the backend already understands. No new capability — it calls createAsset + startScan
// exactly as the Assets screen does, then routes to the live scan.

import { useState } from "react";
import { Customer, api } from "../api";
import { navigate } from "../router";
import { SCAN_TYPES, ScanType } from "../scanCatalog";
import { Async, Card, useAsync } from "../ui";

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

  async function start(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      const asset = await api.createAsset({
        customer_id: form.customer_id, name: form.name || type.label,
        kind: type.assetKind, identifier: form.identifier, exposure: form.exposure,
      });
      const scan = await api.startScan(asset.id, type.engines);
      navigate(`scans/${scan.id}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
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
          <input value={form.identifier} required placeholder={type.identifierPlaceholder}
                 onChange={(e) => setForm({ ...form, identifier: e.target.value })} />
        </label>
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
        <button type="submit" disabled={busy || !form.identifier}>
          {busy ? "Starting…" : "Start scan"}
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
