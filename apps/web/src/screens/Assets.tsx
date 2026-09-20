// Assets: what Guardian knows about, and the place a scan is started from.

import { useState } from "react";
import { Asset, Customer, api } from "../api";
import { navigate } from "../router";
import { Async, Card, EmptyState, useAsync, when } from "../ui";

// A web/api target is fetched exactly as entered and redirects are NOT followed, so the scheme is
// load-bearing: an HTTP-only host silently treated as https:// is unreachable and reads as a clean
// 0-findings scan. Guide the operator to state the scheme rather than have one guessed. Returns a
// live hint (or null when the target is fine). The API enforces the same rule with a 422.
export function targetSchemeHint(kind: string, identifier: string): string | null {
  if (kind !== "web" && kind !== "api") return null;
  const v = identifier.trim();
  if (!v) return null;
  const lower = v.toLowerCase();
  if (lower.startsWith("http://") || lower.startsWith("https://")) return null;
  if (lower.includes("://")) {
    return `Only http:// and https:// targets can be scanned — “${v.split("://")[0]}://” cannot.`;
  }
  return `Include the scheme: http://${v} for a plain-HTTP host, or https://${v} for one served `
    + "over TLS. They are scanned differently and redirects are not followed, so pick the one the "
    + "site actually serves.";
}

const KINDS = [
  { value: "repo", label: "Source repository", hint: "A git URL, or code you supply" },
  { value: "web", label: "Web application",
    hint: "A full URL including the scheme — http:// or https:// (HTTP-only hosts must use http://)" },
  { value: "api", label: "API",
    hint: "A base URL including http:// or https://, with an OpenAPI document" },
  { value: "cloud", label: "Cloud account", hint: "Assessed from a collector export" },
  { value: "host", label: "Host", hint: "A hostname or address" },
  { value: "mobile_app", label: "Mobile app (Android)",
    hint: "Upload an Android .apk — analysed statically (no emulator)" },
  { value: "ios_app", label: "Mobile app (iOS)",
    hint: "Upload an iOS .ipa — analysed statically (Info.plist, entitlements, binary)" },
  { value: "network_host", label: "Home network / Router",
    hint: "Run the local agent and submit its posture report (see docs/LOCAL_AGENT.md)" },
  { value: "server_host", label: "Server (Linux)",
    hint: "Run the local agent and submit its posture report (see docs/LOCAL_AGENT.md)" },
];

const ENGINES = [
  { key: "secrets", label: "Secrets", network: false },
  { key: "sast", label: "Code analysis", network: false },
  { key: "sca", label: "Dependencies", network: false },
  { key: "ai_discovery", label: "AI vulnerability discovery", network: false },
  { key: "iac", label: "Infrastructure code", network: false },
  { key: "cicd", label: "CI/CD & supply chain", network: false },
  { key: "k8s", label: "Kubernetes", network: false },
  { key: "container", label: "Container", network: false },
  { key: "ml_model", label: "ML model malware", network: false },
  { key: "cspm", label: "Cloud posture", network: false },
  { key: "dast", label: "Dynamic web testing", network: true },
  { key: "api", label: "API testing", network: true },
  { key: "mobile", label: "Mobile app (APK)", network: false },
  { key: "ios", label: "Mobile app (iOS IPA)", network: false },
  { key: "host_posture", label: "Host / network posture (agent)", network: false },
];

export function AssetsScreen() {
  const assets = useAsync(() => api.assets(), []);
  const customers = useAsync(() => api.customers(), []);
  const [creating, setCreating] = useState(false);

  return (
    <>
      <Card title="Assets" actions={
        <button onClick={() => setCreating((v) => !v)}>
          {creating ? "Cancel" : "Add asset"}
        </button>
      }>
        {creating && customers.data && (
          <NewAsset
            customers={customers.data.rows}
            onDone={() => { setCreating(false); assets.reload(); }}
          />
        )}
        <Async
          loader={assets}
          empty={
            <EmptyState
              title="No assets yet"
              body="Guardian assesses things you tell it about. Add a repository, a web
                    application, an API or a cloud account to begin."
              action={<button onClick={() => setCreating(true)}>Add your first asset</button>}
            />
          }
        >
          {(page) => (
            <table>
              <thead>
                <tr><th>Name</th><th>Kind</th><th>Identifier</th><th>Exposure</th>
                    <th>Added</th><th /></tr>
              </thead>
              <tbody>
                {page.rows.map((a: Asset) => (
                  <tr key={a.id}>
                    <td>{a.name}</td>
                    <td>{a.kind}</td>
                    <td className="mono">{a.identifier}</td>
                    <td>{a.exposure}</td>
                    <td>{when(a.created_at)}</td>
                    <td><StartScan asset={a} /></td>
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

function NewAsset({ customers, onDone }: { customers: Customer[]; onDone: () => void }) {
  const [form, setForm] = useState({
    customer_id: customers[0]?.id ?? "", name: "", kind: "repo",
    identifier: "", exposure: "public",
  });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.createAsset({ ...form, identifier: form.identifier.trim() });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (customers.length === 0) {
    return <p className="err">
      There is no customer record to attach an asset to. One is created with your organization;
      if you are seeing this, add one on the Organization screen first.
    </p>;
  }

  return (
    <form className="inline-form" onSubmit={submit}>
      <label>Customer
        <select value={form.customer_id}
                onChange={(e) => setForm({ ...form, customer_id: e.target.value })}>
          {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </label>
      <label>Name
        <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
               required placeholder="Production web" />
      </label>
      <label>Kind
        <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
          {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
        </select>
        <small>{KINDS.find((k) => k.value === form.kind)?.hint}</small>
      </label>
      <label>Identifier
        <input value={form.identifier}
               onChange={(e) => setForm({ ...form, identifier: e.target.value })}
               required
               placeholder={form.kind === "web" || form.kind === "api"
                 ? "http://host or https://host — include the scheme"
                 : "https://github.com/acme/app.git, or an uploaded artefact id"} />
        {targetSchemeHint(form.kind, form.identifier) && (
          <small className="warn">{targetSchemeHint(form.kind, form.identifier)}</small>
        )}
      </label>
      <label>Exposure
        <select value={form.exposure}
                onChange={(e) => setForm({ ...form, exposure: e.target.value })}>
          <option value="public">Internet-facing</option>
          <option value="internal">Internal</option>
          <option value="isolated">Isolated</option>
        </select>
      </label>
      {err && <p className="err" role="alert">{err}</p>}
      <button type="submit" disabled={busy}>{busy ? "Adding…" : "Add asset"}</button>
    </form>
  );
}

function StartScan({ asset }: { asset: Asset }) {
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<string[]>(["secrets"]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function start() {
    setBusy(true);
    setErr("");
    try {
      const scan = await api.startScan(asset.id, selected);
      navigate(`scans/${scan.id}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!open) return <button onClick={() => setOpen(true)}>Scan</button>;

  const networkChosen = selected.some((k) => ENGINES.find((e) => e.key === k)?.network);
  return (
    <div className="popover">
      <p><strong>Scan {asset.name}</strong></p>
      {ENGINES.map((e) => (
        <label key={e.key} className="check">
          <input
            type="checkbox"
            checked={selected.includes(e.key)}
            onChange={(ev) => setSelected(ev.target.checked
              ? [...selected, e.key]
              : selected.filter((k) => k !== e.key))}
          />
          {e.label}{e.network ? " (network)" : ""}
        </label>
      ))}
      {networkChosen && (
        // Said before the request, not after the refusal.
        <p className="muted">
          Network testing needs an active authorization covering this asset, and that needs a
          verified domain. Without one these engines will be skipped and the scan will tell you so.
        </p>
      )}
      {err && <p className="err" role="alert">{err}</p>}
      <button onClick={start} disabled={busy || selected.length === 0}>
        {busy ? "Starting…" : "Start scan"}
      </button>
      <button onClick={() => setOpen(false)}>Cancel</button>
    </div>
  );
}
