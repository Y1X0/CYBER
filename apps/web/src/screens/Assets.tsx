// Assets: what Guardian knows about, and the place a scan is started from.

import { useState } from "react";
import { Asset, Customer, api } from "../api";
import { navigate } from "../router";
import { Async, Card, EmptyState, useAsync, when } from "../ui";

const KINDS = [
  { value: "repo", label: "Source repository", hint: "A git URL, or code you supply" },
  { value: "web", label: "Web application", hint: "An https:// URL" },
  { value: "api", label: "API", hint: "A base URL with an OpenAPI document" },
  { value: "cloud", label: "Cloud account", hint: "Assessed from a collector export" },
  { value: "host", label: "Host", hint: "A hostname or address" },
];

const ENGINES = [
  { key: "secrets", label: "Secrets", network: false },
  { key: "sast", label: "Code analysis", network: false },
  { key: "sca", label: "Dependencies", network: false },
  { key: "iac", label: "Infrastructure code", network: false },
  { key: "k8s", label: "Kubernetes", network: false },
  { key: "container", label: "Container", network: false },
  { key: "cspm", label: "Cloud posture", network: false },
  { key: "dast", label: "Dynamic web testing", network: true },
  { key: "api", label: "API testing", network: true },
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
      await api.createAsset(form);
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
               required placeholder="https://example.com or https://github.com/acme/app.git" />
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
