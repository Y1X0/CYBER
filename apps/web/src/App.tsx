import { useEffect, useState } from "react";
import { AttackGraph } from "./AttackGraph";
import { CompliancePanel } from "./Compliance";
import { api, Dashboard, Finding, getToken, Scan, setToken } from "./api";

const SEV_COLOR: Record<string, string> = {
  critical: "#b00020",
  high: "#d9534f",
  medium: "#f0ad4e",
  low: "#5bc0de",
  info: "#777",
};

export function App() {
  const [authed, setAuthed] = useState<boolean>(!!getToken());
  return authed ? <Console onLogout={() => { setToken(null); setAuthed(false); }} />
                : <Login onLogin={() => setAuthed(true)} />;
}

function Login({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState("admin@example.com");
  const [password, setPassword] = useState("ChangeMe123!");
  const [err, setErr] = useState("");
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.login(email, password);
      onLogin();
    } catch {
      setErr("Invalid credentials");
    }
  }
  return (
    <div className="center">
      <form className="card" onSubmit={submit}>
        <h1>🛡️ Security Guardian</h1>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
               placeholder="Password" />
        {err && <p className="err">{err}</p>}
        <button type="submit">Sign in</button>
      </form>
    </div>
  );
}

function Console({ onLogout }: { onLogout: () => void }) {
  const [dash, setDash] = useState<Dashboard | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => { api.dashboard().then(setDash).catch(() => onLogout()); }, []);
  useEffect(() => { if (scan) api.findings(scan.id).then(setFindings); }, [scan]);

  if (!dash) return <div className="center">Loading…</div>;
  return (
    <div className="app">
      <header>
        <h2>🛡️ Security Guardian</h2>
        <button onClick={onLogout}>Sign out</button>
      </header>
      <main>
        <section className="score-card">
          <div className="score">{dash.security_score}<small>/100</small></div>
          <div className="badges">
            {Object.entries(dash.severity_counts).map(([s, n]) => (
              <span key={s} style={{ background: SEV_COLOR[s] }}>{s}: {n}</span>
            ))}
          </div>
          <p>{dash.total_findings} findings across recent scans</p>
        </section>

        <section>
          <h3>Recent scans</h3>
          <table>
            <thead><tr><th>Scan</th><th>Status</th><th>Findings</th><th></th></tr></thead>
            <tbody>
              {dash.recent_scans.map((s) => (
                <tr key={s.id}>
                  <td><code>{s.id.slice(0, 8)}</code></td>
                  <td>{s.status}</td>
                  <td>{s.stats?.total ?? 0}</td>
                  <td><button onClick={() => setScan(s)}>View</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {scan && (
          <section>
            <h3>Findings — scan {scan.id.slice(0, 8)}</h3>
            <table>
              <thead><tr><th>Severity</th><th>Risk</th><th>Title</th><th>Standards</th></tr></thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td><span style={{ color: SEV_COLOR[f.severity] }}>{f.severity.toUpperCase()}</span></td>
                    <td>{f.risk_score}</td>
                    <td>{f.title}</td>
                    <td>{f.cwe_id} {f.owasp_ref}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="hint">
              Export a professional PDF report at
              <code> GET /api/v1/reports/{"{id}"}/export?format=pdf</code>.
            </p>
          </section>
        )}

        {/* The attack graph sits above the chat: what an attacker would do with these findings is
            a more useful next question than any the analyst can be asked. */}
        <AttackGraph />

        <CompliancePanel />

        <ChatBox scanId={scan?.id} />
      </main>
    </div>
  );
}

function ChatBox({ scanId }: { scanId?: string }) {
  const [q, setQ] = useState("");
  const [a, setA] = useState("");
  const [busy, setBusy] = useState(false);
  async function ask() {
    setBusy(true);
    try {
      const r = await api.chat(q, scanId);
      setA(r.answer);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="chat">
      <h3>Ask the AI analyst</h3>
      <p className="hint">Answers are grounded strictly on your own findings.</p>
      <div className="chat-row">
        <input value={q} onChange={(e) => setQ(e.target.value)}
               placeholder="e.g. What is my biggest risk?" />
        <button onClick={ask} disabled={busy || !q}>{busy ? "…" : "Ask"}</button>
      </div>
      {a && <pre className="answer">{a}</pre>}
    </section>
  );
}
