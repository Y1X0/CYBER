// Sign in and sign up — the front door the product did not have.

import { useState } from "react";
import { api } from "../api";

export function AuthScreen({ onAuthed }: { onAuthed: () => void }) {
  const [mode, setMode] = useState<"login" | "signup">("login");
  return (
    <div className="center">
      <div className="card">
        <h1>🛡️ Security Guardian</h1>
        <div className="tabs">
          <button className={mode === "login" ? "tab on" : "tab"} onClick={() => setMode("login")}>
            Sign in
          </button>
          <button className={mode === "signup" ? "tab on" : "tab"}
                  onClick={() => setMode("signup")}>
            Create an organization
          </button>
        </div>
        {mode === "login" ? <LoginForm onAuthed={onAuthed} /> : <SignupForm onAuthed={onAuthed} />}
      </div>
    </div>
  );
}

function LoginForm({ onAuthed }: { onAuthed: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.login(email, password);
      onAuthed();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <label>Email
        <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" required
               autoComplete="username" />
      </label>
      <label>Password
        <input value={password} onChange={(e) => setPassword(e.target.value)} type="password"
               required autoComplete="current-password" />
      </label>
      {err && <p className="err" role="alert">{err}</p>}
      <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
    </form>
  );
}

function SignupForm({ onAuthed }: { onAuthed: () => void }) {
  const [form, setForm] = useState({
    organization: "", company: "", name: "", email: "", password: "",
  });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm({ ...form, [k]: e.target.value });

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.signup(form);
      onAuthed();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <label>Organization
        <input value={form.organization} onChange={set("organization")} required minLength={2}
               placeholder="Acme Inc" />
      </label>
      <label>Company or business unit to assess
        <input value={form.company} onChange={set("company")} placeholder="Acme Production" />
      </label>
      <label>Your name
        <input value={form.name} onChange={set("name")} autoComplete="name" />
      </label>
      <label>Email
        <input value={form.email} onChange={set("email")} type="email" required
               autoComplete="username" />
      </label>
      <label>Password
        <input value={form.password} onChange={set("password")} type="password" required
               minLength={12} autoComplete="new-password" />
        <small>At least 12 characters.</small>
      </label>
      {err && <p className="err" role="alert">{err}</p>}
      <button type="submit" disabled={busy}>
        {busy ? "Creating…" : "Create organization"}
      </button>
      {/* Said at the door rather than discovered later: creating an account grants Guardian
          nothing. Every capability has to be authorized separately, and network testing needs a
          proof of control, not a tick-box. */}
      <p className="muted">
        Creating an organization does not let Guardian scan anything. You will add an asset, then
        authorize what we may do with it — and active network testing additionally requires
        verifying that you control the domain.
      </p>
    </form>
  );
}
