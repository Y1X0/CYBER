// Thin typed client for the Security Guardian API. Token is kept in memory + localStorage.

let token: string | null = localStorage.getItem("guardian_token");

export function getToken(): string | null {
  return token;
}
export function setToken(t: string | null) {
  token = t;
  if (t) localStorage.setItem("guardian_token", t);
  else localStorage.removeItem("guardian_token");
}

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const resp = await fetch(`/api/v1${path}`, { ...opts, headers: { ...headers, ...opts.headers } });
  if (!resp.ok) throw new Error(`${resp.status}: ${await resp.text()}`);
  return resp.json() as Promise<T>;
}

export interface Dashboard {
  security_score: number;
  severity_counts: Record<string, number>;
  total_findings: number;
  recent_scans: Scan[];
}
export interface Scan {
  id: string;
  status: string;
  stats: Record<string, number>;
  requested_engines: string[];
  created_at: string;
}
export interface Finding {
  id: string;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
  cwe_id: string | null;
  owasp_ref: string | null;
  evidence: Record<string, unknown>;
  references: Record<string, unknown>;
}

// ── WP-E4 attack chains ──────────────────────────────────────────────────────────────────────────
export interface ChainStep {
  finding_id: string;
  asset_id: string;
  title: string;
  severity: string;
  cwe_id: string | null;
  grants: string[];
  reliability: number;
  rationale: string;
}
export interface AttackChain {
  entry: string;
  length: number;
  likelihood: number;
  impact: number;
  score: number;
  capabilities: string[];
  narrative: string;
  steps: ChainStep[];
}
export interface AttackChains {
  chains: AttackChain[];
  truncated: boolean;
  /**
   * Findings whose class maps to no capability, so they could not be used as a step. Rendered
   * alongside an empty result: "no attack path" and "we could not reason about these" are
   * different statements, and a UI that shows only the first one is telling the customer they are
   * safe on evidence it does not have.
   */
  unchainable_findings: number;
}

export interface FindingSummary {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_engine: Record<string, number>;
  exploitable: number;
  correlated: number;
  unverified: number;
}

export const api = {
  async login(email: string, password: string): Promise<void> {
    const r = await req<{ access_token: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setToken(r.access_token);
  },
  dashboard: (customerId?: string) =>
    req<Dashboard>(`/dashboard${customerId ? `?customer_id=${customerId}` : ""}`),
  findings: (scanId: string) => req<Finding[]>(`/findings?scan_id=${scanId}`),
  attackChains: (maxLength = 4) =>
    req<AttackChains>(`/graph/attack-chains?max_length=${maxLength}`),
  findingSummary: (scanId?: string) =>
    req<FindingSummary>(`/findings/summary${scanId ? `?scan_id=${scanId}` : ""}`),
  chat: (question: string, scanId?: string) =>
    req<{ answer: string; cited_finding_ids: string[] }>("/chat", {
      method: "POST",
      body: JSON.stringify({ question, scan_id: scanId }),
    }),
};
