// Typed client for the Guardian API.
//
// One rule governs this file: an error is never turned into an empty result. `request` throws an
// `ApiError` carrying the server's own message, and every screen renders that message. A catch that
// returns `[]` would show a customer an empty findings table when the real answer was "your session
// expired" or "the database is unreachable" — which is the single most dangerous thing security
// software can do.

let token: string | null = localStorage.getItem("guardian_token");

export function getToken(): string | null {
  return token;
}
export function setToken(t: string | null) {
  token = t;
  if (t) localStorage.setItem("guardian_token", t);
  else localStorage.removeItem("guardian_token");
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

/** Pull the human-readable reason out of a FastAPI error body. */
function reason(status: number, body: string): string {
  try {
    const parsed = JSON.parse(body);
    const detail = parsed.detail ?? parsed.message;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail.length) {
      return detail.map((d: { loc?: string[]; msg?: string }) =>
        `${(d.loc ?? []).slice(1).join(".")}: ${d.msg ?? ""}`.trim()).join("; ");
    }
  } catch { /* not JSON — fall through to the raw body */ }
  return body.slice(0, 300) || `request failed with status ${status}`;
}

export interface Page<T> {
  rows: T[];
  hasMore: boolean;
  nextCursor: string | null;
}

async function raw(path: string, opts: RequestInit = {}): Promise<Response> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  let resp: Response;
  try {
    resp = await fetch(`/api/v1${path}`, { ...opts, headers: { ...headers, ...opts.headers } });
  } catch (e) {
    // A network failure is a state the customer must see, not an empty list.
    throw new ApiError(0, `Could not reach Guardian: ${(e as Error).message}`);
  }
  if (!resp.ok) throw new ApiError(resp.status, reason(resp.status, await resp.text()));
  return resp;
}

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const resp = await raw(path, opts);
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

async function paged<T>(path: string, opts: RequestInit = {}): Promise<Page<T>> {
  const resp = await raw(path, opts);
  return {
    rows: (await resp.json()) as T[],
    hasMore: resp.headers.get("X-Has-More") === "true",
    nextCursor: resp.headers.get("X-Next-Cursor"),
  };
}

// ── types ────────────────────────────────────────────────────────────────────────────────────────
export interface Scan {
  id: string;
  customer_id: string;
  asset_id: string;
  status: string;
  trigger: string;
  requested_engines: string[];
  stats: Record<string, number>;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface EngineRun {
  engine: string;
  status: string;
  customer_state: "checked" | "not_checked" | "inconclusive" | "running" | "queued";
  meaning: string;
  error: string | null;
  degraded: boolean;
  missing: string[];
  started_at: string | null;
}

export interface QueueHealth {
  state: "working" | "stalled" | "idle";
  detail: string;
  queued: number;
  running: number;
  oldest_waiting_seconds: number;
  scanner: { status: string; detail: string };
}

export interface Finding {
  id: string;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
  category?: string;
  cwe_id: string | null;
  owasp_ref: string | null;
  evidence: Record<string, unknown>;
  references: Record<string, unknown>;
  asset_id?: string;
  scan_id?: string;
  created_at?: string;
}

export interface FindingDossier {
  finding: Finding;
  asset: Record<string, string>;
  scan: Record<string, string>;
  engine: string | null;
  risk_rationale: string[];
  exploit: {
    kev: boolean; maturity: string | null; ransomware: boolean;
    epss: number | null; cvss_base: number | null;
  };
  correlation: null | {
    id: string; rule: string; kind: string; severity: string;
    risk_score: number; rationale: string[]; member_count: number;
  };
  related: Finding[];
  verifications: {
    checked_at: string | null; verdict: string; rationale: string;
    engine: string | null; scan_id: string | null;
  }[];
  timeline: {
    at: string | null; from_status: string | null; to_status: string; note: string;
  }[];
}

export interface Asset {
  id: string;
  customer_id: string;
  name: string;
  kind: string;
  identifier: string;
  exposure: string;
  created_at?: string;
}

export interface Customer {
  id: string;
  name: string;
  criticality: string;
}

export interface Verification {
  id: string;
  customer_id: string;
  domain: string;
  method: string;
  status: string;
  attempts: number;
  last_error: string | null;
  expires_at: string | null;
  verified_at: string | null;
  authorization_id: string | null;
  instructions: null | {
    method: string; record_type: string; record_name: string;
    record_value: string; note: string;
  };
}

export interface Authorization {
  id: string;
  customer_id: string;
  asset_id: string | null;
  method: string;
  scope: string;
  targets: { type: string; value: string }[];
  permits_network: boolean;
  permits_artifact: boolean;
  state: "active" | "expired" | "revoked" | "pending";
  valid_from: string | null;
  valid_until: string | null;
  revoked_at: string | null;
  authorized_by: string;
  created_at: string;
}

export interface AuthorizationMethod {
  method: string;
  label: string;
  permits_network: boolean;
  permits_artifact: boolean;
  summary: string;
  requires: string;
}

export interface RemediationItem {
  id: string;
  finding_id: string;
  customer_id: string;
  status: string;
  assignee_id: string | null;
  due_at: string | null;
  overdue: boolean;
  justification: string | null;
  verified_by_scan_id: string | null;
  finding_title: string;
  severity: string;
  risk_score: number;
}

export interface Report {
  id: string;
  scan_id: string;
  customer_id: string;
  title: string;
  status: string;
  summary: Record<string, unknown>;
  created_at: string;
}

export interface WebhookEndpoint {
  id: string;
  url: string;
  description: string;
  events: string[];
  enabled: boolean;
  disabled_reason: string | null;
  consecutive_failures: number;
  last_success_at: string | null;
  secret?: string;
  note?: string;
}

export interface Dashboard {
  security_score: number;
  severity_counts: Record<string, number>;
  total_findings: number;
  recent_scans: Scan[];
  open_severity_counts: Record<string, number>;
  open_findings: number;
  assets_total: number;
  assets_by_exposure: Record<string, number>;
  scans_by_status: Record<string, number>;
  scans_active: number;
  scans_completed: number;
  last_successful_scan_at: string | null;
  engine_runs_unresolved: Record<string, number>;
  remediation_by_status: Record<string, number>;
  remediation_overdue: number;
  risk_trend: { day: string; severity: string; count: number }[];
  exposure_trend: { day: string; exposure: string; count: number }[];
  trend_days: number;
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

// ── WP-E4 attack chains ──────────────────────────────────────────────────────────────────────────
export interface ChainStep {
  finding_id: string; asset_id: string; title: string; severity: string;
  cwe_id: string | null; grants: string[]; reliability: number; rationale: string;
}
export interface AttackChain {
  entry: string; length: number; likelihood: number; impact: number; score: number;
  capabilities: string[]; narrative: string; steps: ChainStep[];
}
export interface AttackChains {
  chains: AttackChain[];
  truncated: boolean;
  /** Findings whose class maps to no capability. "No attack path" and "we could not reason about
   *  these" are different statements, and the UI must show both. */
  unchainable_findings: number;
}

// ── WP-F4 compliance ─────────────────────────────────────────────────────────────────────────────
export interface ComplianceControl {
  id: string; title: string; description: string; status: string; rationale: string;
  findings: { id: string; title: string; severity: string }[];
}
export interface ComplianceFramework {
  framework: string; counts: Record<string, number>; coverage: number;
  engines_assessed: string[]; controls: ComplianceControl[];
}
export interface Compliance {
  frameworks: ComplianceFramework[];
  overall_coverage: number;
  disclaimer: string;
}

export interface Me {
  id: string; email: string; name: string;
  tenant_id: string; staff_role: string | null; portal_customer_id: string | null;
}

export const api = {
  // ── identity ──────────────────────────────────────────────────────────────────────────────────
  async login(email: string, password: string): Promise<void> {
    const r = await req<{ access_token: string }>(
      "/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
    setToken(r.access_token);
  },
  async signup(body: {
    email: string; password: string; name: string; organization: string; company: string;
  }): Promise<{ tenant_id: string; customer_id: string }> {
    const r = await req<{ access_token: string; tenant_id: string; customer_id: string }>(
      "/auth/signup", { method: "POST", body: JSON.stringify(body) });
    setToken(r.access_token);
    return { tenant_id: r.tenant_id, customer_id: r.customer_id };
  },
  me: () => req<Me>("/auth/me"),

  // ── organization ──────────────────────────────────────────────────────────────────────────────
  customers: () => paged<Customer>("/customers"),
  createCustomer: (name: string, criticality: string) =>
    req<Customer>("/customers", { method: "POST", body: JSON.stringify({ name, criticality }) }),

  // ── assets ────────────────────────────────────────────────────────────────────────────────────
  assets: (cursor?: string) =>
    paged<Asset>(`/assets${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`),
  createAsset: (body: {
    customer_id: string; name: string; kind: string; identifier: string; exposure: string;
  }) => req<Asset>("/assets", { method: "POST", body: JSON.stringify(body) }),

  // ── ownership ─────────────────────────────────────────────────────────────────────────────────
  verifications: () => req<Verification[]>("/verifications"),
  createVerification: (customer_id: string, domain: string, method: string) =>
    req<Verification>("/verifications",
      { method: "POST", body: JSON.stringify({ customer_id, domain, method }) }),
  checkVerification: (id: string) =>
    req<Verification>(`/verifications/${id}/check`, { method: "POST" }),

  // ── authorization ─────────────────────────────────────────────────────────────────────────────
  authorizations: () => paged<Authorization>("/authorizations"),
  authorizationMethods: () =>
    req<{ methods: AuthorizationMethod[]; note: string }>("/authorizations/methods"),
  createAuthorization: (body: {
    customer_id: string; method: string; scope: string; domains: string[];
    asset_id?: string | null; validity_days: number; reference: string;
  }) => req<Authorization>("/authorizations", { method: "POST", body: JSON.stringify(body) }),
  revokeAuthorization: (id: string) => req<void>(`/authorizations/${id}`, { method: "DELETE" }),

  // ── discovery ─────────────────────────────────────────────────────────────────────────────────
  startDiscovery: (customer_id: string, domains: string[]) =>
    req<{ id: string; status: string }>("/discovery/runs", {
      method: "POST",
      body: JSON.stringify({ customer_id, seeds: { domains }, providers: ["dns"] }),
    }),
  discoveryRuns: () => paged<{ id: string; status: string; created_at: string; stats: unknown }>(
    "/discovery/runs"),

  // ── scans ─────────────────────────────────────────────────────────────────────────────────────
  scans: (cursor?: string) =>
    paged<Scan>(`/scans${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`),
  scan: (id: string) => req<Scan>(`/scans/${id}`),
  scanEngines: (id: string) => req<EngineRun[]>(`/scans/${id}/engines`),
  queueHealth: () => req<QueueHealth>("/scans/queue-health"),
  startScan: (asset_id: string, engines: string[]) =>
    req<Scan>("/scans", {
      method: "POST",
      body: JSON.stringify({ asset_id, engines, trigger: "manual" }),
    }),

  // ── findings ──────────────────────────────────────────────────────────────────────────────────
  findings: (params: Record<string, string> = {}) => {
    const q = new URLSearchParams(params).toString();
    return paged<Finding>(`/findings${q ? `?${q}` : ""}`);
  },
  finding: (id: string) => req<FindingDossier>(`/findings/${id}`),
  findingSummary: (scanId?: string) =>
    req<FindingSummary>(`/findings/summary${scanId ? `?scan_id=${scanId}` : ""}`),
  triage: (id: string, status: string, note: string) =>
    req<Finding>(`/findings/${id}`, {
      method: "PATCH", body: JSON.stringify({ status, note }),
    }),
  retest: (id: string) =>
    req<{ status: string; scan_id: string; engine: string }>(
      `/findings/${id}/retest`, { method: "POST" }),

  // ── reports ───────────────────────────────────────────────────────────────────────────────────
  reports: () => paged<Report>("/reports"),
  createReport: (scan_id: string, title: string) =>
    req<Report>("/reports", { method: "POST", body: JSON.stringify({ scan_id, title }) }),
  reportExportUrl: (id: string, format: string) =>
    `/api/v1/reports/${id}/export?format=${format}`,
  async downloadReport(id: string, format: string): Promise<Blob> {
    const resp = await raw(`/reports/${id}/export?format=${format}`);
    return resp.blob();
  },

  // ── remediation ───────────────────────────────────────────────────────────────────────────────
  remediation: (status?: string) =>
    req<RemediationItem[]>(`/remediation${status ? `?status=${status}` : ""}`),
  openRemediation: (customer_id: string) =>
    req<{ opened: number; existing: number; grouped: number; reason?: string }>(
      "/remediation", { method: "POST", body: JSON.stringify({ customer_id }) }),
  updateRemediation: (id: string, body: { status?: string; justification?: string }) =>
    req<RemediationItem>(`/remediation/${id}`, { method: "PATCH", body: JSON.stringify(body) }),

  // ── notifications ─────────────────────────────────────────────────────────────────────────────
  webhooks: () => paged<WebhookEndpoint>("/webhook-endpoints"),
  webhookEvents: () => req<{ events: string[]; note: string }>("/webhook-endpoints/events"),
  createWebhook: (url: string, events: string[], description: string) =>
    req<WebhookEndpoint>("/webhook-endpoints", {
      method: "POST", body: JSON.stringify({ url, events, description }),
    }),
  deleteWebhook: (id: string) => req<void>(`/webhook-endpoints/${id}`, { method: "DELETE" }),
  webhookDeliveries: (id: string) =>
    req<{ id: string; event: string; status: string; attempts: number;
          response_status: number | null; error: string | null;
          delivered_at: string | null; next_attempt_at: string | null }[]>(
      `/webhook-endpoints/${id}/deliveries`),

  // ── analysis ──────────────────────────────────────────────────────────────────────────────────
  attackChains: (maxLength = 4) =>
    req<AttackChains>(`/graph/attack-chains?max_length=${maxLength}`),
  compliance: (framework?: string) =>
    req<Compliance>(`/compliance${framework ? `?framework=${framework}` : ""}`),
  dashboard: (customerId?: string) =>
    req<Dashboard>(`/dashboard${customerId ? `?customer_id=${customerId}` : ""}`),
  chat: (question: string, scanId?: string) =>
    req<{ answer: string; cited_finding_ids: string[] }>("/chat", {
      method: "POST", body: JSON.stringify({ question, scan_id: scanId }),
    }),
};
