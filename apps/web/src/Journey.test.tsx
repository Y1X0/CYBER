// The customer journey, walked through the product UI.
//
// Every other web test holds one screen to one promise. This one is the acceptance test for the
// productization brief's actual target: a customer can go from an empty account to a downloaded
// report *without knowing the API exists*. It drives the real `App` shell — the real navigation,
// the real routing, the real screens — against a fake backend that answers the way the live API
// does, and asserts only on what a person would read.
//
// The scan stage is deliberately the blocked one. This deployment has no worker, so a started scan
// stays `queued` forever; the test asserts the customer is told that plainly and is never shown a
// result. Claiming a completed live scan here would be the exact dishonesty the product forbids.

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { api, setToken } from "./api";

const page = <T,>(rows: T[]) => ({ rows, hasMore: false, nextCursor: null });

const CUSTOMER = { id: "c1", name: "Acme Production", criticality: "high", created_at: DAY(0) };
const ASSET = {
  id: "a1", customer_id: "c1", name: "checkout", kind: "repo",
  identifier: "https://github.com/acme/checkout.git", exposure: "public", created_at: DAY(0),
};
const SCAN = {
  id: "s1", customer_id: "c1", asset_id: "a1", status: "queued", trigger: "manual",
  requested_engines: ["secrets"], stats: {}, started_at: null, finished_at: null,
  created_at: DAY(0),
};
const FINISHED_SCAN = { ...SCAN, id: "s0", status: "completed", stats: { total: 1 } };
const FINDING = {
  id: "f1", title: "AWS access key committed to source", severity: "critical", risk_score: 91,
  status: "open", asset_id: "a1", scan_id: "s0", cwe_id: "CWE-798", owasp_ref: "A07",
  evidence: { file: "config/settings.py", line: "12", excerpt: "AKIA****************" },
  references: {}, created_at: DAY(0),
};

function DAY(offset: number): string {
  // A fixed instant, so nothing here depends on the clock.
  return new Date(Date.UTC(2026, 1, 1 + offset, 9, 0, 0)).toISOString();
}

/** The fake backend. Mutable where the journey changes it, so the UI sees its own effects. */
function backend() {
  const state = {
    assets: [] as (typeof ASSET)[],
    verifications: [] as Record<string, unknown>[],
    authorizations: [] as Record<string, unknown>[],
    scans: [FINISHED_SCAN] as (typeof SCAN)[],
    reports: [] as Record<string, unknown>[],
    remediation: [] as Record<string, unknown>[],
    retests: [] as string[],
  };

  vi.spyOn(api, "me").mockResolvedValue(
    { id: "u1", email: "owner@acme.example", name: "Owner" } as never);
  vi.spyOn(api, "dashboard").mockImplementation(async () => ({
    security_score: 100, severity_counts: {}, total_findings: 0, recent_scans: [],
    open_severity_counts: {}, open_findings: 0,
    assets_total: state.assets.length, assets_by_exposure: {},
    scans_by_status: {}, scans_active: state.scans.filter((s) => s.status === "queued").length,
    scans_completed: state.scans.filter((s) => s.status === "completed").length,
    last_successful_scan_at: null, engine_runs_unresolved: {},
    remediation_by_status: {}, remediation_overdue: 0,
    risk_trend: [], exposure_trend: [], trend_days: 30,
  }) as never);
  vi.spyOn(api, "customers").mockImplementation(async () => page([CUSTOMER]) as never);

  vi.spyOn(api, "assets").mockImplementation(async () => page(state.assets) as never);
  vi.spyOn(api, "createAsset").mockImplementation(async () => {
    state.assets.push(ASSET);
    return ASSET as never;
  });

  vi.spyOn(api, "verifications").mockImplementation(async () => state.verifications as never);
  vi.spyOn(api, "createVerification").mockImplementation(async (_c, domain) => {
    state.verifications.push({
      id: "v1", customer_id: "c1", domain, method: "dns_txt", status: "pending", attempts: 0,
      last_error: null, verified_at: null, expires_at: DAY(30), created_at: DAY(0),
      instructions: {
        record_type: "TXT", record_name: `_guardian-challenge.${domain}`,
        record_value: "guardian-site-verification=abc123",
      },
    });
    return state.verifications[state.verifications.length - 1] as never;
  });

  vi.spyOn(api, "authorizationMethods").mockResolvedValue({
    note: "Verifying a domain proves you control it. It does not by itself authorize every kind " +
          "of scan.",
    methods: [
      { method: "written_consent", label: "Written consent (artifact scanning)",
        permits_network: false, permits_artifact: true,
        summary: "Lets Guardian scan material you supply.",
        requires: "nothing beyond your confirmation" },
      { method: "active_recon", label: "Active testing (network scanning)",
        permits_network: true, permits_artifact: true,
        summary: "Lets Guardian connect to your running systems.",
        requires: "a domain you have already verified" },
    ],
  } as never);
  vi.spyOn(api, "authorizations").mockImplementation(
    async () => page(state.authorizations) as never);
  vi.spyOn(api, "createAuthorization").mockImplementation(async (body) => {
    const row = {
      id: "auth1", customer_id: "c1", asset_id: null, method: body.method, scope: body.scope,
      targets: (body.domains ?? []).map((d: string) => ({ type: "domain", value: d })),
      permits_network: body.method === "active_recon", permits_artifact: true,
      state: "active", valid_from: DAY(0), valid_until: DAY(90), revoked_at: null,
      authorized_by: "owner@acme.example", created_at: DAY(0),
    };
    state.authorizations.push(row);
    return row as never;
  });

  vi.spyOn(api, "scans").mockImplementation(async () => page(state.scans) as never);
  vi.spyOn(api, "scan").mockImplementation(
    async (id) => (state.scans.find((s) => s.id === id) ?? SCAN) as never);
  vi.spyOn(api, "startScan").mockImplementation(async () => {
    state.scans.unshift(SCAN);
    return SCAN as never;
  });
  // No worker: the scan is accepted, nothing executes it, and no engine has run.
  vi.spyOn(api, "scanEngines").mockImplementation(
    async (id) => (id === "s0"
      ? [{ engine: "secrets", status: "completed", customer_state: "checked",
           meaning: "This engine ran and reported everything it found.",
           error: null, degraded: false, missing: [], started_at: DAY(0) }]
      : []) as never);
  vi.spyOn(api, "queueHealth").mockResolvedValue({
    state: "stalled",
    detail: "Guardian has accepted your scan but nothing is executing it. This is an " +
            "infrastructure problem on our side, not a problem with your target — your scan is " +
            "queued and will run when the scanner is available. It has not been lost, and no " +
            "result has been produced.",
    queued: 1, running: 0, oldest_waiting_seconds: 420,
    scanner: { status: "degraded", detail: "the scanner has stopped executing work" },
  } as never);

  // Scoped to a scan, this answers for that scan: the finished one reported a finding, the queued
  // one has reported nothing because nothing has run it.
  vi.spyOn(api, "findings").mockImplementation(async (params = {}) => {
    const scanId = (params as Record<string, string>).scan_id;
    return page(scanId && scanId !== "s0" ? [] : [FINDING]) as never;
  });
  vi.spyOn(api, "findingSummary").mockResolvedValue({
    total: 1, by_severity: { critical: 1 }, by_status: { open: 1 }, by_engine: { secrets: 1 },
    exploitable: 0, correlated: 0, unverified: 1,
  } as never);
  vi.spyOn(api, "finding").mockResolvedValue({
    finding: FINDING,
    asset: { id: "a1", name: "checkout", kind: "repo", exposure: "public",
             identifier: ASSET.identifier },
    scan: { id: "s0" },
    engine: "secrets",
    risk_rationale: ["Internet-facing asset (+15)", "Credential material with a live prefix (+30)"],
    exploit: { kev: false, maturity: null, ransomware: false, epss: null, cvss_base: null },
    correlation: null, related: [], verifications: [], timeline: [],
  } as never);
  vi.spyOn(api, "retest").mockImplementation(async (id) => {
    state.retests.push(id);
    return { scan_id: "s2", engine: "secrets" } as never;
  });

  vi.spyOn(api, "reports").mockImplementation(async () => page(state.reports) as never);
  vi.spyOn(api, "createReport").mockImplementation(async (_scan, title) => {
    state.reports.push({
      id: "r1", scan_id: "s0", title, status: "published",
      summary: { total_findings: 1 }, created_at: DAY(0),
    });
    return state.reports[state.reports.length - 1] as never;
  });

  vi.spyOn(api, "remediation").mockImplementation(async () => state.remediation as never);
  vi.spyOn(api, "remediationSla").mockImplementation(async () => ({
    total: state.remediation.length, active: state.remediation.length, overdue: 0,
    verified: 0, accepted: 0, on_time_rate: 100, by_severity: {},
  }) as never);
  vi.spyOn(api, "openRemediation").mockImplementation(async () => {
    state.remediation.push({
      id: "rem1", finding_id: "f1", finding_title: FINDING.title, severity: "critical",
      status: "open", due_at: DAY(3), overdue: false, justification: null,
      verified_by_scan_id: null, created_at: DAY(0),
    });
    return { opened: 1, existing: 0, grouped: 0, reason: null } as never;
  });

  return state;
}

const go = (label: string) => fireEvent.click(screen.getByRole("button", { name: label }));
const type = (el: HTMLElement, value: string) =>
  fireEvent.change(el, { target: { value } });

beforeEach(() => setToken("journey-token"));
afterEach(() => {
  vi.restoreAllMocks();
  setToken(null);
  window.location.hash = "";
});

describe("a customer, start to finish, without touching the API", () => {
  it("walks from an empty account to a report", async () => {
    const state = backend();
    render(<App />);

    // ── the account is empty, and says so rather than looking reassuring ──────────────────────
    await screen.findByText("Open findings");
    expect(screen.getByText(/queued but nothing is running/i)).toBeInTheDocument();

    // ── 1. add an asset ───────────────────────────────────────────────────────────────────────
    go("Assets");
    expect(await screen.findByText("No assets yet")).toBeInTheDocument();
    go("Add your first asset");
    type(await screen.findByLabelText("Name"), "checkout");
    type(screen.getByLabelText("Identifier"), ASSET.identifier);
    go("Add asset");
    expect(await screen.findByText("checkout")).toBeInTheDocument();
    expect(state.assets).toHaveLength(1);

    // ── 2. prove a domain ─────────────────────────────────────────────────────────────────────
    go("Domains");
    // The screen must not let the customer believe verification is a licence to scan anything.
    expect(await screen.findByText(/does not by itself authorize every kind of scan/i))
      .toBeInTheDocument();
    type(screen.getByLabelText("Domain"), "acme.example");
    go("Start verification");
    // What a customer needs is the record to publish, not a status code.
    expect(await screen.findByText("_guardian-challenge.acme.example")).toBeInTheDocument();
    expect(screen.getByText(/guardian-site-verification=/)).toBeInTheDocument();

    // ── 3. authorize what Guardian may do ─────────────────────────────────────────────────────
    go("Authorization");
    expect(await screen.findByText("Nothing is authorized")).toBeInTheDocument();
    go("Record an authorization");
    type(await screen.findByLabelText("Scope description"), "Pilot assessment");
    type(screen.getByLabelText("Domains (comma separated)"), "acme.example");
    // The grant is refused until somebody takes responsibility for it.
    const record = screen.getByRole("button", { name: "Record authorization" });
    expect(record).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(record);
    expect(await screen.findByText("artifacts only")).toBeInTheDocument();
    expect(state.authorizations).toHaveLength(1);
    expect(state.authorizations[0].method).toBe("written_consent");

    // ── 4. start a scan, and be told the truth about it ───────────────────────────────────────
    go("Assets");
    fireEvent.click(await screen.findByRole("button", { name: "Scan" }));
    fireEvent.click(await screen.findByRole("button", { name: /^Start scan$/ }));

    // Routed to the scan. There is no worker, so this must read as waiting — never as a result.
    expect(await screen.findByText(/waiting and nothing is executing/i)).toBeInTheDocument();
    // Said by the screen itself and echoed by the queue's own explanation.
    expect(screen.getAllByText(/No result has been produced/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/this asset is clean/i)).not.toBeInTheDocument();

    // ── 5. findings, and the dossier behind one ───────────────────────────────────────────────
    go("Findings");
    expect(await screen.findByText(FINDING.title)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open" }));

    expect(await screen.findByText(/91\/100/)).toBeInTheDocument();
    expect(screen.getByText(/Credential material with a live prefix/)).toBeInTheDocument();
    expect(screen.getByText("config/settings.py")).toBeInTheDocument();
    expect(screen.getByText(/never been re-checked/i)).toBeInTheDocument();

    // ── 6. ask for a retest ───────────────────────────────────────────────────────────────────
    fireEvent.click(screen.getByRole("button", { name: "Retest this finding" }));
    await waitFor(() => expect(state.retests).toEqual(["f1"]));
    expect(await screen.findByText(/Retest queued/i)).toBeInTheDocument();

    // ── 7. generate a report ──────────────────────────────────────────────────────────────────
    go("Reports");
    expect(await screen.findByText("No reports yet")).toBeInTheDocument();
    go("Generate report");
    expect(await screen.findByText("Security assessment")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download PDF" })).toBeInTheDocument();
    expect(state.reports).toHaveLength(1);

    // ── 8. open remediation work ──────────────────────────────────────────────────────────────
    go("Remediation");
    expect(await screen.findByText("No remediation work")).toBeInTheDocument();
    go("Open work for open findings");
    expect(await screen.findByText(/Opened 1 item/i)).toBeInTheDocument();
    const row = (await screen.findByText(FINDING.title)).closest("tr")!;
    // The item is tracked, and the one status a person may not set is not on offer: `verified`
    // belongs to a scan that re-checked and did not report the finding again.
    const offered = within(row).getAllByRole("option").map((o) => o.textContent);
    expect(offered).toContain("open");
    expect(offered).not.toContain("verified");
  });

  it("never lets the empty state of a blocked scan read as a clean bill of health", async () => {
    backend();
    // Only the queued scan exists, so "Open" in the list is unambiguous.
    vi.spyOn(api, "scans").mockResolvedValue(page([SCAN]) as never);
    render(<App />);

    go("Scans");
    fireEvent.click(await screen.findByRole("button", { name: "Open" }));

    expect(await screen.findByText("No findings yet")).toBeInTheDocument();
    expect(screen.getByText(/has not finished/i)).toBeInTheDocument();
    expect(screen.queryByText(/this asset is clean/i)).not.toBeInTheDocument();
  });

  it("tells the customer on every screen when the backend cannot answer", async () => {
    // Every route fails. No screen may render as though it had an answer — the one failure mode
    // that turns this product into a liar is a blank panel where a refusal belongs.
    const { ApiError } = await import("./api");
    for (const key of Object.keys(api) as (keyof typeof api)[]) {
      if (typeof api[key] === "function") {
        vi.spyOn(api, key).mockRejectedValue(new ApiError(503, "the backend is unreachable"));
      }
    }
    vi.spyOn(api, "me").mockResolvedValue(
      { id: "u1", email: "owner@acme.example", name: "Owner" } as never);

    render(<App />);
    await screen.findByRole("navigation");

    const screens = ["Dashboard", "Organization", "Assets", "Domains", "Authorization",
                     "Discovery", "Scans", "Findings", "Remediation", "Reports", "Compliance",
                     "Attack paths", "Notifications"];
    for (const label of screens) {
      go(label);
      await waitFor(
        () => expect(
          screen.queryAllByText(/could not be loaded|unreachable|could not be reached/i).length,
        ).toBeGreaterThan(0),
        { timeout: 2000 },
      );
    }
  });

  it("shows the server's refusal when the scan gate says no", async () => {
    const { ApiError } = await import("./api");
    backend();
    vi.spyOn(api, "startScan").mockRejectedValue(new ApiError(
      403, "no authorization covers github.com — record the customer's consent for this artifact"));
    vi.spyOn(api, "assets").mockResolvedValue(page([ASSET]) as never);

    render(<App />);
    go("Assets");
    fireEvent.click(await screen.findByRole("button", { name: "Scan" }));
    fireEvent.click(await screen.findByRole("button", { name: /^Start scan$/ }));

    expect(await screen.findByText(/no authorization covers github.com/i)).toBeInTheDocument();
  });
});
