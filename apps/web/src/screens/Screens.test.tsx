// Behaviour the product promises, asserted screen by screen.
//
// These are deliberately about *what the customer is told*, not about markup. Each one maps to a
// rule from the productization brief: real data only, errors never rendered as emptiness, and the
// authorization screen never implying that verifying a domain authorizes everything.

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api } from "../api";
import { AuthorizationScreen } from "./Authorization";
import { DashboardScreen } from "./Dashboard";
import { FindingsScreen } from "./Findings";
import { AuthScreen } from "./Onboarding";
import { OrganizationScreen } from "./Organization";
import { RemediationScreen } from "./Remediation";

afterEach(() => vi.restoreAllMocks());

const page = (rows: unknown[]) => ({ rows, hasMore: false, nextCursor: null });

/** Type into a controlled input the way React sees it. */
function type(el: HTMLElement, value: string) {
  fireEvent.change(el, { target: { value } });
}

const DASH = {
  security_score: 62,
  severity_counts: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
  total_findings: 3,
  recent_scans: [],
  open_severity_counts: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
  open_findings: 3,
  assets_total: 4,
  assets_by_exposure: { public: 3, internal: 1 },
  scans_by_status: { completed: 5, queued: 1 },
  scans_active: 1,
  scans_completed: 5,
  last_successful_scan_at: "2026-02-01T10:00:00Z",
  engine_runs_unresolved: {},
  remediation_by_status: {},
  remediation_overdue: 0,
  risk_trend: [],
  exposure_trend: [],
  trend_days: 30,
};

describe("dashboard", () => {
  it("renders the numbers the API returned, not invented ones", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue(DASH as never);
    vi.spyOn(api, "queueHealth").mockResolvedValue({ state: "idle", detail: "" } as never);

    render(<DashboardScreen />);

    await waitFor(() => expect(screen.getByText("Open findings")).toBeInTheDocument());
    expect(screen.getByText("4")).toBeInTheDocument();          // assets_total
    expect(screen.getByText(/Security score 62\/100/)).toBeInTheDocument();
  });

  it("warns that engines which did not answer are not clean results", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue(
      { ...DASH, engine_runs_unresolved: { failed: 2, skipped: 1 } } as never);
    vi.spyOn(api, "queueHealth").mockResolvedValue({ state: "idle", detail: "" } as never);

    render(<DashboardScreen />);

    expect(await screen.findByText(/did not answer/i)).toBeInTheDocument();
    expect(screen.getByText(/unknown, not clean/i)).toBeInTheDocument();
  });

  it("says so when nothing has ever completed rather than showing a reassuring blank", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue(
      { ...DASH, last_successful_scan_at: null, total_findings: 0 } as never);
    vi.spyOn(api, "queueHealth").mockResolvedValue({ state: "idle", detail: "" } as never);

    render(<DashboardScreen />);

    expect(await screen.findByText(/never — nothing has completed yet/i)).toBeInTheDocument();
    expect(screen.getByText(/not a clean bill of health/i)).toBeInTheDocument();
  });

  it("tells the customer when their scans are queued and nothing is running", async () => {
    vi.spyOn(api, "dashboard").mockResolvedValue(DASH as never);
    vi.spyOn(api, "queueHealth").mockResolvedValue({
      state: "stalled", detail: "nothing is executing it", queued: 2, running: 0,
      oldest_waiting_seconds: 600, scanner: { status: "degraded", detail: "" },
    } as never);

    render(<DashboardScreen />);

    expect(await screen.findByText(/queued but nothing is running/i)).toBeInTheDocument();
  });
});

describe("authorization", () => {
  const METHODS = {
    note: "Verifying a domain proves you control it. It does not by itself authorize every kind " +
          "of scan.",
    methods: [
      { method: "written_consent", label: "Written consent (artifact scanning)",
        permits_network: false, permits_artifact: true, summary: "Artifacts only.",
        requires: "your confirmation" },
      { method: "active_recon", label: "Active testing (network scanning)",
        permits_network: true, permits_artifact: true, summary: "Connects to your systems.",
        requires: "a domain you have already verified" },
    ],
  };

  it("never implies that verifying a domain authorizes every scan", async () => {
    vi.spyOn(api, "authorizationMethods").mockResolvedValue(METHODS as never);
    vi.spyOn(api, "authorizations").mockResolvedValue(page([]) as never);
    vi.spyOn(api, "customers").mockResolvedValue(page([]) as never);

    render(<AuthorizationScreen />);

    expect(await screen.findByText(/does not by itself authorize every kind of scan/i))
      .toBeInTheDocument();
    expect(screen.getByText(/a domain you have already verified/i)).toBeInTheDocument();
  });

  it("distinguishes an artifact grant from one that touches running systems", async () => {
    vi.spyOn(api, "authorizationMethods").mockResolvedValue(METHODS as never);
    vi.spyOn(api, "customers").mockResolvedValue(page([]) as never);
    vi.spyOn(api, "authorizations").mockResolvedValue(page([
      {
        id: "a1", customer_id: "c", asset_id: null, method: "written_consent",
        scope: "Repo review", targets: [], permits_network: false, permits_artifact: true,
        state: "active", valid_from: null, valid_until: "2026-06-01T00:00:00Z",
        revoked_at: null, authorized_by: "owner@example.com", created_at: "2026-01-01T00:00:00Z",
      },
      {
        id: "a2", customer_id: "c", asset_id: null, method: "active_recon",
        scope: "External test", targets: [{ type: "domain", value: "example.com" }],
        permits_network: true, permits_artifact: true, state: "active",
        valid_from: null, valid_until: "2026-06-01T00:00:00Z", revoked_at: null,
        authorized_by: "owner@example.com", created_at: "2026-01-01T00:00:00Z",
      },
    ]) as never);

    render(<AuthorizationScreen />);

    // "network + artifacts" is only ever said about a grant, never about a method on offer.
    expect(await screen.findByText("network + artifacts")).toBeInTheDocument();
    expect(screen.getAllByText("artifacts only").length).toBeGreaterThan(0);
    // The responsible identity is on screen, not buried in an audit log.
    expect(screen.getAllByText("owner@example.com").length).toBe(2);
  });
});

describe("organization", () => {
  function stub(over: {
    verifications?: unknown[]; authorizations?: unknown[];
  } = {}) {
    vi.spyOn(api, "me").mockResolvedValue({
      id: "u1", email: "owner@acme.example", name: "Owner", tenant_id: "t1",
      staff_role: "owner", portal_customer_id: null,
    } as never);
    vi.spyOn(api, "customers").mockResolvedValue(
      page([{ id: "c1", name: "Acme Production", criticality: "high" }]) as never);
    vi.spyOn(api, "assets").mockResolvedValue(page([]) as never);
    vi.spyOn(api, "verifications").mockResolvedValue((over.verifications ?? []) as never);
    vi.spyOn(api, "authorizations").mockResolvedValue(page(over.authorizations ?? []) as never);
  }

  it("counts proof of control and granted permission separately", async () => {
    stub({
      verifications: [{ id: "v1", customer_id: "c1", domain: "acme.example", method: "dns_txt",
                        status: "verified", attempts: 1, last_error: null,
                        expires_at: null, verified_at: "2026-02-01T00:00:00Z",
                        authorization_id: null, instructions: null }],
      authorizations: [],
    });

    render(<OrganizationScreen />);

    // One verified domain, zero authorizations — and the screen must not let those blur together.
    expect(await screen.findByText("Verified domains")).toBeInTheDocument();
    expect(screen.getByText("Active authorizations")).toBeInTheDocument();
    expect(screen.getByText(/authorizes nothing on its own/i)).toBeInTheDocument();
    expect(screen.getByText(/Nothing is authorized/i)).toBeInTheDocument();
  });

  it("does not claim a count it has not loaded", async () => {
    stub();
    vi.spyOn(api, "verifications").mockRejectedValue(new ApiError(503, "unreachable"));

    render(<OrganizationScreen />);

    // A failed count renders as unknown, never as zero — zero would read as "no domains verified".
    await waitFor(() => expect(screen.getAllByText("—").length).toBeGreaterThan(0));
    expect(await screen.findByText("This could not be loaded")).toBeInTheDocument();
  });
});

describe("findings", () => {
  const SUMMARY = {
    total: 0, by_severity: {}, by_status: {}, by_engine: {},
    exploitable: 0, correlated: 0, unverified: 0,
  };

  it("shows the server's reason instead of an empty table", async () => {
    vi.spyOn(api, "findings").mockRejectedValue(new ApiError(503, "the database is unreachable"));
    vi.spyOn(api, "findingSummary").mockResolvedValue(SUMMARY as never);

    render(<FindingsScreen />);

    expect(await screen.findByText("This could not be loaded")).toBeInTheDocument();
    expect(screen.getByText("the database is unreachable")).toBeInTheDocument();
  });

  it("does not present an empty list as proof of safety", async () => {
    vi.spyOn(api, "findings").mockResolvedValue(page([]) as never);
    vi.spyOn(api, "findingSummary").mockResolvedValue(SUMMARY as never);

    render(<FindingsScreen />);

    expect(await screen.findByText(/not the same as being clean/i)).toBeInTheDocument();
  });
});

describe("remediation", () => {
  const SLA = {
    total: 0, active: 0, overdue: 0, verified: 0, accepted: 0, on_time_rate: 100, by_severity: {},
  };

  it("shows why nothing was opened rather than a silent success", async () => {
    vi.spyOn(api, "remediation").mockResolvedValue([] as never);
    vi.spyOn(api, "remediationSla").mockResolvedValue(SLA as never);
    vi.spyOn(api, "me").mockResolvedValue({ id: "u1", email: "o@x" } as never);
    vi.spyOn(api, "customers").mockResolvedValue(page([{ id: "c1", name: "Acme" }]) as never);
    vi.spyOn(api, "openRemediation").mockResolvedValue({
      opened: 0, existing: 2, grouped: 0,
      reason: "every one of the 2 trackable finding(s) is already tracked",
    } as never);

    render(<RemediationScreen />);
    fireEvent.click(await screen.findByRole("button", { name: /open work/i }));

    expect(await screen.findByText(/already tracked/i)).toBeInTheDocument();
  });

  it("explains that only a scan can mark work verified", async () => {
    vi.spyOn(api, "remediation").mockResolvedValue([] as never);
    vi.spyOn(api, "remediationSla").mockResolvedValue(SLA as never);
    vi.spyOn(api, "me").mockResolvedValue({ id: "u1", email: "o@x" } as never);
    vi.spyOn(api, "customers").mockResolvedValue(page([]) as never);

    render(<RemediationScreen />);

    expect(await screen.findByText(/Only a scan that re-checks/i)).toBeInTheDocument();
  });

  it("lets a person take ownership of an item and shows its clock", async () => {
    const item = {
      id: "rem1", finding_id: "f1", customer_id: "c1", status: "open", assignee_id: null,
      due_at: "2026-03-01T00:00:00Z", overdue: false, justification: null,
      verified_by_scan_id: null, finding_title: "Exposed key", severity: "critical",
      risk_score: 90,
    };
    vi.spyOn(api, "remediation").mockResolvedValue([item] as never);
    vi.spyOn(api, "remediationSla").mockResolvedValue(
      { ...SLA, total: 1, active: 1, overdue: 1, on_time_rate: 0 } as never);
    vi.spyOn(api, "me").mockResolvedValue({ id: "u1", email: "o@x" } as never);
    vi.spyOn(api, "customers").mockResolvedValue(page([]) as never);
    const update = vi.spyOn(api, "updateRemediation").mockResolvedValue(item as never);

    render(<RemediationScreen />);

    expect(await screen.findByText("Overdue")).toBeInTheDocument();
    expect(screen.getByText("nobody")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Take" }));
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith("rem1", { assignee_id: "u1" }));
  });

  it("does not let a failed clock read as work that is on time", async () => {
    vi.spyOn(api, "remediation").mockResolvedValue([] as never);
    vi.spyOn(api, "me").mockResolvedValue({ id: "u1", email: "o@x" } as never);
    vi.spyOn(api, "customers").mockResolvedValue(page([]) as never);
    vi.spyOn(api, "remediationSla").mockRejectedValue(new ApiError(500, "the clock is down"));

    render(<RemediationScreen />);

    expect(await screen.findByText(/should be read as on time/i)).toBeInTheDocument();
    expect(screen.getByText(/the clock is down/)).toBeInTheDocument();
  });
});

describe("sign-up", () => {
  function openSignup() {
    render(<AuthScreen onAuthed={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /create an organization/i }));
  }

  it("states that creating an organization grants Guardian nothing", () => {
    openSignup();

    expect(screen.getByText(/does not let Guardian scan anything/i)).toBeInTheDocument();
  });

  it("surfaces the server's refusal on sign-up", async () => {
    vi.spyOn(api, "signup").mockRejectedValue(
      new ApiError(409, "that address cannot be used to create an organization"));

    openSignup();
    type(screen.getByLabelText(/^organization/i), "Acme");
    type(screen.getByLabelText(/^email/i), "a@example.com");
    type(screen.getByLabelText(/^password/i), "correct horse battery");
    fireEvent.click(screen.getByRole("button", { name: /^create organization$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/cannot be used/i);
  });
});
