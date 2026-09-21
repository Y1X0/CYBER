// The finding dossier's E4 "Attack paths" section: staff-only, ordered, and semantically distinct
// from the E1 "Related findings" panel.
//
// These pin the Slice-5 contract: a portal contact never sees it (the section is not rendered and
// the staff-only endpoint is never called), a staff user sees ordered attacker steps with E4's own
// "path reliability" and scores, and none of E1's relationship-confidence vocabulary is reused.

import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AttackChains, api } from "../api";
import { FindingAttackPaths } from "./Findings";

afterEach(() => vi.restoreAllMocks());

const STAFF = { id: "u1", email: "s@x", name: "Analyst", tenant_id: "t1",
                staff_role: "pentester", portal_customer_id: null };
const PORTAL = { id: "u2", email: "p@x", name: "Portal", tenant_id: "t1",
                 staff_role: null, portal_customer_id: "c1" };

const CHAINS: AttackChains = {
  chains: [{
    entry: "shop.example.invalid",
    length: 3,
    likelihood: 61,
    impact: 90,
    score: 74,
    capabilities: ["code_execution", "credential_access"],
    narrative: "An attacker who can reach shop.example.invalid uses `RCE` then uses `Secret`.",
    steps: [
      { finding_id: "f-rce", asset_id: "a1", title: "OS command injection", severity: "critical",
        cwe_id: "CWE-78", grants: ["code_execution"], reliability: 90,
        rationale: "OS command injection runs an attacker's command on the host" },
      { finding_id: "f-secret", asset_id: "a1", title: "Hardcoded AWS credential", severity: "high",
        cwe_id: "CWE-798", grants: ["credential_access"], reliability: 95,
        rationale: "a hardcoded credential authenticates wherever it is valid" },
      { finding_id: "f-iam", asset_id: "a2", title: "Over-permissioned IAM role", severity: "high",
        cwe_id: "CWE-269", grants: ["privilege_escalation"], reliability: 85,
        rationale: "the principal's permissions exceed its purpose" },
    ],
  }],
  truncated: false,
  unchainable_findings: 0,
};

describe("finding attack paths (E4)", () => {
  it("renders nothing for a portal contact and never calls the staff-only endpoint", async () => {
    vi.spyOn(api, "me").mockResolvedValue(PORTAL as never);
    const spy = vi.spyOn(api, "attackChainsForFinding").mockResolvedValue(CHAINS as never);

    const { container } = render(<FindingAttackPaths findingId="f-secret" />);

    await waitFor(() => expect(api.me).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
    expect(spy).not.toHaveBeenCalled();
  });

  it("shows an ordered attack path with E4 reliability and scores for a staff user", async () => {
    vi.spyOn(api, "me").mockResolvedValue(STAFF as never);
    vi.spyOn(api, "attackChainsForFinding").mockResolvedValue(CHAINS as never);

    const { container } = render(<FindingAttackPaths findingId="f-secret" />);

    // Wait for the chain itself to render (the inner loader has resolved).
    expect(await screen.findByText("OS command injection")).toBeInTheDocument();
    expect(screen.getByText("Attack paths")).toBeInTheDocument();
    // E4-specific labels — reliability and score, not an E1 confidence tier.
    const text = container.textContent ?? "";
    expect(text).toContain("Path reliability: 90%");
    expect(text).toContain("Path score 74");
    expect(text).toContain("Likelihood 61%");

    // Ordered steps, in E4's order.
    const steps = screen.getAllByRole("listitem").map((li) => li.textContent ?? "");
    const rce = steps.findIndex((t) => t.includes("OS command injection"));
    const secret = steps.findIndex((t) => t.includes("Hardcoded AWS credential"));
    const iam = steps.findIndex((t) => t.includes("Over-permissioned IAM role"));
    expect(rce).toBeGreaterThanOrEqual(0);
    expect(rce).toBeLessThan(secret);
    expect(secret).toBeLessThan(iam);

    // The focused finding is marked (the step marker, distinct from the intro line).
    expect(screen.getByText(/·\s*this finding/)).toBeInTheDocument();
  });

  it("does not reuse E1 confidence vocabulary or call the path a correlation", async () => {
    vi.spyOn(api, "me").mockResolvedValue(STAFF as never);
    vi.spyOn(api, "attackChainsForFinding").mockResolvedValue(CHAINS as never);

    render(<FindingAttackPaths findingId="f-secret" />);
    await screen.findByText("Attack paths");

    for (const e1 of [/Confirmed relationship/i, /Strong evidence/i, /Potential relationship/i,
                      /Related findings?/i, /correlation/i, /Relationship evidence/i]) {
      expect(screen.queryByText(e1)).toBeNull();
    }
    // No manufactured causal wording (E4 proves ordered participation, not "A causes B").
    for (const causal of [/causes/i, /because of/i, /exploitable because/i]) {
      expect(screen.queryByText(causal)).toBeNull();
    }
    // It is explicitly labelled as an attack path, not a relationship or a confirmed exploit.
    expect(screen.getByText(/not a finding relationship, and not a confirmed exploit/i))
      .toBeInTheDocument();
  });

  it("shows a neutral empty state when the finding is in no chain", async () => {
    vi.spyOn(api, "me").mockResolvedValue(STAFF as never);
    vi.spyOn(api, "attackChainsForFinding").mockResolvedValue(
      { chains: [], truncated: false, unchainable_findings: 0 } as never);

    render(<FindingAttackPaths findingId="f-secret" />);

    expect(await screen.findByText(/does not appear in any computed attack path/i))
      .toBeInTheDocument();
  });

  it("does not claim 'no path' when the computation was truncated", async () => {
    vi.spyOn(api, "me").mockResolvedValue(STAFF as never);
    vi.spyOn(api, "attackChainsForFinding").mockResolvedValue(
      { chains: [], truncated: true, unchainable_findings: 0 } as never);

    render(<FindingAttackPaths findingId="f-secret" />);

    // The honest truncated state, NOT a definitive "no attack path".
    expect(await screen.findByText(/truncated at the computation limit/i)).toBeInTheDocument();
    expect(screen.getByText(/may exist but was not among the chains scored/i)).toBeInTheDocument();
    expect(screen.queryByText(/does not appear in any computed attack path/i)).toBeNull();
  });
});
