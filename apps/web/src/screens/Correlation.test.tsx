// The E1 correlation panel presents finding RELATIONSHIPS — and must never read as an attack path.
//
// These assertions pin the honest semantics the backend persists: the confidence is relationship
// evidence (not vulnerability certainty), members are listed in a neutral order (no "1 → 2 → 3"),
// an edge is labelled "relationship evidence" (never an attack step), and a historical correlation
// with no recorded edge shows a neutral empty state rather than fabricated evidence.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CorrelationConfidence, CorrelationMember, FindingDossier } from "../api";
import { CorrelationCard } from "./Findings";

type Correlation = NonNullable<FindingDossier["correlation"]>;

function member(over: Partial<CorrelationMember> = {}): CorrelationMember {
  return {
    finding_id: over.finding_id ?? crypto.randomUUID(),
    role: over.role ?? "corroborating",
    ordinal: over.ordinal ?? 0,
    edge_source_finding_id: over.edge_source_finding_id ?? null,
    edge_rationale: over.edge_rationale ?? null,
    edge_confidence: over.edge_confidence ?? null,
    title: over.title ?? "A finding",
    category: over.category ?? "secret",
    severity: over.severity ?? "high",
    is_self: over.is_self ?? false,
  };
}

function correlation(over: Partial<Correlation> = {}): Correlation {
  const primaryId = "11111111-1111-1111-1111-111111111111";
  return {
    id: "corr-1",
    rule: over.rule ?? "same-cve-on-asset",
    kind: over.kind ?? "duplicate",
    confidence: over.confidence ?? "strong_evidence",
    severity: "high",
    risk_score: 70,
    rationale: over.rationale ?? [],
    member_count: over.member_count ?? 2,
    created_at: null,
    updated_at: null,
    members: over.members ?? [
      member({ finding_id: primaryId, role: "primary", ordinal: 0, is_self: true,
               title: "The finding you opened" }),
      member({ finding_id: "22222222-2222-2222-2222-222222222222", role: "corroborating",
               ordinal: 1, edge_source_finding_id: primaryId,
               edge_rationale: "Both findings reference the same CVE on the same asset.",
               edge_confidence: "strong_evidence", title: "The sibling finding" }),
    ],
  };
}

describe("correlation panel", () => {
  it("labels the relationship with a human rule name and preserves the machine rule id", () => {
    render(<CorrelationCard correlation={correlation({ rule: "same-cve-on-asset" })} />);
    expect(screen.getByText("Same CVE on the same asset")).toBeInTheDocument();
    expect(screen.getByText("(same-cve-on-asset)")).toBeInTheDocument();
  });

  it("shows the group confidence as relationship evidence, not vulnerability certainty", () => {
    render(<CorrelationCard correlation={correlation({ confidence: "confirmed" })} />);
    expect(screen.getByText("Confirmed relationship")).toBeInTheDocument();
    // The disclaimer keeps 'confirmed' from being read as 'the vulnerability is confirmed'.
    expect(screen.getByText(/not whether the vulnerability is exploitable/i)).toBeInTheDocument();
  });

  it.each<[CorrelationConfidence, string]>([
    ["confirmed", "Confirmed relationship"],
    ["strong_evidence", "Strong evidence"],
    ["potential", "Potential relationship"],
  ])("renders the %s tier as %s", (tier, label) => {
    render(<CorrelationCard correlation={correlation({ confidence: tier })} />);
    expect(screen.getAllByText(label).length).toBeGreaterThan(0);
  });

  it("orders members neutrally and never as an exploitation sequence", () => {
    render(<CorrelationCard correlation={correlation()} />);
    expect(screen.getByText("This finding")).toBeInTheDocument();
    expect(screen.getByText("Related finding 1")).toBeInTheDocument();
    // Explicitly says this is a relationship, not an attack path.
    expect(screen.getByText(/not an attack path/i)).toBeInTheDocument();
    // No causal / attack-sequence language anywhere in the panel.
    for (const causal of [/attack step/i, /exploit →/i, /next target/i, /kill chain/i, /→/]) {
      expect(screen.queryByText(causal)).toBeNull();
    }
  });

  it("renders per-edge relationship evidence with its own confidence", () => {
    render(<CorrelationCard correlation={correlation()} />);
    expect(
      screen.getByText(/Relationship evidence: Both findings reference the same CVE/i),
    ).toBeInTheDocument();
    // Two strong-evidence badges: the group's and the edge's — both present.
    expect(screen.getAllByText("Strong evidence").length).toBe(2);
  });

  it("shows a neutral empty state for a historical correlation with no edge evidence", () => {
    const primaryId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    render(<CorrelationCard correlation={correlation({
      confidence: "potential",
      members: [
        member({ finding_id: primaryId, role: "primary", ordinal: 0, is_self: true }),
        member({ finding_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", role: "duplicate", ordinal: 1,
                 edge_source_finding_id: null, edge_rationale: null, edge_confidence: null }),
      ],
    })} />);
    expect(
      screen.getByText(/Relationship evidence not available for this historical correlation/i),
    ).toBeInTheDocument();
    // Nothing invented: no edge-evidence line rendered for the historical member.
    expect(screen.queryByText(/Relationship evidence: /)).toBeNull();
  });
});
