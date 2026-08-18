import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CompliancePanel } from "./Compliance";
import { Compliance } from "./api";

/**
 * Control coverage (WP-F4).
 *
 * The panel is read by people deciding on behalf of others. Every test here is about the one way it
 * could mislead them: presenting "nobody looked" as "this is fine".
 */

const DATA: Compliance = {
  frameworks: [
    {
      framework: "soc2",
      counts: { failing: 1, passing: 2, not_assessed: 5 },
      coverage: 38,
      engines_assessed: ["secrets"],
      controls: [
        {
          id: "CC6.2",
          title: "Credential management",
          description: "Credentials are issued, protected, and revoked appropriately.",
          status: "failing",
          rationale: "1 open finding(s) map to this control; the most severe is high — AWS key",
          findings: [{ id: "f1", title: "Hardcoded AWS credential", severity: "high" }],
        },
        {
          id: "CC7.2",
          title: "Monitoring and logging",
          description: "System activity is monitored.",
          status: "not_assessed",
          rationale: "not assessed: no engine that can evaluate it ran (cspm, k8s would)",
          findings: [],
        },
        {
          id: "CC6.8",
          title: "Malicious software",
          description: "Unauthorized software is prevented.",
          status: "passing",
          rationale: "assessed by secrets; no finding maps to this control",
          findings: [],
        },
      ],
    },
  ],
  overall_coverage: 38,
  disclaimer:
    "Guardian reports whether a technical control was observed to fail. It does not certify " +
    "compliance: controls that are procedural, or that no engine here can evaluate, are reported " +
    "as not assessed rather than as passing.",
};

function mockFetch(body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: true,
      json: async () => body,
      text: async () => JSON.stringify(body),
    })),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("compliance panel", () => {
  it("shows all three statuses, with 'not assessed' as its own count", async () => {
    mockFetch(DATA);
    render(<CompliancePanel />);

    await waitFor(() => expect(screen.getByText(/1 failing/)).toBeInTheDocument());
    expect(screen.getByText(/2 passing/)).toBeInTheDocument();
    // The count that must never be folded into "passing".
    expect(screen.getByText(/5 not assessed/)).toBeInTheDocument();
  });

  it("prints the coverage percentage next to the counts", async () => {
    // A 100% pass rate over 20% coverage is the number that misleads an auditor, and it only
    // misleads when the denominator is missing.
    mockFetch(DATA);
    render(<CompliancePanel />);

    await waitFor(() =>
      expect(screen.getByText(/38% of controls assessed/)).toBeInTheDocument(),
    );
  });

  it("says which engines did the assessing", async () => {
    mockFetch(DATA);
    render(<CompliancePanel />);

    await waitFor(() => expect(screen.getByText(/Assessed by:/)).toBeInTheDocument());
    // Scoped to the engines line: "secrets" also appears in a control's rationale, and a bare
    // text query would match both and pass for the wrong reason.
    expect(screen.getByText(/Assessed by:/).textContent).toContain("secrets");
  });

  it("explains why an unassessed control is unassessed", async () => {
    mockFetch(DATA);
    render(<CompliancePanel />);

    await waitFor(() =>
      expect(screen.getByText(/no engine that can evaluate it ran/)).toBeInTheDocument(),
    );
    expect(screen.getByText("not assessed")).toBeInTheDocument();
  });

  it("names the findings behind a failing control", async () => {
    mockFetch(DATA);
    render(<CompliancePanel />);

    await waitFor(() =>
      expect(screen.getByText(/Hardcoded AWS credential/)).toBeInTheDocument(),
    );
  });

  it("carries the disclaimer that this is not a certification", async () => {
    mockFetch(DATA);
    render(<CompliancePanel />);

    await waitFor(() =>
      expect(screen.getByText(/does not certify compliance/)).toBeInTheDocument(),
    );
  });

  it("shows no control status at all when the request fails", async () => {
    // An unknown status is not a passing one, and a panel that renders empty after an error reads
    // as "nothing is failing".
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("gateway timeout");
      }),
    );
    render(<CompliancePanel />);

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(screen.getByRole("alert")).toHaveTextContent(/an unknown status is not a passing one/i);
    expect(screen.queryByText("passing")).not.toBeInTheDocument();
  });

  it("says plainly when no engine has run at all", async () => {
    mockFetch({
      frameworks: [
        {
          framework: "soc2",
          counts: { failing: 0, passing: 0, not_assessed: 8 },
          coverage: 0,
          engines_assessed: [],
          controls: [],
        },
      ],
      overall_coverage: 0,
      disclaimer: DATA.disclaimer,
    });
    render(<CompliancePanel />);

    await waitFor(() =>
      expect(screen.getByText(/no engine has run against this scope yet/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/0% of controls assessed/)).toBeInTheDocument();
  });
});
