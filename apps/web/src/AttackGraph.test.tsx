import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AttackGraph } from "./AttackGraph";
import { AttackChains } from "./api";

/**
 * The attack-graph view (WP-F3).
 *
 * This is the one screen where a presentation mistake is a security problem: a customer who reads
 * "no attack paths" walks away believing something. So the tests are mostly about what the view
 * must never imply.
 */

const CHAIN: AttackChains = {
  chains: [
    {
      entry: "app.example.com",
      length: 3,
      likelihood: 73,
      impact: 95,
      score: 84,
      capabilities: ["code_execution", "credential_access", "privilege_escalation"],
      narrative:
        "An attacker who can reach app.example.com uses `OS command injection` (CWE-78); then uses " +
        "`Hardcoded AWS credential` (CWE-798); then uses `IAM role has admin` (CWE-269).",
      steps: [
        {
          finding_id: "f-rce",
          asset_id: "a-web",
          title: "OS command injection in `host`",
          severity: "critical",
          cwe_id: "CWE-78",
          grants: ["code_execution"],
          reliability: 90,
          rationale: "OS command injection runs an attacker's command on the host",
        },
        {
          finding_id: "f-secret",
          asset_id: "a-web",
          title: "Hardcoded AWS credential",
          severity: "high",
          cwe_id: "CWE-798",
          grants: ["credential_access"],
          reliability: 95,
          rationale: "a hardcoded credential authenticates wherever it is valid",
        },
        {
          finding_id: "f-iam",
          asset_id: "a-cloud",
          title: "IAM role has full administrative access",
          severity: "high",
          cwe_id: "CWE-269",
          grants: ["privilege_escalation", "lateral_movement"],
          reliability: 85,
          rationale: "the principal's permissions exceed its purpose",
        },
      ],
    },
  ],
  truncated: false,
  unchainable_findings: 0,
};

function mockFetch(body: unknown, ok = true) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok,
      json: async () => body,
      text: async () => JSON.stringify(body),
    })),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("attack graph", () => {
  it("renders every hop of a chain, in order, with the finding each rests on", async () => {
    mockFetch(CHAIN);
    render(<AttackGraph />);

    await waitFor(() => expect(screen.getByText(/OS command injection/)).toBeInTheDocument());
    expect(screen.getByText(/Hardcoded AWS credential/)).toBeInTheDocument();
    expect(screen.getByText(/IAM role has full administrative access/)).toBeInTheDocument();

    // Order matters: a chain read out of sequence describes a different attack.
    const html = document.body.innerHTML;
    expect(html.indexOf("OS command injection")).toBeLessThan(html.indexOf("Hardcoded AWS"));
    expect(html.indexOf("Hardcoded AWS")).toBeLessThan(html.indexOf("IAM role has full"));
  });

  it("shows the deterministic score, likelihood and impact", async () => {
    mockFetch(CHAIN);
    render(<AttackGraph />);

    await waitFor(() => expect(screen.getByText("84")).toBeInTheDocument());
    expect(screen.getByText(/73% likelihood/)).toBeInTheDocument();
    expect(screen.getByText(/impact 95/)).toBeInTheDocument();
  });

  it("says what the attacker ends up able to do, in words", async () => {
    mockFetch(CHAIN);
    render(<AttackGraph />);

    await waitFor(() =>
      expect(screen.getByText(/run code/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/hold a credential/)).toBeInTheDocument();
  });

  it("never renders a failed request as an empty graph", async () => {
    // The failure this test exists for: "no attack paths found" and "the server did not answer"
    // look identical to a customer if the error is swallowed, and only one means they are fine.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    render(<AttackGraph />);

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(screen.getByRole("alert")).toHaveTextContent(/could not be loaded/);
    expect(screen.getByRole("alert")).toHaveTextContent(/not a statement that there are none/);
    expect(screen.queryByText(/No attack chain was found/)).not.toBeInTheDocument();
  });

  it("qualifies an empty result with what could not be reasoned about", async () => {
    mockFetch({ chains: [], truncated: false, unchainable_findings: 12 });
    render(<AttackGraph />);

    await waitFor(() =>
      expect(screen.getByText(/No attack chain was found/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/12 finding\(s\) could not be reasoned about/)).toBeInTheDocument();
    expect(screen.getByText(/not a clean bill of health/)).toBeInTheDocument();
  });

  it("reports a truncated result rather than presenting it as complete", async () => {
    mockFetch({ ...CHAIN, truncated: true });
    render(<AttackGraph />);

    await waitFor(() =>
      expect(screen.getByText(/more exist than were returned/)).toBeInTheDocument(),
    );
  });

  it("shows an empty graph as empty only when the request actually succeeded", async () => {
    mockFetch({ chains: [], truncated: false, unchainable_findings: 0 });
    render(<AttackGraph />);

    await waitFor(() =>
      expect(screen.getByText(/No attack chain was found/)).toBeInTheDocument(),
    );
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
