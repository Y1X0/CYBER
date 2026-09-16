// The plain-language layer must explain a finding without inventing facts about it, and must fall
// back sensibly when there is no CWE mapping. It never changes the finding — only how it reads.

import { describe, expect, it } from "vitest";
import { Finding } from "./api";
import { explainFinding } from "./findingExplain";

function finding(over: Partial<Finding>): Finding {
  return {
    id: "f", title: "x", severity: "high", risk_score: 50, status: "open",
    cwe_id: null, owasp_ref: null, evidence: {}, references: {}, ...over,
  };
}

describe("explainFinding", () => {
  it("explains a known CWE in plain words", () => {
    const ex = explainFinding(finding({ cwe_id: "CWE-306", title: "Missing Authentication" }));
    expect(ex.whatItMeans.toLowerCase()).toContain("without any credentials");
    expect(ex.whatToDo.toLowerCase()).toContain("require authentication");
    expect(ex.whyItMatters).toBeTruthy();
  });

  it("falls back to the category when there is no CWE", () => {
    const ex = explainFinding(finding({ cwe_id: null, category: "vuln-dep" }));
    expect(ex.whatItMeans.toLowerCase()).toContain("dependency");
    expect(ex.whatToDo.toLowerCase()).toContain("upgrade");
  });

  it("uses the description and its Remediation: section when nothing else maps", () => {
    const ex = explainFinding(finding({
      cwe_id: null, category: "other",
      description: "The server exposes its version banner. Remediation: hide the Server header.",
    }));
    expect(ex.whatItMeans).toContain("version banner");
    expect(ex.whatToDo).toContain("hide the Server header");
  });

  it("falls back to a severity-based 'why it matters' with no mapping at all", () => {
    const ex = explainFinding(finding({ severity: "critical" }));
    expect(ex.whyItMatters.toLowerCase()).toContain("critical");
    expect(ex.whatToDo).toBeTruthy();
  });

  it("composes a Location line from evidence, never a bare field", () => {
    expect(explainFinding(finding({ evidence: { endpoint: "GET /api/users" } })).where)
      .toBe("Endpoint GET /api/users");
    expect(explainFinding(finding({ evidence: { file: "config/settings.py", line: "12" } })).where)
      .toBe("File config/settings.py:12");
    expect(explainFinding(finding({ evidence: { package: "flask", version: "2.0.1" } })).where)
      .toBe("Component flask@2.0.1");
    expect(explainFinding(finding({ evidence: {} })).where).toBe("");
  });
});
