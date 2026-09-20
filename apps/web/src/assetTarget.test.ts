// The console must guide the operator to a scheme, never guess one — a web/api target fetched over
// the wrong protocol (or none) is unreachable and reads as a clean 0-findings scan.

import { describe, expect, it } from "vitest";
import { targetSchemeHint } from "./screens/Assets";

describe("targetSchemeHint", () => {
  it("is silent when a web/api target already has http(s)://", () => {
    expect(targetSchemeHint("web", "http://testphp.vulnweb.com")).toBeNull();
    expect(targetSchemeHint("web", "https://app.example.com/login")).toBeNull();
    expect(targetSchemeHint("api", "https://api.example.com")).toBeNull();
  });

  it("guides a scheme-less web/api target toward both http and https", () => {
    const hint = targetSchemeHint("web", "testphp.vulnweb.com");
    expect(hint).toContain("http://testphp.vulnweb.com");
    expect(hint).toContain("https://testphp.vulnweb.com");
  });

  it("flags an unsupported scheme", () => {
    expect(targetSchemeHint("web", "ftp://files.example.com")).toContain("http");
  });

  it("does not constrain non-web kinds", () => {
    expect(targetSchemeHint("repo", "git@github.com:acme/app.git")).toBeNull();
    expect(targetSchemeHint("cloud", "acme-prod")).toBeNull();
  });

  it("is silent on an empty target (the rule bites only once one is entered)", () => {
    expect(targetSchemeHint("web", "")).toBeNull();
    expect(targetSchemeHint("web", "   ")).toBeNull();
  });
});
