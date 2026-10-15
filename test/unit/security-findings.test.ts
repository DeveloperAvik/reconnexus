import { describe, expect, it } from "vitest";
import { insecureCookieFindings, type SecurityMetadataFindingInput } from "@reconnexus/control-plane";

/**
 * The only security-metadata finding rule is strictly gated: HTTPS + an actually-set cookie +
 * Secure absent. Everything else stays inventory. False-positive and negative cases are asserted
 * here so the rule cannot quietly broaden.
 */
function cookie(overrides: Partial<SecurityMetadataFindingInput> & { detail?: Record<string, unknown> }): SecurityMetadataFindingInput {
  return {
    service: "https://app.example.com",
    category: "COOKIE",
    name: "session",
    status: "OBSERVED",
    url: "https://app.example.com/",
    detail: { secure: false, httpOnly: true, sameSite: "Lax" },
    ...overrides,
  };
}

describe("security-metadata findings (insecure cookie)", () => {
  it("flags a cookie set over HTTPS without Secure", () => {
    const f = insecureCookieFindings([cookie({})]);
    expect(f).toHaveLength(1);
    expect(f[0]!.category).toBe("INSECURE_COOKIE");
    expect(f[0]!.severity).toBe("LOW");
    expect(f[0]!.validation).toBe("SUSPECTED");
    expect(f[0]!.sourceStage).toBe("10-security-checks");
    expect(f[0]!.evidenceRefs).toContain("cookie:session");
  });

  it("does not flag a Secure cookie", () => {
    expect(insecureCookieFindings([cookie({ detail: { secure: true, httpOnly: true, sameSite: "Lax" } })])).toHaveLength(0);
  });

  it("does not flag a cookie set over plaintext HTTP (no TLS context)", () => {
    expect(insecureCookieFindings([cookie({ url: "http://app.example.com/", service: "http://app.example.com" })])).toHaveLength(0);
  });

  it("does not flag NOT_OBSERVED controls or non-cookie categories (e.g. CORS)", () => {
    expect(insecureCookieFindings([cookie({ status: "NOT_OBSERVED" })])).toHaveLength(0);
    expect(insecureCookieFindings([cookie({ category: "CORS", name: "cors", detail: { wildcard: true, allowCredentials: true } })])).toHaveLength(0);
    expect(insecureCookieFindings([cookie({ category: "HEADER", name: "strict-transport-security", detail: {} })])).toHaveLength(0);
  });

  it("deduplicates the same cookie across observations", () => {
    const f = insecureCookieFindings([cookie({}), cookie({ detail: { secure: false, httpOnly: false, sameSite: "None" } })]);
    expect(f).toHaveLength(1);
  });

  it("ignores a nameless cookie entry", () => {
    expect(insecureCookieFindings([cookie({ name: "" })])).toHaveLength(0);
  });
});
