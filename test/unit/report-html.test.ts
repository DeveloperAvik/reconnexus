import { describe, expect, it } from "vitest";
import { esc, redactReport, renderReportHtml } from "@reconnexus/control-plane";
import { makeReport, makeV1Document } from "../helpers/report-fixture.js";

const html = renderReportHtml(makeReport());

describe("HTML report — safety", () => {
  it("escapes every HTML metacharacter", () => {
    expect(esc(`<script>"'&`)).toBe("&lt;script&gt;&quot;&#39;&amp;");
    expect(esc(undefined)).toBe("");
    expect(esc(42)).toBe("42");
  });

  it("never emits a script element or an inline event handler, whatever the scan found", () => {
    const hostile = makeReport({
      rootDomain: "<script>alert('xss')</script>.example.com",
      summary: `</style><script>alert(1)</script><img src=x onerror="alert(2)">`,
    });
    const out = renderReportHtml(hostile);
    expect(out).not.toMatch(/<script/i);
    expect(out).not.toMatch(/<img/i);
    // No real tag carries an event handler. (The hostile text itself survives as escaped data,
    // which is the point — it must read as text, not as markup.)
    for (const tag of out.matchAll(/<[a-z][^>]*>/gi)) {
      expect(tag[0]).not.toMatch(/\son[a-z]+\s*=/i);
    }
    expect(out).not.toContain('onerror="alert(2)"');
    // The hostile text is still present — escaped, so it reads as data.
    expect(out).toContain("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;");
  });

  it("renders a javascript: URL as text, never as a link target", () => {
    expect(html).toContain("javascript:alert(1)");
    expect(html).not.toMatch(/href\s*=\s*"javascript:/i);
    // The only hrefs are in-document anchors.
    const hrefs = Array.from(html.matchAll(/href="([^"]*)"/g)).map((m) => m[1]!);
    expect(hrefs.length).toBeGreaterThan(0);
    expect(hrefs.every((h) => h.startsWith("#"))).toBe(true);
  });

  it("is self-contained: no remote stylesheet, font, image or import", () => {
    expect(html).not.toMatch(/<link\b/i);
    expect(html).not.toMatch(/@import/i);
    expect(html).not.toMatch(/\bsrc\s*=/i);
    expect(html).not.toMatch(/url\(\s*https?:/i);
  });

  it("cannot be broken out of by a quote in a style-adjacent value", () => {
    const hostile = makeReport({ findings: [{ ...makeReport().findings[0]!, confidence: 1 }] });
    const out = renderReportHtml(hostile);
    // The one inline style is a computed width from a clamped number.
    const styles = Array.from(out.matchAll(/style="([^"]*)"/g)).map((m) => m[1]!);
    expect(styles.every((s) => /^width:\d{1,3}%$/.test(s))).toBe(true);
  });

  it("carries redaction through to the rendered document (fail-closed upstream)", () => {
    const leaky = makeReport({
      summary: "token AKIAIOSFODNN7EXAMPLE was seen",
      secretFindings: [{ ...makeReport().secretFindings[0]!, redactedSnippet: "Bearer abcdefghijklmnopqrstuvwxyz" }],
    });
    const out = renderReportHtml(redactReport(leaky));
    expect(out).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(out).not.toContain("abcdefghijklmnopqrstuvwxyz");
    expect(out).toContain("[REDACTED]");
  });
});

describe("HTML report — content and status semantics", () => {
  it("states both statuses and never calls a partial assessment complete", () => {
    expect(html).toContain("PARTIAL");
    expect(html).toContain("did not complete every stage");
    expect(html).not.toContain("Every stage of this assessment succeeded.");
  });

  it("says every stage succeeded only when the report status says so", () => {
    const clean = renderReportHtml(
      makeReport({ reportStatus: "COMPLETE_NO_FINDINGS", scanStatus: "SUCCEEDED", findings: [], findingTotals: { total: 0, bySeverity: {}, byValidation: {}, validated: 0 } }),
    );
    expect(clean).toContain("Every stage of this assessment succeeded.");
    expect(clean).toContain("this is a clean result");
  });

  it("does not present an incomplete scan's empty findings as a clean result", () => {
    const out = renderReportHtml(makeReport({ findings: [], findingTotals: { total: 0, bySeverity: {}, byValidation: {}, validated: 0 } }));
    expect(out).toContain("not evidence that none exist");
  });

  it("includes every required section", () => {
    for (const id of ["summary", "assessment", "stages", "inventory", "intelligence", "findings", "problems", "reproducibility", "limitations"]) {
      expect(html).toContain(`id="${id}"`);
    }
  });

  it("reports findings with severity, confidence, validation, evidence and remediation", () => {
    expect(html).toContain("MEDIUM");
    expect(html).toContain("SUSPECTED");
    expect(html).toContain("confidence 95 percent");
    expect(html).toContain("Evidence (redacted)");
    expect(html).toContain("Remediation");
    expect(html).toContain("rule:generic-api-key");
  });

  it("shows unmeasured values as em dashes, never as zero", () => {
    // 09-secret-detection was skipped, so it has no duration.
    expect(html).toContain('title="not recorded"');
    expect(html).toContain("—");
  });

  it("marks truncated inventory sections and keeps the exact total", () => {
    expect(html).toContain("truncated — showing 1 of 31");
    // A complete section says so instead, so a reader can tell a cap from a count.
    expect(html).toContain("2 recorded");
    expect(html).toContain("truncated — showing 2 of 12");
  });

  it("surfaces provider errors and incomplete stages with their impact", () => {
    expect(html).toContain("gau");
    expect(html).toContain("exit 1: &lt;timeout&gt;");
    expect(html).toContain("completed partially");
    expect(html).toContain("09-secret-detection");
  });

  it("carries reproducibility metadata and an evidence appendix of references only", () => {
    expect(html).toContain("report schema v2");
    expect(html).toContain("reconnexus report 11111111-1111-1111-1111-111111111111 --format json");
    expect(html).toContain(`sha256:${"a".repeat(64)}`);
    expect(html).toContain("Artifact bodies are never embedded");
  });

  it("is printable, responsive and accessible in its scaffolding", () => {
    expect(html).toContain('<html lang="en">');
    expect(html).toContain('name="viewport"');
    expect(html).toContain("@media print");
    expect(html).toContain("@media (max-width:640px)");
    expect(html).toContain('class="skip"');
    expect(html).toContain('scope="col"');
    expect(html).toContain("<caption>");
    expect(html).toContain("prefers-color-scheme");
  });
});

describe("HTML report — determinism and robustness", () => {
  it("is byte-identical for identical input", () => {
    expect(renderReportHtml(makeReport())).toBe(renderReportHtml(makeReport()));
  });

  it("renders a v1 document by filling v2 defaults instead of failing", () => {
    const out = renderReportHtml(makeV1Document() as never);
    expect(out).toContain("legacy.example.com");
    expect(out).toContain("report schema v1");
    expect(out).toContain("No DNS observations were recorded");
  });

  it("bounds a very large findings list and says what it capped", () => {
    const one = makeReport().findings[0]!;
    const many = Array.from({ length: 1200 }, (_, i) => ({ ...one, id: `id${i}`, title: `Finding ${i}` }));
    const out = renderReportHtml(makeReport({ findings: many }));
    expect(out).toContain("Showing 500 of 1,200 findings".replace("1,200", "1200"));
    expect(out).not.toContain("Finding 700");
  });
});
