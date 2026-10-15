import { describe, expect, it } from "vitest";
import { ReportSchema, REPORT_SCHEMA_VERSION } from "@reconnexus/contracts";
import { buildFindings, findingTotals, formatReport, normalizeReport, redactReport } from "@reconnexus/control-plane";
import { makeReport, makeV1Document } from "../helpers/report-fixture.js";

describe("canonical report model", () => {
  it("accepts a v1 document and fills the v2 sections from defaults", () => {
    const v1 = normalizeReport(makeV1Document());
    expect(v1.schemaVersion).toBe(1);
    expect(v1.findings).toEqual([]);
    expect(v1.inventory.urls.total).toBe(0);
    expect(v1.assessment.profile).toBe("default");
    expect(v1.reproducibility.derivedFromPersistedStateOnly).toBe(true);
    expect(v1.findingTotals.validated).toBe(0);
  });

  it("defaults new reports to the current schema version", () => {
    expect(REPORT_SCHEMA_VERSION).toBe(2);
    const r = ReportSchema.parse({ ...makeV1Document(), schemaVersion: undefined });
    expect(r.schemaVersion).toBe(2);
  });

  it("rejects a malformed document rather than rendering it partially", () => {
    expect(() => normalizeReport({ ...makeV1Document(), scanId: "not-a-uuid" })).toThrow();
    expect(() => normalizeReport({ ...makeV1Document(), reportStatus: "PRODUCTION_READY" })).toThrow();
  });

  it("keeps an unmeasured duration null instead of zero", () => {
    const r = makeReport();
    const skipped = r.stages.find((s) => s.stage === "09-secret-detection")!;
    expect(skipped.durationMs).toBeNull();
    expect(skipped.records).toBe(0);
    // A measured stage keeps its measurement.
    expect(r.stages.find((s) => s.stage === "02-subdomain-discovery")!.durationMs).toBe(4200);
  });
});

describe("finding derivation", () => {
  const secrets = [
    { ruleId: "aws-key", category: "CLOUD_CREDENTIAL", status: "HIGH_CONFIDENCE", confidence: 0.99, artifact: "https://e.com/a.js", host: "e.com", location: "1:1", redactedSnippet: "[REDACTED]" },
    { ruleId: "entropy", category: "GENERIC_HIGH_ENTROPY", status: "CANDIDATE", confidence: 0.4, artifact: "https://e.com/b.js", host: "e.com", location: "2:2", redactedSnippet: "[REDACTED]" },
    { ruleId: "noise", category: "API_KEY", status: "SUPPRESSED", confidence: 0.1, artifact: "https://e.com/c.js", host: "e.com", location: "3:3", redactedSnippet: "[REDACTED]" },
    { ruleId: "broken", category: "OTHER", status: "ANALYSIS_FAILED", confidence: 0, artifact: "https://e.com/d.js", host: "e.com", location: "", redactedSnippet: "" },
  ];
  const takeovers = [
    { host: "a.e.com", cname: "a.s3.amazonaws.com", service: "s3", status: "SUSPECTED", confidence: 0.8, httpStatus: 404, evidence: "NoSuchBucket" },
    { host: "b.e.com", cname: "b.github.io", service: "github", status: "NOT_VULNERABLE", confidence: 0.9, httpStatus: 200, evidence: "claimed" },
  ];
  const findings = buildFindings(secrets, takeovers);

  it("never marks a scan-derived finding as VALIDATED", () => {
    expect(findings.every((f) => f.validation !== "VALIDATED")).toBe(true);
    expect(findingTotals(findings).validated).toBe(0);
  });

  it("maps candidate status onto validation state, not onto confidence", () => {
    const byId = new Map(findings.map((f) => [f.title, f]));
    const high = [...byId.values()].find((f) => f.subject === "https://e.com/a.js")!;
    expect(high.validation).toBe("SUSPECTED");
    expect(high.confidence).toBe(0.99);
    expect([...byId.values()].find((f) => f.subject === "https://e.com/c.js")!.validation).toBe("REJECTED");
    expect([...byId.values()].find((f) => f.subject === "https://e.com/d.js")!.validation).toBe("INDETERMINATE");
    // A NOT_VULNERABLE takeover is inventory, not a finding: it must not appear as a finding at all.
    expect([...byId.values()].find((f) => f.subject === "b.e.com")).toBeUndefined();
  });

  it("excludes non-actionable takeover candidates (NOT_VULNERABLE / INCONCLUSIVE) from findings", () => {
    const mixed = [
      { host: "s.e.com", cname: "s.s3.amazonaws.com", service: "s3", status: "SUSPECTED", confidence: 0.8, httpStatus: 404, evidence: "NoSuchBucket" },
      { host: "n.e.com", cname: "n.github.io", service: "github", status: "NOT_VULNERABLE", confidence: 0.9, httpStatus: 200, evidence: "claimed" },
      { host: "i.e.com", cname: "i.herokuapp.com", service: "heroku", status: "INCONCLUSIVE", confidence: 0.25, httpStatus: 404, evidence: "status only" },
    ];
    const only = buildFindings([], mixed);
    expect(only.map((f) => f.subject)).toEqual(["s.e.com"]);
  });

  it("assigns severity by impact and never escalates a suppressed candidate", () => {
    const bySubject = new Map(findings.map((f) => [f.subject, f]));
    expect(bySubject.get("https://e.com/a.js")!.severity).toBe("HIGH");
    expect(bySubject.get("https://e.com/b.js")!.severity).toBe("LOW");
    expect(bySubject.get("https://e.com/c.js")!.severity).toBe("INFO");
    expect(bySubject.get("a.e.com")!.severity).toBe("HIGH");
    expect(findings.every((f) => f.severity !== "CRITICAL")).toBe(true);
  });

  it("gives every finding remediation and evidence references", () => {
    expect(findings.every((f) => f.remediation.length > 0)).toBe(true);
    expect(findings.every((f) => f.evidenceRefs.length > 0 || f.subject === "")).toBe(true);
  });

  it("is deterministic: stable ids and stable ordering", () => {
    const again = buildFindings(secrets, takeovers);
    expect(again.map((f) => f.id)).toEqual(findings.map((f) => f.id));
    const severities = findings.map((f) => f.severity);
    expect(severities).toEqual([...severities].sort((a, b) => ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].indexOf(a) - ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].indexOf(b)));
  });

  it("counts zero explicitly for every severity and validation state", () => {
    const totals = findingTotals([]);
    expect(totals.total).toBe(0);
    expect(totals.bySeverity).toEqual({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });
    expect(totals.byValidation.VALIDATED).toBe(0);
  });
});

describe("format contract compatibility", () => {
  const report = makeReport();

  it("json round-trips the whole model", () => {
    const parsed = JSON.parse(formatReport(report, "json"));
    expect(parsed.scanId).toBe(report.scanId);
    expect(parsed.inventory.urls.total).toBe(12);
    expect(ReportSchema.safeParse(parsed).success).toBe(true);
  });

  it("jsonl keeps the original kinds first and appends the new ones", () => {
    const kinds = formatReport(report, "jsonl").split("\n").map((l) => JSON.parse(l).kind as string);
    expect(kinds[0]).toBe("summary");
    expect(kinds).toContain("stage");
    expect(kinds).toContain("secret");
    expect(kinds).toContain("correlation");
    expect(kinds).toContain("takeover");
    expect(kinds).toContain("finding");
    expect(kinds).toContain("provider-error");
    expect(kinds).toContain("evidence");
    // Original kinds come before the additions, so a positional consumer is unaffected.
    expect(kinds.lastIndexOf("takeover")).toBeLessThan(kinds.indexOf("finding"));
    for (const line of formatReport(report, "jsonl").split("\n")) expect(() => JSON.parse(line)).not.toThrow();
  });

  it("csv keeps its header and section vocabulary", () => {
    const rows = formatReport(report, "csv").split("\n");
    expect(rows[0]).toBe("section,type,key,status,detail");
    const sections = rows.slice(1).map((r) => r.split(",")[0]);
    expect(new Set(sections)).toEqual(new Set(["stage", "secret", "correlation", "takeover", "finding", "provider-error", "incomplete-stage"]));
  });

  it("neutralises spreadsheet formula injection in every new row type too", () => {
    const hostile = makeReport({
      findings: [{ ...makeReport().findings[0]!, subject: "=cmd|'/c calc'!A1", title: "x" }],
      providerErrors: [{ stage: "05-url-collection", provider: "+evil", outcome: "FAILED", reason: "@SUM(1)", records: 0, timedOut: false }],
    });
    const csv = formatReport(hostile, "csv");
    expect(csv).toContain("'=cmd|'/c calc'!A1");
    expect(csv).not.toMatch(/,=cmd/);
    expect(csv).toContain("'+evil");
    expect(csv).toContain("'@SUM(1)");
  });

  it("human output keeps its historical markers and adds the new sections", () => {
    const human = formatReport(report, "human");
    expect(human).toContain("ReconNexus report");
    expect(human).toContain("Stages:");
    expect(human).toContain("Secret findings (redacted candidates): 1");
    expect(human).toContain("Correlations: 1");
    expect(human).toContain("Subdomain-takeover candidates: 1");
    expect(human).toContain("Assessment:");
    expect(human).toContain("Findings: 1");
    expect(human).toContain("Tool/provider errors: 1");
    expect(human).toContain("Reproducibility:");
    expect(human).toContain("Limitations:");
  });

  it("prints an unmeasured duration as a dash, never 0ms", () => {
    const human = formatReport(makeReport(), "human");
    const line = human.split("\n").find((l) => l.includes("09-secret-detection"))!;
    expect(line).toContain("-");
    expect(line).not.toContain("0ms");
  });

  it("renders every format from a v1 document without throwing", () => {
    for (const f of ["human", "json", "jsonl", "csv", "html"]) {
      expect(() => formatReport(makeV1Document() as never, f)).not.toThrow();
    }
  });

  it("is deterministic across renders", () => {
    for (const f of ["human", "json", "jsonl", "csv", "html"]) {
      expect(formatReport(report, f)).toBe(formatReport(makeReport(), f));
    }
  });

  it("stays bounded on a large result set", () => {
    const row = makeReport().inventory.urls.rows[0]!;
    const big = makeReport({
      inventory: {
        ...makeReport().inventory,
        urls: { total: 50_000, shown: 200, truncated: true, rows: Array.from({ length: 200 }, (_, i) => ({ ...row, url: `https://example.com/${i}` })) },
      },
    });
    const html = formatReport(big, "html");
    expect(html).toContain("truncated — showing 200 of 50000");
    expect(html.length).toBeLessThan(2_000_000);
  });
});

describe("redaction at the report boundary", () => {
  it("scrubs secret-shaped strings from every section, including new ones", () => {
    const leaky = makeReport({
      summary: "found AKIAIOSFODNN7EXAMPLE in the bundle",
      findings: [{ ...makeReport().findings[0]!, evidence: "Authorization: Bearer abcdefghijklmnopqrst", remediation: "rotate AKIAIOSFODNN7EXAMPLE" }],
    });
    const out = redactReport(leaky);
    expect(JSON.stringify(out)).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(JSON.stringify(out)).not.toContain("abcdefghijklmnopqrst");
  });

  it("leaves count maps structurally intact", () => {
    const out = redactReport(makeReport());
    expect(out.observationCounts.byKind.host).toBe(31);
    expect(out.inventory.urls.total).toBe(12);
    expect(out.findingTotals.bySeverity.MEDIUM).toBe(1);
  });
});
