import { describe, expect, it } from "vitest";
import { renderReportSarif } from "@reconnexus/control-plane";
import { makeReport } from "../helpers/report-fixture.js";

describe("SARIF report export", () => {
  it("produces a well-formed SARIF 2.1.0 document with one result per finding", () => {
    const report = makeReport();
    const sarif = JSON.parse(renderReportSarif(report));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0.json");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("ReconNexus");
    expect(sarif.runs[0].results).toHaveLength(report.findings.length);
  });

  it("carries the finding's category as ruleId and declares a matching rule", () => {
    const sarif = JSON.parse(renderReportSarif(makeReport()));
    const result = sarif.runs[0].results[0];
    expect(result.ruleId).toBe("API_KEY");
    const rule = sarif.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === "API_KEY");
    expect(rule).toBeDefined();
  });

  it("maps severity to SARIF level: CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFO -> note", () => {
    const base = makeReport().findings[0]!;
    const report = makeReport({
      findings: [
        { ...base, id: "f1", severity: "CRITICAL" },
        { ...base, id: "f2", severity: "HIGH" },
        { ...base, id: "f3", severity: "MEDIUM" },
        { ...base, id: "f4", severity: "LOW" },
        { ...base, id: "f5", severity: "INFO" },
      ],
    });
    const sarif = JSON.parse(renderReportSarif(report));
    const levels = sarif.runs[0].results.map((r: { level: string }) => r.level);
    expect(levels).toEqual(["error", "error", "warning", "note", "note"]);
  });

  it("carries confidence, validation, remediation and references through as properties", () => {
    const sarif = JSON.parse(renderReportSarif(makeReport()));
    const result = sarif.runs[0].results[0];
    expect(result.properties).toMatchObject({
      confidence: 0.95,
      validation: "SUSPECTED",
      sourceStage: "09-secret-detection",
      remediation: "Rotate the key, scope it to the minimum required permissions.",
    });
    expect(result.properties.references).toEqual(["rule:generic-api-key"]);
  });

  it("is valid JSON even when a finding's text contains quotes and newlines", () => {
    const base = makeReport().findings[0]!;
    const report = makeReport({ findings: [{ ...base, title: `"quoted"\nmulti-line title`, evidence: `embedded "quote"` }] });
    expect(() => JSON.parse(renderReportSarif(report))).not.toThrow();
  });

  it("produces an empty results array, never a missing one, when there are no findings", () => {
    const sarif = JSON.parse(renderReportSarif(makeReport({ findings: [] })));
    expect(sarif.runs[0].results).toEqual([]);
  });
});
