import { describe, expect, it } from "vitest";
import type { Report } from "@reconnexus/contracts";
import { deriveReportStatus, redactReport, ReportRedactionError } from "@reconnexus/control-plane";
import { csvField, formatReport } from "../../apps/cli/src/commands/report.js";

function job(jobKey: string, status: string): { jobKey: string; status: string } {
  return { jobKey, status };
}

describe("deriveReportStatus", () => {
  it("REPORTING_NOT_RUN before the reporting job ran", () => {
    expect(deriveReportStatus("QUEUED", [], 0)).toBe("REPORTING_NOT_RUN");
    expect(deriveReportStatus("RUNNING", [job("12-reporting", "QUEUED")], 5)).toBe("REPORTING_NOT_RUN");
  });

  it("REPORTING_FAILED when the reporting job failed", () => {
    expect(deriveReportStatus("PARTIAL", [job("12-reporting", "FAILED")], 0)).toBe("REPORTING_FAILED");
    expect(deriveReportStatus("PARTIAL", [job("12-reporting", "SOURCE_UNAVAILABLE")], 0)).toBe("REPORTING_FAILED");
    expect(deriveReportStatus("PARTIAL", [job("12-reporting", "BLOCKED")], 0)).toBe("REPORTING_FAILED");
  });

  it("COMPLETE_* only when the scan is SUCCEEDED", () => {
    expect(deriveReportStatus("SUCCEEDED", [job("12-reporting", "SUCCEEDED")], 0)).toBe("COMPLETE_NO_FINDINGS");
    expect(deriveReportStatus("SUCCEEDED", [job("12-reporting", "SUCCEEDED")], 3)).toBe("COMPLETE_WITH_FINDINGS");
  });

  it("PARTIAL / FAILED propagate from the scan, never 'complete'", () => {
    expect(deriveReportStatus("PARTIAL", [job("12-reporting", "SUCCEEDED")], 0)).toBe("PARTIAL");
    expect(deriveReportStatus("CANCELLED", [job("12-reporting", "SUCCEEDED")], 0)).toBe("PARTIAL");
    expect(deriveReportStatus("FAILED", [job("12-reporting", "SUCCEEDED")], 0)).toBe("FAILED");
  });
});

const report: Report = {
  schemaVersion: 1,
  scanId: "11111111-1111-1111-1111-111111111111",
  projectId: "22222222-2222-2222-2222-222222222222",
  rootDomain: "example.com",
  startUrl: "https://example.com/",
  scanStatus: "PARTIAL",
  reportStatus: "PARTIAL",
  generatedAt: "2026-01-01T00:00:00.000Z",
  stages: [],
  coverageGaps: [],
  assetCounts: {},
  observationCounts: { total: 0, byKind: {}, bySource: {} },
  secretFindings: [],
  correlations: [],
  takeoverCandidates: [],
  limitations: ["candidate not confirmed"],
  summary: "partial",
};

describe("redactReport (fail-closed)", () => {
  it("returns a valid report through the default redactor", () => {
    const out = redactReport(report);
    expect(out.reportStatus).toBe("PARTIAL");
    expect(out.limitations).toEqual(["candidate not confirmed"]);
  });

  it("throws ReportRedactionError when the redactor fails, never returning the original", () => {
    expect(() => redactReport(report, () => {
      throw new Error("boom");
    })).toThrow(ReportRedactionError);
  });

  it("throws when redaction yields an invalid report", () => {
    expect(() => redactReport(report, () => ({ not: "a report" }))).toThrow(ReportRedactionError);
  });
});

describe("formatReport", () => {
  it("produces parseable json / jsonl / csv and a human summary", () => {
    expect(JSON.parse(formatReport(report, "json")).scanId).toBe(report.scanId);
    const jsonl = formatReport(report, "jsonl").split("\n");
    expect(JSON.parse(jsonl[0]!).kind).toBe("summary");
    const csv = formatReport(report, "csv").split("\n");
    expect(csv[0]).toBe("section,type,key,status,detail");
    expect(formatReport(report, "human")).toContain("ReconNexus report");
  });
});

describe("csvField", () => {
  it("quotes fields containing separators or quotes", () => {
    expect(csvField("a,b")).toBe('"a,b"');
    expect(csvField('say "hi"')).toBe('"say ""hi"""');
    expect(csvField("line\nbreak")).toBe('"line\nbreak"');
  });

  it("neutralises spreadsheet formula injection", () => {
    expect(csvField("=cmd|'/c calc'!A1")).toBe("'=cmd|'/c calc'!A1");
    expect(csvField("=1,2")).toBe(`"'=1,2"`);
    expect(csvField("+1+1")).toBe("'+1+1");
    expect(csvField("-2")).toBe("'-2");
    expect(csvField("@SUM(A1)")).toBe("'@SUM(A1)");
  });
});
