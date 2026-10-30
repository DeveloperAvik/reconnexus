import type { Report, ReportFinding } from "@reconnexus/contracts";
import { normalizeReport } from "./report.js";

/**
 * SARIF 2.1.0 exporter for the canonical report model, so findings can flow into tools that
 * already consume SARIF (GitHub code scanning, most CI security dashboards) without a bespoke
 * importer. Like the HTML exporter, it is self-contained: no data source beyond the model
 * handed in, which is already redacted, and the output is JSON — there is no markup to escape.
 *
 * Only `findings` is represented; the rest of the report (coverage, inventory, secret/takeover
 * candidates not promoted to a finding) has no SARIF equivalent and is intentionally left out.
 */

const SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/** SARIF's result levels. CRITICAL/HIGH read as `error`, MEDIUM as `warning`, LOW/INFO as `note`. */
function levelFor(severity: string): "error" | "warning" | "note" {
  if (severity === "CRITICAL" || severity === "HIGH") return "error";
  if (severity === "MEDIUM") return "warning";
  return "note";
}

// A rule's default level is keyed only by its own id, independent of any one finding's severity,
// since the same rule can produce findings of different severities (e.g. CORS misconfiguration is
// HIGH with credentials and MEDIUM without). A result's own `level` always wins in a viewer; this
// only sets the rule's fallback, from the first finding of that category encountered.
function ruleFor(category: string, severityByRule: ReadonlyMap<string, string>): { id: string; name: string; shortDescription: { text: string }; defaultConfiguration: { level: string } } {
  const id = category || "UNCATEGORIZED";
  return {
    id,
    name: id,
    shortDescription: { text: id.replace(/_/g, " ").toLowerCase() },
    defaultConfiguration: { level: levelFor(severityByRule.get(id) ?? "MEDIUM") },
  };
}

function resultFor(f: ReportFinding): Record<string, unknown> {
  return {
    ruleId: f.category || "UNCATEGORIZED",
    level: levelFor(f.severity),
    message: { text: f.evidence ? `${f.title} — ${f.evidence}` : f.title },
    locations: [{ logicalLocations: [{ name: f.subject || "unknown", kind: "resource" }] }],
    partialFingerprints: { reconnexusFindingId: f.id },
    properties: {
      confidence: f.confidence,
      validation: f.validation,
      sourceStage: f.sourceStage,
      sourceKind: f.sourceKind,
      remediation: f.remediation,
      references: f.references,
      evidenceRefs: f.evidenceRefs,
    },
  };
}

export function renderReportSarif(input: Report): string {
  const report = normalizeReport(input);
  const severityByRule = new Map<string, string>();
  for (const f of report.findings) {
    const id = f.category || "UNCATEGORIZED";
    if (!severityByRule.has(id)) severityByRule.set(id, f.severity);
  }
  const categories = Array.from(severityByRule.keys()).sort();

  const sarif = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "ReconNexus",
            informationUri: "https://github.com/DeveloperAvik/reconnexus",
            version: report.reproducibility.toolVersion,
            rules: categories.map((c) => ruleFor(c, severityByRule)),
          },
        },
        results: report.findings.map(resultFor),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
