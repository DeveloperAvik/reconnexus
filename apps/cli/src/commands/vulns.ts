import { readFileSync } from "node:fs";
import { ExitCode } from "@reconnexus/contracts";
import {
  CachingVulnerabilitySource,
  NvdVulnerabilitySource,
  StaticAdvisorySource,
  correlateTechnologies,
  fingerprintFromTechnology,
  kevCveSet,
  type AdvisoryRecord,
  type VulnerabilityMatch,
  type VulnerabilityReport,
  type VulnerabilitySource,
} from "@reconnexus/control-plane";
import { createDb, Repository } from "@reconnexus/control-plane";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { color, result, type CommandResult } from "../output.js";

export interface VulnsOptions {
  product?: string;
  state?: string;
  format?: string;
  advisories?: string;
  kev?: string;
  online?: boolean;
  maxProducts?: number;
}

const STATES = [
  "MATCH_CANDIDATE",
  "NEEDS_VERSION_CONFIRMATION",
  "NEEDS_APPLICABILITY_REVIEW",
  "VALIDATED",
  "NOT_APPLICABLE",
  "INCONCLUSIVE",
  "SOURCE_UNAVAILABLE",
] as const;

function loadJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new CliError(`could not read ${path}: ${(err as Error).message}`, ExitCode.CONFIG_INVALID);
  }
}

function buildSource(opts: VulnsOptions): VulnerabilitySource {
  const kev = opts.kev ? kevCveSet(loadJson(opts.kev)) : new Set<string>();
  if (opts.advisories) {
    const raw = loadJson(opts.advisories);
    if (!Array.isArray(raw)) throw new CliError("advisories file must be a JSON array of advisory records", ExitCode.CONFIG_INVALID);
    return new StaticAdvisorySource(raw as AdvisoryRecord[], `advisories:${opts.advisories}`);
  }
  if (opts.online) {
    return new CachingVulnerabilitySource(
      new NvdVulnerabilitySource({ fetch: globalThis.fetch, ...(process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {}), kev }),
      { ttlMs: 60 * 60 * 1000, staleIfErrorMs: 24 * 60 * 60 * 1000 },
    );
  }
  throw new CliError("no intelligence source: pass --advisories <file.json> (offline) or --online (NVD + KEV)", ExitCode.USAGE_ERROR);
}

function stateColor(state: string): (s: string) => string {
  switch (state) {
    case "MATCH_CANDIDATE":
      return color.red;
    case "NEEDS_APPLICABILITY_REVIEW":
      return color.yellow;
    case "NEEDS_VERSION_CONFIRMATION":
      return color.yellow;
    case "VALIDATED":
      return color.green;
    case "NOT_APPLICABLE":
      return color.dim;
    default:
      return color.dim;
  }
}

function renderMatch(m: VulnerabilityMatch): string {
  const sev = (m.cvss?.severity || "n/a").padEnd(8);
  const score = m.cvss ? `CVSS ${m.cvss.version} ${m.cvss.score}` : "CVSS n/a";
  const kev = m.kev ? color.red("KEV ") : "    ";
  const lines = [
    `  ${stateColor(m.applicability)(m.applicability.padEnd(28))} ${sev} ${kev}${color.bold(m.cveId)}  ${m.product} ${m.observedVersion ?? "(version unknown)"}  [${score}]${m.stale ? color.yellow(" (stale)") : ""}`,
    `      affected: ${m.affected}${m.fixedIn ? `  fixed in ${m.fixedIn}` : ""}`,
    `      ${m.rationale}`,
    `      hosts: ${m.hosts.join(", ")}`,
    `      ref: ${m.sourceUrl}`,
  ];
  if (m.backportNote) lines.push(`      backport: ${m.backportNote}`);
  return lines.join("\n");
}

function renderHuman(report: VulnerabilityReport): string {
  const c = report.coverage;
  const lines: string[] = [];
  lines.push(`Vulnerability intelligence — scan ${report.scanId}`);
  lines.push(
    `  products ${c.products} · candidates ${c.candidates} · needs version ${c.needsVersion} · needs review ${c.needsReview} · inconclusive ${c.inconclusive} · source-unavailable ${c.sourceUnavailable} · unmatched ${c.unmatchedProducts.length} · ambiguous ${c.ambiguousProducts.length}`,
  );
  if (report.sources.length) {
    lines.push(`  sources: ${report.sources.map((s) => `${s.source}=${s.status}${s.stale ? "(stale)" : ""}`).join(" ")}`);
  }
  if (report.matches.length === 0) {
    lines.push("");
    lines.push("  No CVE candidates were derived from the observed technologies.");
    if (c.sourceUnavailable > 0) lines.push(color.yellow("  Note: an intelligence source was unavailable — this is not a clean result."));
  } else {
    lines.push("");
    for (const m of report.matches) lines.push(renderMatch(m));
  }
  lines.push("");
  lines.push("  limitations:");
  for (const l of report.limitations) lines.push(color.dim(`    - ${l}`));
  return lines.join("\n");
}

export async function vulnsCommand(ctx: Context, scanId: string, opts: VulnsOptions): Promise<CommandResult<unknown>> {
  const format = opts.format ?? "human";
  if (!["human", "json"].includes(format)) {
    throw new CliError(`unsupported format: ${format} (expected human or json)`, ExitCode.USAGE_ERROR);
  }
  const states = opts.state ? opts.state.split(",").map((s) => s.trim().toUpperCase()) : undefined;
  if (states) {
    const bad = states.filter((s) => !(STATES as readonly string[]).includes(s));
    if (bad.length) throw new CliError(`unknown applicability state: ${bad.join(", ")} (expected ${STATES.join(", ")})`, ExitCode.USAGE_ERROR);
  }
  if (opts.maxProducts !== undefined && (!Number.isFinite(opts.maxProducts) || opts.maxProducts < 1)) {
    throw new CliError("--max-products must be a positive integer", ExitCode.USAGE_ERROR);
  }

  const source = buildSource(opts);
  const db = createDb(ctx.config.database);
  try {
    const repo = new Repository(db);
    const scan = await repo.getScan(scanId);
    if (!scan) throw new CliError(`scan not found: ${scanId}`, ExitCode.USAGE_ERROR);
    const techs = await repo.listTechnologyObservations(scanId);
    const fingerprints = techs.map((t) => fingerprintFromTechnology({ name: t.name, host: t.host, category: t.category, evidenceType: t.evidence_type, evidence: t.evidence, confidence: t.confidence }));

    let report = await correlateTechnologies(scanId, fingerprints, source, opts.maxProducts ? { maxProducts: opts.maxProducts } : {});
    if (opts.product || states) {
      const product = opts.product?.toLowerCase();
      report = {
        ...report,
        matches: report.matches.filter((m) => (!product || m.product.toLowerCase().includes(product) || m.cveId.toLowerCase().includes(product)) && (!states || states.includes(m.applicability))),
      };
    }

    const rendered = format === "json" ? JSON.stringify(report, null, 2) : renderHuman(report);
    return result({
      exitCode: ExitCode.SUCCESS,
      data: report,
      warnings: report.coverage.sourceUnavailable > 0 ? ["an intelligence source was unavailable; affected CVEs are unknown, not absent"] : [],
      render: () => rendered,
    });
  } finally {
    await db.close();
  }
}
