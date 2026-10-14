import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { ExitCode, ScopePolicySchema } from "@reconnexus/contracts";
import { findRepoRoot } from "@reconnexus/configuration";
import { canonicalHost, registrableDomain } from "@reconnexus/normalization";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { color, result, type CommandResult } from "../output.js";

export interface InitOptions {
  domain?: string;
  reference?: string;
  authorizedBy?: string;
  out?: string;
  force?: boolean;
  /** Base directory (defaults to cwd); resolvable for tests. */
  cwd?: string;
}

async function ask(prompt: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return (await rl.question(prompt)).trim();
  } finally {
    rl.close();
  }
}

async function required(value: string | undefined, prompt: string): Promise<string> {
  if (value) return value;
  if (process.stdin.isTTY) {
    const answer = await ask(prompt);
    if (answer) return answer;
  }
  throw new CliError("missing required input; supply it via flags (see --help)", ExitCode.USAGE_ERROR);
}

function buildPolicy(domain: string, reference: string, authorizedBy: string): unknown {
  const now = new Date();
  const until = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
  const root = registrableDomain(domain) ?? canonicalHost(domain);
  return {
    schemaVersion: 1,
    policyId: randomUUID(),
    projectId: randomUUID(),
    policyVersion: 1,
    authorization: {
      reference,
      authorizedBy,
      validFrom: now.toISOString(),
      validUntil: until.toISOString(),
      capabilities: ["PASSIVE", "DNS", "ACTIVE_HTTP", "CRAWL", "JS_ANALYSIS", "API_DISCOVERY", "SECRET_SCAN", "SECURITY_CHECKS", "TAKEOVER_CHECK"],
    },
    inScope: { domains: [{ value: root, includeSubdomains: true }], hosts: [], ips: [], cidrs: [] },
    exclusions: { domains: [], hosts: [], ips: [], cidrs: [], paths: [] },
    limits: { maxConcurrency: 8, requestsPerSecond: 10, crawlDepth: 2, maxRuntimeSeconds: 1800, maxArtifactBytes: 8388608 },
  };
}

export async function initCommand(ctx: Context, opts: InitOptions): Promise<CommandResult<unknown>> {
  const domain = (await required(opts.domain, "Authorized domain (e.g. example.com): ")).replace(/^https?:\/\//, "").split("/")[0]!;
  if (!domain) throw new CliError("a domain is required", ExitCode.USAGE_ERROR);
  const authorizedBy = await required(opts.authorizedBy, "Authorized by (your name or team): ");
  const reference = opts.reference ?? (process.stdin.isTTY ? (await ask("Authorization reference [LOCAL-AUTHORIZATION]: ")) || "LOCAL-AUTHORIZATION" : "LOCAL-AUTHORIZATION");

  const policy = ScopePolicySchema.parse(buildPolicy(domain, reference, authorizedBy));
  const base = opts.cwd ?? process.cwd();
  const root = findRepoRoot(base) ?? base;
  const policiesDir = join(root, "policies");
  const policyPath = opts.out ? opts.out : join(policiesDir, `${canonicalHost(domain)}.json`);
  const configPath = join(root, "reconnexus.config.json");

  const created: string[] = [];
  const skipped: string[] = [];

  if (existsSync(policyPath) && !opts.force) {
    skipped.push(policyPath);
  } else {
    mkdirSync(join(policyPath, ".."), { recursive: true });
    writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`, { mode: 0o600 });
    created.push(policyPath);
  }

  if (!existsSync(configPath) || opts.force) {
    const relPolicy = policyPath.startsWith(root) ? `.${policyPath.slice(root.length)}` : policyPath;
    const config = {
      schemaVersion: 1,
      defaultPolicyFile: relPolicy,
      logging: { level: "info", format: process.stdout.isTTY ? "pretty" : "json" },
    };
    writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
    created.push(configPath);
  } else {
    skipped.push(configPath);
  }

  return result({
    exitCode: ExitCode.SUCCESS,
    data: { domain: canonicalHost(domain), rootDomain: policy.inScope.domains[0]?.value, policyPath, configPath, authorization: policy.authorization },
    render: () =>
      [
        color.green("ReconNexus initialized."),
        created.length ? `  wrote:   ${created.join(", ")}` : "",
        skipped.length ? `  kept:    ${skipped.join(", ")} (already exists; use --force to overwrite)` : "",
        "",
        "This policy authorizes:",
        `  domain:        ${policy.inScope.domains[0]?.value} (and subdomains)`,
        `  authorized by: ${authorizedBy}`,
        `  reference:     ${reference}`,
        `  valid until:   ${policy.authorization.validUntil}`,
        "",
        "Next steps:",
        "  reconnexus config migrate",
        `  reconnexus scan start https://${domain}/ --run`,
      ]
        .filter((l) => l !== "")
        .join("\n"),
  });
}
