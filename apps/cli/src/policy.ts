import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ScopePolicySchema, type ScopePolicy } from "@reconnexus/contracts";
import { findRepoRoot } from "@reconnexus/configuration";
import { CliError } from "./errors.js";
import { ExitCode } from "@reconnexus/contracts";

export function loadPolicyFile(path: string): ScopePolicy {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new CliError(`policy file not found: ${path}`, ExitCode.CONFIG_INVALID);
    }
    throw new CliError(`policy file is not valid JSON: ${path}: ${(err as Error).message}`, ExitCode.CONFIG_INVALID);
  }
  const parsed = ScopePolicySchema.safeParse(raw);
  if (!parsed.success) {
    throw new CliError(`policy failed schema validation: ${path}`, ExitCode.CONFIG_INVALID, parsed.error.flatten());
  }
  return parsed.data;
}

/** Candidate policy files under `<repoRoot>/policies/*.json`. */
export function discoverPolicyPaths(cwd: string = process.cwd()): string[] {
  const root = findRepoRoot(cwd) ?? cwd;
  const dir = join(root, "policies");
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .sort()
      .map((f) => join(dir, f));
  } catch {
    return [];
  }
}

/**
 * Resolve a policy to use: explicit `--policy`, then `defaultPolicyFile`, then a single file under
 * `policies/`. Gives actionable guidance instead of a bare failure.
 */
export function resolvePolicy(explicitPath: string | undefined, defaultPath: string | undefined, cwd: string = process.cwd()): { path: string; policy: ScopePolicy } {
  if (explicitPath) return { path: explicitPath, policy: loadPolicyFile(explicitPath) };
  if (defaultPath) return { path: defaultPath, policy: loadPolicyFile(defaultPath) };
  const candidates = discoverPolicyPaths(cwd);
  if (candidates.length === 1) return { path: candidates[0]!, policy: loadPolicyFile(candidates[0]!) };
  if (candidates.length > 1) {
    throw new CliError(
      `multiple scope policies found; pass --policy <file>. Candidates:\n  ${candidates.join("\n  ")}`,
      ExitCode.USAGE_ERROR,
    );
  }
  throw new CliError(
    "no scope policy found. Create one with:  reconnexus init --domain example.com --authorized-by you\n" +
      "or pass --policy <file> / set defaultPolicyFile in reconnexus.config.json.",
    ExitCode.USAGE_ERROR,
  );
}

/** Backwards-compatible helper returning just the policy. */
export function requirePolicy(explicitPath: string | undefined, defaultPath: string | undefined): ScopePolicy {
  return resolvePolicy(explicitPath, defaultPath).policy;
}
