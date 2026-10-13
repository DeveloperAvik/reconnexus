import { lookup } from "node:dns/promises";
import type { ScopeCheckRequest, ScopeDecision } from "@reconnexus/contracts";
import type { ScopeEngine } from "./engine.js";

/**
 * Resolve a host to A/AAAA records at connection time. Callers must pass the
 * resolved addresses back into `ScopeEngine.check` so the decision is made on the
 * addresses actually connected to — not on a stale pre-flight answer.
 */
export async function resolveAddresses(host: string): Promise<string[]> {
  const results = await lookup(host, { all: true, verbatim: true });
  return Array.from(new Set(results.map((r) => r.address)));
}

export interface ResolveAndCheckOptions {
  /** When false (default), no DNS is performed and only literal targets are checked. */
  resolve?: boolean;
  /** Injectable resolver, primarily for deterministic tests. Defaults to node:dns lookup. */
  resolver?: (host: string) => Promise<string[]>;
}

/**
 * Network-disabled by default. When `resolve` is true, performs DNS and validates
 * every resolved address, catching rebinding where a public name resolves to a
 * restricted address between authorization and connection.
 */
export async function resolveAndCheck(
  engine: ScopeEngine,
  req: ScopeCheckRequest,
  opts: ResolveAndCheckOptions = {},
): Promise<ScopeDecision> {
  if (!opts.resolve || req.resolvedAddresses) {
    return engine.check(req);
  }
  const host = req.kind === "URL" ? safeHost(req.value) : req.value;
  if (!host) return engine.check(req);
  const resolver = opts.resolver ?? resolveAddresses;
  let addresses: string[] = [];
  try {
    addresses = await resolver(host);
  } catch {
    // Resolution failure is not an allow: surface it explicitly.
    return {
      allowed: false,
      code: "DNS_RESOLUTION_FAILED",
      reason: `DNS resolution failed for ${host}`,
    };
  }
  return engine.check({ ...req, resolvedAddresses: addresses });
}

function safeHost(value: string): string | null {
  try {
    return new URL(value).hostname;
  } catch {
    return null;
  }
}
