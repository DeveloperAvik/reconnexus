import { getDomain, getPublicSuffix } from "tldts";
import { parseIp } from "./ip.js";

const HOSTNAME_RE = /^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)(\.[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)*\.?$/;

export function isIpLiteral(host: string): boolean {
  return parseIp(host) !== null;
}

/** Lowercase, strip a single trailing dot, and strip surrounding brackets from an IPv6 literal. */
export function canonicalHost(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.endsWith(".")) h = h.slice(0, -1);
  return h;
}

/** Validate a DNS hostname (not an IP literal). Underscores are permitted for service labels. */
export function isValidHostname(host: string): boolean {
  const h = canonicalHost(host);
  if (h.length === 0 || h.length > 253) return false;
  if (isIpLiteral(h)) return false;
  if (h.startsWith(".") || h.endsWith(".")) return false;
  return HOSTNAME_RE.test(h);
}

/**
 * Extract the registrable (eTLD+1) domain using the Public Suffix List.
 * Returns null for IP literals, localhost-style single labels, and unknown suffixes.
 */
export function registrableDomain(host: string): string | null {
  const h = canonicalHost(host);
  if (h.length === 0 || isIpLiteral(h)) return null;
  const domain = getDomain(h, { allowPrivateDomains: true });
  if (domain) return domain;
  // Fallback: if the host has no known public suffix (e.g. an internal TLD),
  // treat the last two labels as the registrable domain when possible.
  const labels = h.split(".").filter(Boolean);
  if (labels.length >= 2) return labels.slice(-2).join(".");
  return null;
}

export function publicSuffix(host: string): string | null {
  const h = canonicalHost(host);
  if (h.length === 0 || isIpLiteral(h)) return null;
  return getPublicSuffix(h, { allowPrivateDomains: true });
}

export interface DomainRule {
  value: string;
  includeSubdomains: boolean;
}

/** Returns true when `host` matches domain rule `value` (optionally including subdomains). */
export function hostMatchesDomain(host: string, value: string, includeSubdomains: boolean): boolean {
  const h = canonicalHost(host);
  const v = canonicalHost(value);
  if (h === v) return true;
  return includeSubdomains && h.endsWith(`.${v}`);
}

/** Returns true when `candidate` is the same registrable domain as `root` or a subdomain of it. */
export function isSubdomainOf(candidate: string, root: string): boolean {
  const c = canonicalHost(candidate);
  const r = canonicalHost(root);
  if (c === r) return true;
  return c.endsWith(`.${r}`);
}
