import { canonicalHost, isIpLiteral, registrableDomain } from "./domain.js";

export interface NormalizedUrl {
  raw: string;
  scheme: string;
  host: string;
  port: number | null;
  isIpLiteral: boolean;
  registrableDomain: string | null;
  path: string;
  query: string;
  fragment: string;
  queryKeys: string[];
  /** Stable identity used for deduplication: lowercased host, default port removed, fragment removed. */
  canonical: string;
}

const DEFAULT_PORTS: Record<string, number> = { http: 80, https: 443, ws: 80, wss: 443 };

export class InvalidUrlError extends Error {
  constructor(message: string, readonly input: string) {
    super(message);
    this.name = "InvalidUrlError";
  }
}

export interface ParseUrlOptions {
  /** Schemes considered valid scan targets. Defaults to http and https only. */
  allowedSchemes?: string[];
}

export function parseUrl(input: string, opts: ParseUrlOptions = {}): NormalizedUrl {
  const allowed = opts.allowedSchemes ?? ["http", "https"];
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    throw new InvalidUrlError("malformed URL", input);
  }
  const scheme = u.protocol.replace(/:$/, "").toLowerCase();
  if (!allowed.includes(scheme)) {
    throw new InvalidUrlError(`unsupported scheme '${scheme}'`, input);
  }
  const host = canonicalHost(u.hostname);
  if (host.length === 0) throw new InvalidUrlError("missing host", input);

  const defaultPort = DEFAULT_PORTS[scheme];
  const explicitPort = u.port ? Number(u.port) : null;
  const port = explicitPort === defaultPort ? null : explicitPort;

  const path = u.pathname === "" ? "/" : u.pathname;
  const qs = u.search.startsWith("?") ? u.search.slice(1) : u.search;
  const fragment = u.hash.startsWith("#") ? u.hash.slice(1) : u.hash;

  const portPart = port !== null ? `:${port}` : "";
  const canonical = `${scheme}://${host}${portPart}${path}${qs ? `?${qs}` : ""}`;

  return {
    raw: input,
    scheme,
    host,
    port,
    isIpLiteral: isIpLiteral(host),
    registrableDomain: registrableDomain(host),
    path,
    query: qs,
    fragment,
    queryKeys: Array.from(new Set([...u.searchParams.keys()])),
    canonical,
  };
}

export function tryParseUrl(input: string, opts?: ParseUrlOptions): NormalizedUrl | null {
  try {
    return parseUrl(input, opts);
  } catch {
    return null;
  }
}

/**
 * Extract host, port and path candidates from free text (robots.txt, sitemaps, JS blobs).
 * Does not attempt semantic validation beyond scheme/host sanity.
 */
export function extractUrlLike(text: string, opts?: ParseUrlOptions): string[] {
  const re = /\bhttps?:\/\/[^\s'"`<>()\[\]{}]+/gi;
  const out: string[] = [];
  for (const m of text.matchAll(re)) {
    const candidate = m[0].replace(/[.,;:]+$/, "");
    if (tryParseUrl(candidate, opts)) out.push(candidate);
  }
  return out;
}
