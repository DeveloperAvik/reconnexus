/**
 * Deterministic version parsing and range evaluation for vulnerability correlation.
 *
 * Versions are compared segment by segment. A segment that parses as an integer compares
 * numerically; otherwise it compares lexically. A release (`1.2.3`) sorts above the same core with a
 * pre-release suffix (`1.2.3-rc1`), matching common advisory conventions. The logic is intentionally
 * conservative: anything it cannot parse is reported as unparseable rather than guessed, so a
 * comparison failure can never manufacture a match.
 */

export interface ParsedVersion {
  raw: string;
  /** Numeric/alphanumeric release segments. */
  segments: Array<number | string>;
  /** Pre-release/build suffix segments that sort below the bare release. */
  prerelease: Array<number | string>;
  valid: boolean;
}

const NUMERIC = /^\d+$/;

/** Split a version string into release and pre-release segments. */
export function parseVersion(input: string): ParsedVersion {
  const raw = (input ?? "").trim();
  if (raw === "") return { raw, segments: [], prerelease: [], valid: false };
  // Drop a leading `v` and any surrounding whitespace/`=` noise.
  const cleaned = raw.replace(/^v/i, "").replace(/^=/, "").trim();
  // Pre-release begins at the first `-` or `+` (build metadata ignored for ordering), or the first
  // letter-suffixed token such as `1.2.3p1`.
  const m = /^([0-9][0-9.]*?)(?:[-+](.*))?$/.exec(cleaned);
  if (!m) {
    // Not a numeric version (e.g. a name): unparseable, so it can never be compared into a match.
    return { raw, segments: [], prerelease: [], valid: false };
  }
  const core = m[1]!;
  const pre = m[2] ?? "";
  const segments: Array<number | string> = core
    .split(".")
    .filter((s) => s !== "")
    .map((s) => (NUMERIC.test(s) ? Number(s) : s));
  const prerelease: Array<number | string> = pre
    .split(/[.\-]/)
    .filter((s) => s !== "")
    .map((s) => (NUMERIC.test(s) ? Number(s) : s));
  return { raw, segments, prerelease, valid: segments.length > 0 };
}

function compareSegment(a: number | string | undefined, b: number | string | undefined): number {
  if (a === undefined && b === undefined) return 0;
  // A missing segment is lower than a present one (1.0 < 1.0.1).
  if (a === undefined) return -1;
  if (b === undefined) return 1;
  if (typeof a === "number" && typeof b === "number") return a === b ? 0 : a < b ? -1 : 1;
  const as = String(a);
  const bs = String(b);
  return as < bs ? -1 : as > bs ? 1 : 0;
}

/** Standard three-way comparison: negative if a<b, 0 if equal, positive if a>b. */
export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  const n = Math.max(pa.segments.length, pb.segments.length);
  for (let i = 0; i < n; i++) {
    const c = compareSegment(pa.segments[i], pb.segments[i]);
    if (c !== 0) return c;
  }
  // Equal core: a bare release outranks a pre-release.
  if (pa.prerelease.length === 0 && pb.prerelease.length === 0) return 0;
  if (pa.prerelease.length === 0) return 1;
  if (pb.prerelease.length === 0) return -1;
  const pn = Math.max(pa.prerelease.length, pb.prerelease.length);
  for (let i = 0; i < pn; i++) {
    const c = compareSegment(pa.prerelease[i], pb.prerelease[i]);
    if (c !== 0) return c;
  }
  return 0;
}

export type ComparisonOp = ">=" | "<=" | ">" | "<" | "=";
export interface Constraint {
  op: ComparisonOp;
  version: string;
  wildcard: boolean;
}

export interface ParsedRange {
  constraints: Constraint[];
  valid: boolean;
}

/**
 * Parse a range expression such as `>=1.0.0, <1.25.3`, `1.2.*` or `>= 2.0`. Supported operators are
 * `>= <= > < =`; a bare version means equality; a trailing `*`/`x` is a prefix wildcard.
 */
export function parseRange(input: string): ParsedRange {
  const raw = (input ?? "").trim();
  if (raw === "" || raw === "*") return { constraints: [], valid: true };
  // Normalise `>= 1.0` → `>=1.0`, then split on commas/whitespace.
  const normalised = raw.replace(/(>=|<=|>|<|==|=)\s+/g, "$1");
  const parts = normalised.split(/[\s,]+/).filter(Boolean);
  const constraints: Constraint[] = [];
  for (const part of parts) {
    const m = /^(>=|<=|>|<|==|=)?\s*(.+)$/.exec(part);
    if (!m) return { constraints: [], valid: false };
    const opRaw = (m[1] ?? "=") as ComparisonOp | "==";
    const op: ComparisonOp = opRaw === "==" ? "=" : opRaw;
    let version = m[2]!.trim();
    const wildcard = /[*xX]$/.test(version);
    if (wildcard) version = version.replace(/[*xX]+$/, "").replace(/\.$/, "");
    constraints.push({ op, version, wildcard });
  }
  return { constraints, valid: constraints.length > 0 };
}

/** True when `version` satisfies every constraint. Unparseable input yields `null` (not `false`). */
export function versionInRange(version: string, range: string): boolean | null {
  const v = parseVersion(version);
  if (!v.valid) return null;
  const parsed = parseRange(range);
  if (!parsed.valid) return null;
  for (const c of parsed.constraints) {
    if (c.wildcard) {
      // Prefix match on segment boundaries: `1.2` matches `1.2`, `1.2.3` but not `1.20`.
      if (!versionHasPrefix(version, c.version)) return false;
      continue;
    }
    const cmp = compareVersions(version, c.version);
    switch (c.op) {
      case ">=":
        if (cmp < 0) return false;
        break;
      case "<=":
        if (cmp > 0) return false;
        break;
      case ">":
        if (cmp <= 0) return false;
        break;
      case "<":
        if (cmp >= 0) return false;
        break;
      case "=":
        if (cmp !== 0) return false;
        break;
    }
  }
  return true;
}

/** Segment-boundary prefix test used for wildcard ranges. */
export function versionHasPrefix(version: string, prefix: string): boolean {
  const v = parseVersion(version);
  const p = parseVersion(prefix);
  if (!v.valid || !p.valid) return false;
  if (p.segments.length > v.segments.length) return false;
  for (let i = 0; i < p.segments.length; i++) {
    if (compareSegment(v.segments[i], p.segments[i]) !== 0) return false;
  }
  return true;
}
