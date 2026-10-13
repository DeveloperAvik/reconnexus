export type IpVersion = 4 | 6;

export interface ParsedIp {
  version: IpVersion;
  value: bigint;
  canonical: string;
}

export interface IpClassification {
  isPrivate: boolean;
  isLoopback: boolean;
  isLinkLocal: boolean;
  isUniqueLocal: boolean;
  isCGNAT: boolean;
  isMulticast: boolean;
  isUnspecified: boolean;
  isBroadcast: boolean;
  isReserved: boolean;
  isMetadata: boolean;
  /** true when any of the above non-routable/special categories apply */
  isSpecial: boolean;
}

const V4_MAX = 0xffffffffn;
const V6_MAX = (1n << 128n) - 1n;

function v4ToBigInt(o1: number, o2: number, o3: number, o4: number): bigint {
  return (
    (BigInt(o1) << 24n) | (BigInt(o2) << 16n) | (BigInt(o3) << 8n) | BigInt(o4)
  );
}

function parseV4(input: string): ParsedIp | null {
  const parts = input.split(".");
  if (parts.length !== 4) return null;
  const nums: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith("0")) return null; // reject octal-ish
    const n = Number(part);
    if (n > 255) return null;
    nums.push(n);
  }
  const [a, b, c, d] = nums as [number, number, number, number];
  const value = v4ToBigInt(a, b, c, d);
  return { version: 4, value, canonical: `${a}.${b}.${c}.${d}` };
}

function parseV6(input: string): ParsedIp | null {
  let addr = input;
  const zone = addr.indexOf("%");
  if (zone !== -1) addr = addr.slice(0, zone);
  if (addr.length === 0) return null;

  const doubleColonCount = (addr.match(/::/g) ?? []).length;
  if (doubleColonCount > 1) return null;
  const hasDoubleColon = doubleColonCount === 1;

  let headParts: string[];
  let tailParts: string[] | null;
  if (hasDoubleColon) {
    const idx = addr.indexOf("::");
    const left = addr.slice(0, idx);
    const right = addr.slice(idx + 2);
    headParts = left.length ? left.split(":") : [];
    tailParts = right.length ? right.split(":") : [];
  } else {
    headParts = addr.split(":");
    tailParts = null;
  }

  const toGroups = (tokens: string[], allowV4: boolean): number[] | null => {
    const out: number[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i]!;
      if (tok.includes(".")) {
        if (!allowV4 || i !== tokens.length - 1) return null;
        const v4 = parseV4(tok);
        if (!v4) return null;
        out.push(Number((v4.value >> 16n) & 0xffffn));
        out.push(Number(v4.value & 0xffffn));
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(tok)) return null;
        out.push(parseInt(tok, 16));
      }
    }
    return out;
  };

  const headGroups = toGroups(headParts, !hasDoubleColon);
  if (headGroups === null) return null;

  let full: number[];
  if (tailParts !== null) {
    const tailGroups = toGroups(tailParts, true);
    if (tailGroups === null) return null;
    const missing = 8 - (headGroups.length + tailGroups.length);
    if (missing < 1) return null;
    full = [...headGroups, ...new Array<number>(missing).fill(0), ...tailGroups];
  } else {
    full = headGroups;
  }
  if (full.length !== 8) return null;

  let value = 0n;
  for (const g of full) value = (value << 16n) | BigInt(g);

  return { version: 6, value, canonical: canonicalizeV6(full, value) };
}

function canonicalizeV6(groups: number[], value: bigint): string {
  // unwrap IPv4-mapped ::ffff:0:0/96 and ::ffff:0:0:0/96
  const mapped = unwrapV4Mapped(value, groups);
  if (mapped) return `::ffff:${mapped}`;
  return formatV6(groups);
}

function formatV6(groups: number[]): string {
  const hex = groups.map((g) => g.toString(16));
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) return hex.join(":");
  const left = hex.slice(0, bestStart).join(":");
  const right = hex.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}

function unwrapV4Mapped(value: bigint, groups: number[]): string | null {
  // ::ffff:a.b.c.d  -> groups[0..4]=0, groups[5]=0xffff
  const zeroPrefix = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0;
  if (!zeroPrefix || groups[5] !== 0xffff) return null;
  const v4 = (BigInt(groups[6]!) << 16n) | BigInt(groups[7]!);
  return `${Number((v4 >> 24n) & 0xffn)}.${Number((v4 >> 16n) & 0xffn)}.${Number((v4 >> 8n) & 0xffn)}.${Number(v4 & 0xffn)}`;
}

/** Parse an IPv4 or IPv6 literal. Returns null for anything that is not an IP literal (no hostnames). */
export function parseIp(input: string): ParsedIp | null {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.includes(":")) return parseV6(trimmed);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) return parseV4(trimmed);
  return null;
}

/** Unwrap an IPv4-mapped IPv6 literal to its IPv4 form. */
export function unwrapIpv4Mapped(ip: ParsedIp): ParsedIp {
  if (ip.version !== 6) return ip;
  const v4 = ip.value & 0xffffffffn;
  const high = ip.value >> 32n;
  // ::ffff:0:0/96
  if (high === 0xffffn) {
    return parseV4(
      `${Number((v4 >> 24n) & 0xffn)}.${Number((v4 >> 16n) & 0xffn)}.${Number((v4 >> 8n) & 0xffn)}.${Number(v4 & 0xffn)}`,
    )!;
  }
  return ip;
}

function inRange(value: bigint, base: string, prefix: number): boolean {
  const b = parseIp(base);
  if (!b) return false;
  const width = b.version === 4 ? 32 : 128;
  if (prefix <= 0) return true;
  if (prefix > width) return false;
  const shift = BigInt(width - prefix);
  return (value >> shift) === (b.value >> shift);
}

/** Classify an address into special-purpose categories (RFC 6890 and friends). */
export function classifyIp(ip: ParsedIp): IpClassification {
  const v = unwrapIpv4Mapped(ip);
  const is4 = v.version === 4;
  const value = v.value;

  const loopback = is4 ? inRange(value, "127.0.0.0", 8) : value === 1n;
  const linkLocal = is4
    ? inRange(value, "169.254.0.0", 16)
    : inRange(value, "fe80::", 10);
  const privateV4 = inRange(value, "10.0.0.0", 8) || inRange(value, "172.16.0.0", 12) || inRange(value, "192.168.0.0", 16);
  const uniqueLocal = !is4 && inRange(value, "fc00::", 7);
  const isPrivate = is4 ? privateV4 : uniqueLocal;
  const cgnat = is4 && inRange(value, "100.64.0.0", 10);
  const multicast = is4 ? inRange(value, "224.0.0.0", 4) : inRange(value, "ff00::", 8);
  const unspecified = value === 0n;
  const broadcast = is4 && value === V4_MAX;
  const reserved = is4
    ? inRange(value, "0.0.0.0", 8) ||
      inRange(value, "192.0.0.0", 24) ||
      inRange(value, "192.0.2.0", 24) ||
      inRange(value, "198.18.0.0", 15) ||
      inRange(value, "198.51.100.0", 24) ||
      inRange(value, "203.0.113.0", 24) ||
      inRange(value, "240.0.0.0", 4)
    : inRange(value, "2001:db8::", 32);
  const metadata = is4 && value === v4ToBigInt(169, 254, 169, 254);
  const metadataV6 = !is4 && value === (parseIp("fd00:ec2::254")!.value);

  const isMetadata = metadata || metadataV6;

  return {
    isPrivate,
    isLoopback: loopback,
    isLinkLocal: linkLocal,
    isUniqueLocal: uniqueLocal,
    isCGNAT: cgnat,
    isMulticast: multicast,
    isUnspecified: unspecified,
    isBroadcast: broadcast,
    isReserved: reserved,
    isMetadata,
    isSpecial:
      isPrivate || loopback || linkLocal || cgnat || multicast || unspecified || broadcast || reserved || isMetadata,
  };
}

export interface ParsedCidr {
  version: IpVersion;
  base: ParsedIp;
  prefix: number;
}

export function parseCidr(input: string): ParsedCidr | null {
  const trimmed = input.trim();
  const slash = trimmed.lastIndexOf("/");
  if (slash === -1) {
    const base = parseIp(trimmed);
    if (!base) return null;
    return { version: base.version, base, prefix: base.version === 4 ? 32 : 128 };
  }
  const ipPart = trimmed.slice(0, slash);
  const prefixPart = trimmed.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefixPart)) return null;
  const base = parseIp(ipPart);
  if (!base) return null;
  const prefix = Number(prefixPart);
  const width = base.version === 4 ? 32 : 128;
  if (prefix > width) return null;
  return { version: base.version, base, prefix };
}

export function cidrContains(cidr: ParsedCidr, ip: ParsedIp): boolean {
  const v = unwrapIpv4Mapped(ip);
  if (v.version !== cidr.version) return false;
  if (cidr.prefix === 0) return true;
  const shift = BigInt((v.version === 4 ? 32 : 128) - cidr.prefix);
  return (v.value >> shift) === (cidr.base.value >> shift);
}

export function ipInCidrList(ip: ParsedIp, cidrs: string[]): ParsedCidr | null {
  for (const c of cidrs) {
    const parsed = parseCidr(c);
    if (parsed && cidrContains(parsed, ip)) return parsed;
  }
  return null;
}

/** True when two IP literals denote the same address after canonicalization. */
export function ipEquals(a: ParsedIp, b: ParsedIp): boolean {
  const ua = unwrapIpv4Mapped(a);
  const ub = unwrapIpv4Mapped(b);
  return ua.version === ub.version && ua.value === ub.value;
}

export { V4_MAX, V6_MAX };
