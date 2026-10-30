import type { ReportFinding } from "@reconnexus/contracts";
import type { Repository } from "../repository.js";
import { loadScanFindings, type PortFindingInput } from "../reporting/findings.js";

/**
 * Per-host risk ranking. It is a prioritization aid for deciding where to look first, not a
 * vulnerability rating: every input is a candidate or an observation (nothing is exploited or
 * validated), and the score says how much attention a host deserves, not how likely it is to be
 * compromised.
 *
 * The score is deterministic and explainable. Each contribution is a named factor with its points,
 * the raw points are summed, and the sum is squashed onto 0-100 with diminishing returns so a host
 * with many low-grade signals cannot outrank one with a serious signal, and ten findings are not
 * ten times worse than one.
 */

export interface RiskFactor {
  kind: "finding" | "attack-surface" | "login-interface";
  label: string;
  points: number;
  /** Finding id, when the factor comes from a finding. */
  ref?: string;
}

export const RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export interface HostRisk {
  host: string;
  /** 0-100, higher means look sooner. */
  score: number;
  level: RiskLevel;
  /** Sum of factor points before squashing. */
  rawPoints: number;
  findingCount: number;
  openPorts: number[];
  /** Largest contributions first. */
  factors: RiskFactor[];
}

export interface LoginRiskInput {
  host: string;
  kind: string;
  status: string;
}

export interface RiskInputs {
  findings: readonly ReportFinding[];
  ports: readonly PortFindingInput[];
  logins: readonly LoginRiskInput[];
}

const SEVERITY_POINTS: Record<string, number> = { CRITICAL: 40, HIGH: 25, MEDIUM: 12, LOW: 4, INFO: 1 };
/**
 * Findings of one severity add at most this many times a single finding's points to a host, so
 * volume cannot outweigh severity: many LOW findings never add up to a HIGH one.
 */
const TIER_CAP_MULTIPLE = 2;
const VALIDATION_WEIGHT: Record<string, number> = { VALIDATED: 1, SUSPECTED: 0.8, OBSERVED: 0.7, INDETERMINATE: 0.3, REJECTED: 0 };
const WEB_PORTS = new Set([80, 443]);
const PORT_POINTS_EACH = 2;
const PORT_POINTS_CAP = 10;
const LOGIN_POINTS: Record<string, Record<string, number>> = {
  ADMIN: { DETECTED: 8, POSSIBLE: 3 },
  CPANEL: { DETECTED: 10, POSSIBLE: 4 },
};
/** Raw points at which the score reaches ~63; chosen so a single HIGH finding lands in MEDIUM. */
const SATURATION = 50;
const MAX_FACTORS = 8;

const round1 = (n: number): number => Math.round(n * 10) / 10;

export function riskLevel(score: number): RiskLevel {
  if (score >= 70) return "CRITICAL";
  if (score >= 45) return "HIGH";
  if (score >= 20) return "MEDIUM";
  if (score > 0) return "LOW";
  return "MINIMAL";
}

/** The host a finding is about: a URL subject (such as a JS artifact) reduces to its hostname. */
export function hostOfSubject(subject: string): string {
  const s = subject.trim().toLowerCase();
  if (!s) return "";
  if (s.includes("://")) {
    try {
      return new URL(s).hostname;
    } catch {
      return s;
    }
  }
  return s;
}

export function assessRisk(inputs: RiskInputs): HostRisk[] {
  interface Acc {
    factors: RiskFactor[];
    findings: number;
    ports: Set<number>;
    tierUsed: Map<string, number>;
  }
  const hosts = new Map<string, Acc>();
  const acc = (host: string): Acc => {
    let a = hosts.get(host);
    if (!a) hosts.set(host, (a = { factors: [], findings: 0, ports: new Set(), tierUsed: new Map() }));
    return a;
  };

  for (const f of inputs.findings) {
    const host = hostOfSubject(f.subject);
    if (!host) continue;
    const weight = VALIDATION_WEIGHT[f.validation] ?? 0.5;
    const wanted = round1((SEVERITY_POINTS[f.severity] ?? 0) * weight * (0.5 + 0.5 * f.confidence));
    if (wanted <= 0) continue;
    const a = acc(host);
    a.findings++;
    const used = a.tierUsed.get(f.severity) ?? 0;
    const points = round1(Math.min(wanted, (SEVERITY_POINTS[f.severity] ?? 0) * TIER_CAP_MULTIPLE - used));
    if (points <= 0) continue;
    a.tierUsed.set(f.severity, used + points);
    a.factors.push({ kind: "finding", label: `${f.severity} ${f.category.toLowerCase().replace(/_/g, " ")}: ${f.title}`, points, ref: f.id });
  }

  // Open ports are grouped by host, so a host that merely shares an address is credited with it too.
  for (const p of inputs.ports) {
    if (p.state !== "OPEN" || p.protocol !== "tcp" || !p.host) continue;
    acc(p.host.toLowerCase()).ports.add(p.port);
  }
  for (const [, a] of hosts) {
    const nonWeb = Array.from(a.ports).filter((p) => !WEB_PORTS.has(p));
    if (nonWeb.length > 0) {
      const points = Math.min(PORT_POINTS_CAP, nonWeb.length * PORT_POINTS_EACH);
      a.factors.push({ kind: "attack-surface", label: `${nonWeb.length} non-web open port${nonWeb.length === 1 ? "" : "s"} (${nonWeb.sort((x, y) => x - y).join(", ")})`, points });
    }
  }

  const seenLogin = new Set<string>();
  for (const l of inputs.logins) {
    const host = l.host.toLowerCase();
    const points = LOGIN_POINTS[l.kind]?.[l.status];
    const key = `${host}\u0000${l.kind}\u0000${l.status}`;
    if (!host || !points || seenLogin.has(key)) continue;
    seenLogin.add(key);
    acc(host).factors.push({ kind: "login-interface", label: `${l.kind === "CPANEL" ? "control-panel" : "admin login"} interface ${l.status.toLowerCase()}`, points });
  }

  const out: HostRisk[] = [];
  for (const [host, a] of hosts) {
    const raw = round1(a.factors.reduce((sum, f) => sum + f.points, 0));
    const score = round1(100 * (1 - Math.exp(-raw / SATURATION)));
    const factors = a.factors.sort((x, y) => y.points - x.points || (x.label < y.label ? -1 : 1));
    out.push({ host, score, level: riskLevel(score), rawPoints: raw, findingCount: a.findings, openPorts: Array.from(a.ports).sort((x, y) => x - y), factors: factors.slice(0, MAX_FACTORS) });
  }
  return out.sort((x, y) => y.score - x.score || (x.host < y.host ? -1 : x.host > y.host ? 1 : 0));
}

/** Loads a scan's persisted findings, ports and login interfaces and ranks its hosts. */
export async function loadScanRisk(repo: Repository, scanId: string): Promise<HostRisk[]> {
  const [findings, portRows, loginRows] = await Promise.all([loadScanFindings(repo, scanId), repo.listPortObservations(scanId), repo.listLoginInterfaces(scanId)]);
  const ports = portRows.map((r) => {
    const d = r.data as Partial<PortFindingInput>;
    return { host: d.host ?? "", ip: d.ip ?? "", port: d.port ?? 0, protocol: d.protocol ?? "tcp", state: d.state ?? "", service: d.service ?? "", product: d.product ?? "", version: d.version ?? "" };
  });
  const logins = loginRows.map((r) => {
    const d = r.data as { kind?: string; status?: string; host?: string };
    return { host: d.host ?? hostOfSubject(r.url), kind: d.kind ?? "", status: d.status ?? "" };
  });
  return assessRisk({ findings, ports, logins });
}
