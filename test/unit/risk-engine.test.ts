import { describe, expect, it } from "vitest";
import type { ReportFinding } from "@reconnexus/contracts";
import { assessRisk, hostOfSubject, riskLevel } from "@reconnexus/control-plane";

function finding(over: Partial<ReportFinding>): ReportFinding {
  return {
    id: "f", title: "t", category: "SOME_CATEGORY", severity: "HIGH", confidence: 1, validation: "SUSPECTED", subject: "a.example.com",
    sourceStage: "", sourceKind: "", evidence: "", evidenceRefs: [], remediation: "", references: [], ...over,
  };
}

describe("risk engine", () => {
  it("scores a host by weighted findings and is deterministic", () => {
    const inputs = { findings: [finding({ id: "1" }), finding({ id: "2", severity: "LOW" })], ports: [], logins: [] };
    const a = assessRisk(inputs);
    expect(a).toEqual(assessRisk(inputs));
    expect(a).toHaveLength(1);
    // HIGH suspected at full confidence = 25 * 0.8 * 1; LOW = 4 * 0.8 * 1.
    expect(a[0]!.rawPoints).toBe(23.2);
    expect(a[0]!.findingCount).toBe(2);
    expect(a[0]!.score).toBeGreaterThan(0);
    expect(a[0]!.score).toBeLessThan(100);
  });

  it("ranks the host with the serious signal above one with many weak signals", () => {
    const weak = Array.from({ length: 8 }, (_, i) => finding({ id: `w${i}`, severity: "LOW", subject: "weak.example.com" }));
    const strong = [finding({ id: "s", severity: "HIGH", subject: "strong.example.com" })];
    const ranked = assessRisk({ findings: [...weak, ...strong], ports: [], logins: [] });
    expect(ranked.map((h) => h.host)).toEqual(["strong.example.com", "weak.example.com"]);
  });

  it("gives rejected findings no weight and lowers indeterminate ones", () => {
    const [rejected] = assessRisk({ findings: [finding({ validation: "REJECTED" })], ports: [], logins: [] });
    expect(rejected).toBeUndefined();
    const [indet] = assessRisk({ findings: [finding({ validation: "INDETERMINATE" })], ports: [], logins: [] });
    expect(indet!.rawPoints).toBe(7.5);
  });

  it("attributes URL subjects to their host", () => {
    expect(hostOfSubject("https://App.Example.com:8443/static/app.js")).toBe("app.example.com");
    const [h] = assessRisk({ findings: [finding({ subject: "https://cdn.example.com/app.js" })], ports: [], logins: [] });
    expect(h!.host).toBe("cdn.example.com");
  });

  it("credits non-web open ports with a cap, and ignores 80/443 and closed ports", () => {
    const port = (p: number, state = "OPEN") => ({ host: "a.example.com", ip: "1.2.3.4", port: p, protocol: "tcp", state, service: "", product: "", version: "" });
    const [h] = assessRisk({ findings: [], ports: [port(80), port(443), port(22), port(6379), port(9999, "FILTERED")], logins: [] });
    expect(h!.openPorts).toEqual([22, 80, 443, 6379]);
    expect(h!.factors).toHaveLength(1);
    expect(h!.factors[0]!.points).toBe(4);
    const many = Array.from({ length: 20 }, (_, i) => port(2000 + i));
    expect(assessRisk({ findings: [], ports: many, logins: [] })[0]!.factors[0]!.points).toBe(10);
  });

  it("credits login interfaces once per host, kind and status", () => {
    const l = { host: "a.example.com", kind: "CPANEL", status: "DETECTED" };
    const [h] = assessRisk({ findings: [], ports: [], logins: [l, l, { host: "a.example.com", kind: "ADMIN", status: "POSSIBLE" }] });
    expect(h!.rawPoints).toBe(13);
  });

  it("keeps the score under 100 and maps scores to levels", () => {
    const [h] = assessRisk({ findings: Array.from({ length: 50 }, (_, i) => finding({ id: String(i), severity: "CRITICAL", validation: "VALIDATED" })), ports: [], logins: [] });
    expect(h!.score).toBeLessThanOrEqual(100);
    expect(h!.factors.length).toBeLessThanOrEqual(8);
    expect([riskLevel(0), riskLevel(1), riskLevel(20), riskLevel(45), riskLevel(70)]).toEqual(["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
  });

  it("returns hosts sorted by score then name", () => {
    const f = (host: string) => finding({ id: host, subject: host });
    const ranked = assessRisk({ findings: [f("b.example.com"), f("a.example.com")], ports: [], logins: [] });
    expect(ranked.map((h) => h.host)).toEqual(["a.example.com", "b.example.com"]);
  });
});

describe("risk engine tier caps", () => {
  it("caps each severity tier per host so volume cannot outweigh severity", () => {
    const lows = Array.from({ length: 40 }, (_, i) => finding({ id: `l${i}`, severity: "LOW" }));
    const [h] = assessRisk({ findings: lows, ports: [], logins: [] });
    expect(h!.rawPoints).toBe(8);
    expect(h!.findingCount).toBe(40);
  });
});
