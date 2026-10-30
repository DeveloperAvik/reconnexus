import { describe, expect, it } from "vitest";
import { StageId } from "@reconnexus/contracts";
import { applyProfileLimits, plannedStagesFor, profileFromSnapshot, resolveScanProfile, SCAN_PROFILES, UnknownProfileError } from "@reconnexus/control-plane";

const limits = { maxConcurrency: 8, requestsPerSecond: 10, crawlDepth: 3, maxRuntimeSeconds: 1800, maxArtifactBytes: 8 * 1024 * 1024 };

describe("scan profiles", () => {
  it("only ever tighten the policy limits", () => {
    const stealth = applyProfileLimits(limits, SCAN_PROFILES.stealth);
    expect(stealth).toMatchObject({ requestsPerSecond: 2, maxConcurrency: 2, crawlDepth: 1 });
    const slowPolicy = { ...limits, requestsPerSecond: 1, maxConcurrency: 1, crawlDepth: 0 };
    expect(applyProfileLimits(slowPolicy, SCAN_PROFILES.stealth)).toMatchObject({ requestsPerSecond: 1, maxConcurrency: 1, crawlDepth: 0 });
    expect(applyProfileLimits(limits, SCAN_PROFILES.deep)).toEqual(limits);
    expect(applyProfileLimits(limits, null)).toBe(limits);
  });

  it("leave excluded stages out of the plan and keep the chain intact", () => {
    const caps = ["PASSIVE", "DNS", "ACTIVE_HTTP", "PORT_SCAN", "ACTIVE_TEMPLATE_CHECK"];
    const standard = plannedStagesFor(caps, SCAN_PROFILES.standard);
    expect(standard).toContain(StageId.PORT_SCAN);
    expect(standard).toContain(StageId.TEMPLATE_CHECKS);
    const quick = plannedStagesFor(caps, SCAN_PROFILES.quick);
    for (const s of [StageId.PORT_SCAN, StageId.TEMPLATE_CHECKS, StageId.LOGIN_FINDER]) expect(quick).not.toContain(s);
    expect(quick).toContain(StageId.REPORTING);
    expect(quick[0]).toBe(StageId.INPUT_AUTHORIZATION);
  });

  it("never plan opt-in stages the policy does not grant, whatever the profile", () => {
    const deep = plannedStagesFor(["PASSIVE", "DNS", "ACTIVE_HTTP"], SCAN_PROFILES.deep);
    expect(deep).not.toContain(StageId.PORT_SCAN);
    expect(deep).not.toContain(StageId.TEMPLATE_CHECKS);
    expect(plannedStagesFor([])).not.toContain(StageId.PORT_SCAN);
  });

  it("deep's port selection fits the worker's limit", () => {
    let total = 0;
    for (const part of SCAN_PROFILES.deep.ports!.split(",")) {
      const [a, b] = part.split("-").map(Number);
      total += (b ?? a!) - a! + 1;
    }
    expect(total).toBeLessThanOrEqual(2048);
  });

  it("resolve by name and from a scan snapshot", () => {
    expect(resolveScanProfile("quick").name).toBe("quick");
    expect(() => resolveScanProfile("loud")).toThrow(UnknownProfileError);
    expect(profileFromSnapshot({ scanProfile: "deep" })?.name).toBe("deep");
    expect(profileFromSnapshot({ scanProfile: "nope" })).toBeNull();
    expect(profileFromSnapshot(null)).toBeNull();
  });
});
