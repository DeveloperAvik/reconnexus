import { describe, expect, it } from "vitest";
import { aggregate } from "@reconnexus/control-plane";

/**
 * Regression: a provider that returns PARTIAL must never be masked by its siblings (or by being
 * the only provider in the stage). Before the fix, `aggregate(["PARTIAL"])` and
 * `aggregate(["SUCCEEDED", "PARTIAL"])` both returned SUCCEEDED, so a scan could report every
 * stage SUCCEEDED while individual providers had only partially completed.
 */
describe("aggregate (stage status from provider outcomes)", () => {
  it("treats a lone PARTIAL provider as a partial stage, not a success", () => {
    expect(aggregate(["PARTIAL"])).toBe("PARTIAL");
  });

  it("treats a mix of SUCCEEDED and PARTIAL as partial", () => {
    expect(aggregate(["SUCCEEDED", "PARTIAL"])).toBe("PARTIAL");
    expect(aggregate(["SUCCEEDED", "SUCCEEDED", "PARTIAL"])).toBe("PARTIAL");
  });

  it("reports SUCCEEDED only when every provider succeeded", () => {
    expect(aggregate(["SUCCEEDED"])).toBe("SUCCEEDED");
    expect(aggregate(["SUCCEEDED", "SUCCEEDED"])).toBe("SUCCEEDED");
  });

  it("keeps hard failures distinguishable", () => {
    expect(aggregate(["FAILED"])).toBe("FAILED");
    expect(aggregate(["FAILED", "SOURCE_UNAVAILABLE"])).toBe("FAILED");
    expect(aggregate(["SUCCEEDED", "FAILED"])).toBe("PARTIAL");
    expect(aggregate(["SOURCE_UNAVAILABLE"])).toBe("SOURCE_UNAVAILABLE");
  });

  it("handles skipped, blocked, cancelled and empty outcome sets", () => {
    expect(aggregate([])).toBe("SKIPPED");
    expect(aggregate(["SKIPPED"])).toBe("SKIPPED");
    expect(aggregate(["BLOCKED"])).toBe("BLOCKED");
    expect(aggregate(["CANCELLED"])).toBe("CANCELLED");
    expect(aggregate(["FAILED", "SKIPPED"])).toBe("FAILED");
  });
});
