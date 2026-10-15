import { describe, expect, it } from "vitest";
import { compareVersions, parseVersion, parseRange, versionHasPrefix, versionInRange } from "@reconnexus/control-plane";

describe("version comparison", () => {
  it("orders numeric segments numerically, not lexically", () => {
    expect(compareVersions("1.2.3", "1.2.4")).toBeLessThan(0);
    expect(compareVersions("1.2.10", "1.2.9")).toBeGreaterThan(0);
    expect(compareVersions("2.0", "1.99.99")).toBeGreaterThan(0);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
    expect(compareVersions("v1.2.3", "1.2.3")).toBe(0);
    // 1.0 < 1.0.1 (missing segment is lower)
    expect(compareVersions("1.0", "1.0.1")).toBeLessThan(0);
  });

  it("treats a pre-release as lower than the bare release", () => {
    expect(compareVersions("1.2.3-rc1", "1.2.3")).toBeLessThan(0);
    expect(compareVersions("1.2.3", "1.2.3-rc1")).toBeGreaterThan(0);
    expect(compareVersions("1.2.3-rc1", "1.2.3-rc2")).toBeLessThan(0);
  });

  it("parses versions defensively", () => {
    expect(parseVersion("1.2.3").valid).toBe(true);
    expect(parseVersion("").valid).toBe(false);
    expect(parseVersion("1.2.3").segments).toEqual([1, 2, 3]);
  });
});

describe("version ranges", () => {
  it("evaluates compound ranges", () => {
    const range = ">=1.0.0 <1.25.3";
    expect(versionInRange("1.0.0", range)).toBe(true);
    expect(versionInRange("1.25.2", range)).toBe(true);
    expect(versionInRange("1.25.3", range)).toBe(false); // exclusive upper bound
    expect(versionInRange("0.9.9", range)).toBe(false);
  });

  it("accepts comma- and space-separated constraints and spaced operators", () => {
    expect(versionInRange("2.4.1", ">= 2.0, < 3.0")).toBe(true);
    expect(parseRange(">= 2.0 < 3.0").valid).toBe(true);
  });

  it("matches prefix wildcards on segment boundaries", () => {
    expect(versionInRange("1.2.9", "1.2.*")).toBe(true);
    expect(versionInRange("1.2", "1.2.*")).toBe(true);
    expect(versionInRange("1.20.0", "1.2.*")).toBe(false); // 1.2 is not a prefix of 1.20
    expect(versionHasPrefix("1.2.3", "1.2")).toBe(true);
    expect(versionHasPrefix("1.20", "1.2")).toBe(false);
  });

  it("returns null (not false) for unparseable input, so it can never manufacture a match", () => {
    expect(versionInRange("not-a-version", ">=1.0")).toBeNull();
    expect(versionInRange("1.0", "")).toBe(true); // empty range = matches everything
  });
});
