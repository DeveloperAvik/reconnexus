import { describe, expect, it } from "vitest";
import { dependenciesSatisfied, deriveScanStatus } from "../../apps/control-plane/src/orchestration/scan-status.js";
import type { JobRow } from "../../apps/control-plane/src/repository.js";

const job = (job_key: string, status: string, depends_on: string[] = []): JobRow => ({ job_key, status, depends_on }) as unknown as JobRow;

describe("deriveScanStatus (scan status from job statuses)", () => {
  it("is SUCCEEDED only when every job succeeded", () => {
    expect(deriveScanStatus(["SUCCEEDED", "SUCCEEDED"])).toBe("SUCCEEDED");
  });
  it("is PARTIAL when any job is still RUNNING or QUEUED, whatever else happened", () => {
    expect(deriveScanStatus(["SUCCEEDED", "RUNNING"])).toBe("PARTIAL");
    expect(deriveScanStatus(["FAILED", "QUEUED"])).toBe("PARTIAL");
    expect(deriveScanStatus(["SUCCEEDED", "SUCCEEDED", "QUEUED"])).toBe("PARTIAL");
  });
  it("is PARTIAL when some jobs produced data and others failed, were blocked or skipped", () => {
    expect(deriveScanStatus(["SUCCEEDED", "FAILED"])).toBe("PARTIAL");
    expect(deriveScanStatus(["SUCCEEDED", "SOURCE_UNAVAILABLE"])).toBe("PARTIAL");
    expect(deriveScanStatus(["PARTIAL", "BLOCKED"])).toBe("PARTIAL");
    expect(deriveScanStatus(["SUCCEEDED", "SKIPPED"])).toBe("PARTIAL");
    expect(deriveScanStatus(["PARTIAL", "PARTIAL"])).toBe("PARTIAL");
  });
  it("is FAILED when jobs failed, were unavailable or blocked and nothing succeeded", () => {
    expect(deriveScanStatus(["FAILED"])).toBe("FAILED");
    expect(deriveScanStatus(["FAILED", "SOURCE_UNAVAILABLE", "BLOCKED"])).toBe("FAILED");
    expect(deriveScanStatus(["FAILED", "SKIPPED"])).toBe("FAILED");
  });
  it("is PARTIAL when everything was skipped, and for statuses it does not classify", () => {
    expect(deriveScanStatus(["SKIPPED"])).toBe("PARTIAL");
    expect(deriveScanStatus(["SKIPPED", "SKIPPED"])).toBe("PARTIAL");
    expect(deriveScanStatus(["CANCELLED"])).toBe("PARTIAL"); // cancellation is decided by the caller, before this
  });
  it("characterization: an empty job list is SUCCEEDED (every() over nothing)", () => {
    expect(deriveScanStatus([])).toBe("SUCCEEDED");
  });
});

describe("dependenciesSatisfied (stage prerequisite gate)", () => {
  const all = [job("a", "SUCCEEDED"), job("b", "PARTIAL"), job("c", "SKIPPED"), job("d", "FAILED"), job("e", "SOURCE_UNAVAILABLE"), job("f", "BLOCKED"), job("g", "RUNNING"), job("h", "QUEUED")];
  const gate = (deps: string[], completed: string[] = []) => dependenciesSatisfied(job("x", "QUEUED", deps), all, new Set(completed));

  it("has no prerequisites to wait for", () => {
    expect(gate([])).toBe(true);
  });
  it("is satisfied by SUCCEEDED, PARTIAL and SKIPPED prerequisites", () => {
    expect(gate(["a"])).toBe(true);
    expect(gate(["b"])).toBe(true);
    expect(gate(["c"])).toBe(true);
    expect(gate(["a", "b", "c"])).toBe(true);
  });
  it("is not satisfied by FAILED, SOURCE_UNAVAILABLE, BLOCKED, RUNNING or QUEUED prerequisites", () => {
    for (const k of ["d", "e", "f", "g", "h"]) expect(gate([k]), k).toBe(false);
  });
  it("requires every prerequisite, not just one", () => {
    expect(gate(["a", "d"])).toBe(false);
  });
  it("accepts a prerequisite already recorded as completed in this run even if its row says otherwise", () => {
    expect(gate(["d"], ["d"])).toBe(true);
    expect(gate(["g"], ["g"])).toBe(true);
  });
  it("ignores prerequisites that are not in the job list", () => {
    expect(gate(["missing"])).toBe(true);
    expect(gate(["missing", "d"])).toBe(false);
  });
});
