import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DiscoveryRecordSchema } from "@reconnexus/contracts";

const workersDir = fileURLToPath(new URL("../../workers", import.meta.url));

function goAvailable(): boolean {
  try {
    execFileSync("go", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

interface Samples {
  types: string[];
  records: Array<Record<string, unknown>>;
}

/**
 * The Go worker and the TypeScript contracts describe the same records in two languages, and a
 * divergence is invisible to the rest of the suite: every other test drives the orchestrator with
 * an in-process runner that already speaks the TypeScript shape. This check marshals one record of
 * every type through the real Go code and validates it here, which is what catches a payload that
 * drifts (a nested object where the contract is flat) or a nil slice emitted as `null`.
 */
describe("record-shape conformance (Go worker ↔ contracts)", () => {
  const run = goAvailable() ? it : it.skip;
  run("validates one record of every type against DiscoveryRecordSchema", () => {
    const out = execFileSync("go", ["run", "./cmd/record-samples"], {
      cwd: workersDir,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    const samples = JSON.parse(out) as Samples;

    expect(samples.records.length).toBe(samples.types.length);
    expect(samples.records.map((r) => r.type)).toEqual(samples.types);

    for (const record of samples.records) {
      const parsed = DiscoveryRecordSchema.safeParse(record);
      expect(
        parsed.success,
        `record ${String(record.type)} failed the contract: ${
          parsed.success ? "" : JSON.stringify(parsed.error.issues)
        }`,
      ).toBe(true);
    }
  });
});
