import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ScopePolicySchema } from "@reconnexus/contracts";
import { loadContext } from "../../apps/cli/src/context.js";
import { initCommand } from "../../apps/cli/src/commands/init.js";
import { discoverPolicyPaths, resolvePolicy } from "../../apps/cli/src/policy.js";

let dir: string;
const ctx = loadContext({});

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "reconnexus-init-"));
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("reconnexus init", () => {
  it("scaffolds a valid scope policy and config, and is discoverable", async () => {
    const r = await initCommand(ctx, { domain: "app.example.com", authorizedBy: "Sec Team", reference: "AUTH-1", cwd: dir });
    expect(r.exitCode).toBe(0);
    const data = r.data as { policyPath: string; configPath: string };
    const policy = ScopePolicySchema.parse(JSON.parse(readFileSync(data.policyPath, "utf8")));
    expect(policy.inScope.domains[0]?.value).toBe("example.com");
    expect(policy.inScope.domains[0]?.includeSubdomains).toBe(true);
    expect(policy.authorization.reference).toBe("AUTH-1");
    expect(policy.authorization.capabilities).toContain("SECRET_SCAN");

    const config = JSON.parse(readFileSync(data.configPath, "utf8")) as { defaultPolicyFile?: string };
    expect(config.defaultPolicyFile).toContain("policies/");

    // The single generated policy is auto-discovered for later commands.
    expect(discoverPolicyPaths(dir).length).toBe(1);
    const resolved = resolvePolicy(undefined, undefined, dir);
    expect(resolved.policy.policyId).toBe(policy.policyId);
  });

  it("keeps an existing policy unless --force is given", async () => {
    const r = await initCommand(ctx, { domain: "app.example.com", authorizedBy: "Other", cwd: dir });
    expect(r.exitCode).toBe(0);
    const data = r.data as { policyPath: string };
    const policy = ScopePolicySchema.parse(JSON.parse(readFileSync(data.policyPath, "utf8")));
    expect(policy.authorization.reference).toBe("AUTH-1"); // unchanged, not clobbered
  });

  it("updates defaultPolicyFile in an existing config without clobbering other settings", async () => {
    const other = mkdtempSync(join(tmpdir(), "reconnexus-init-default-"));
    try {
      const configPath = join(other, "reconnexus.config.json");
      writeFileSync(
        configPath,
        JSON.stringify({
          schemaVersion: 1,
          defaultPolicyFile: "./policies/old.example.json",
          logging: { level: "debug", format: "json" },
          database: { url: "postgres://localhost:5432/custom" },
        }),
      );
      const r = await initCommand(ctx, { domain: "https://dunya.com.pk/", authorizedBy: "you", reference: "Avik", cwd: other });
      expect(r.exitCode).toBe(0);
      const config = JSON.parse(readFileSync(configPath, "utf8")) as {
        defaultPolicyFile: string;
        logging: { level: string };
        database: { url: string };
      };
      expect(config.defaultPolicyFile).toBe("./policies/dunya.com.pk.json");
      expect(config.logging.level).toBe("debug");
      expect(config.database.url).toBe("postgres://localhost:5432/custom");
      expect((r.data as { configUpdated: boolean }).configUpdated).toBe(true);
      // The new default policy actually authorizes the requested target.
      const policy = ScopePolicySchema.parse(JSON.parse(readFileSync(join(other, "policies", "dunya.com.pk.json"), "utf8")));
      expect(policy.inScope.domains[0]?.value).toBe("dunya.com.pk");
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  });

  it("refuses when multiple policies are present", () => {
    writeFileSync(join(dir, "policies", "second.example.net.json"), JSON.stringify({ schemaVersion: 1 }));
    expect(() => resolvePolicy(undefined, undefined, dir)).toThrow(/multiple scope policies/);
  });
});
