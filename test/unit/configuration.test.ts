import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "@reconnexus/configuration";

const configFixture = fileURLToPath(new URL("../fixtures/config/valid.json", import.meta.url));

describe("configuration loader", () => {
  it("loads defaults when no file is present", () => {
    const cfg = loadConfig({ cwd: "/tmp", env: { USER: "tester" } as NodeJS.ProcessEnv });
    expect(cfg.schemaVersion).toBe(1);
    expect(cfg.database.url).toContain("reconnexus");
    expect(cfg.network.allowRestrictedAddresses).toBe(false);
    expect(cfg.artifacts.root.startsWith("/")).toBe(true);
  });

  it("applies a config file over defaults", () => {
    const cfg = loadConfig({ cwd: "/tmp", env: {} as NodeJS.ProcessEnv, configPath: configFixture });
    expect(cfg.database.url).toContain("reconnexus_test");
    expect(cfg.logging.level).toBe("warn");
  });

  it("lets environment override the file", () => {
    const cfg = loadConfig({
      cwd: "/tmp",
      configPath: configFixture,
      env: { RECONNEXUS_DATABASE_URL: "postgres://envhost/db" } as NodeJS.ProcessEnv,
    });
    expect(cfg.database.url).toBe("postgres://envhost/db");
  });

  it("rejects an invalid config file", () => {
    expect(() =>
      loadConfig({ cwd: "/tmp", env: {} as NodeJS.ProcessEnv, configPath: "/nonexistent/config.json" }),
    ).toThrow(ConfigError);
  });

  it("keeps restricted addresses denied by default and allows opt-in via env", () => {
    const relaxed = loadConfig({ cwd: "/tmp", env: { RECONNEXUS_ALLOW_RESTRICTED: "true" } as NodeJS.ProcessEnv });
    expect(relaxed.network.allowRestrictedAddresses).toBe(true);
  });
});
