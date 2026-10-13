import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { ConfigSchema, PartialConfigSchema, type PartialConfig, type ReconNexusConfig } from "./schema.js";

export class ConfigError extends Error {
  constructor(message: string, readonly details?: unknown) {
    super(message);
    this.name = "ConfigError";
  }
}

const CONFIG_FILE_NAMES = ["reconnexus.config.json", ".reconnexusrc.json", "reconnexus.json"];

/** Walk up from `startDir` looking for the monorepo root marker (`go.work` or root package.json). */
export function findRepoRoot(startDir: string = process.cwd()): string | null {
  let dir = resolve(startDir);
  for (;;) {
    if (existsSync(join(dir, "go.work"))) return dir;
    const pkg = join(dir, "package.json");
    if (existsSync(pkg)) {
      try {
        const parsed = JSON.parse(readFileSync(pkg, "utf8")) as { name?: string };
        if (parsed.name === "reconnexus") return dir;
      } catch {
        /* ignore malformed */
      }
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function deepMerge<T extends Record<string, unknown>>(base: T, overlay: Record<string, unknown>): T {
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(overlay)) {
    if (v === undefined) continue;
    const existing = out[k];
    if (isPlainObject(existing) && isPlainObject(v)) {
      out[k] = deepMerge(existing, v);
    } else {
      out[k] = v;
    }
  }
  return out as T;
}

function readConfigFile(path: string): PartialConfig {
  if (!existsSync(path)) throw new ConfigError(`config file not found: ${path}`);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new ConfigError(`config file is not valid JSON: ${path}`, e);
  }
  const parsed = PartialConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigError(`config file failed schema validation: ${path}`, parsed.error.flatten());
  }
  if (parsed.data.schemaVersion !== undefined && parsed.data.schemaVersion !== 1) {
    throw new ConfigError(`unsupported config schemaVersion ${parsed.data.schemaVersion}`);
  }
  return parsed.data;
}

function envOverlay(env: NodeJS.ProcessEnv): PartialConfig {
  const overlay: Record<string, unknown> = {};
  const dbUrl = env.RECONNEXUS_DATABASE_URL ?? env.DATABASE_URL;
  if (dbUrl) overlay.database = { ...(overlay.database as object), url: dbUrl };
  if (env.RECONNEXUS_DB_POOL_SIZE) {
    overlay.database = { ...(overlay.database as object), poolSize: Number(env.RECONNEXUS_DB_POOL_SIZE) };
  }
  if (env.RECONNEXUS_REDIS_URL) overlay.redis = { enabled: true, url: env.RECONNEXUS_REDIS_URL };
  if (env.RECONNEXUS_ARTIFACTS_DIR) overlay.artifacts = { root: env.RECONNEXUS_ARTIFACTS_DIR };
  if (env.RECONNEXUS_LOG_LEVEL) overlay.logging = { ...(overlay.logging as object), level: env.RECONNEXUS_LOG_LEVEL };
  if (env.RECONNEXUS_LOG_FORMAT) overlay.logging = { ...(overlay.logging as object), format: env.RECONNEXUS_LOG_FORMAT };
  if (env.RECONNEXUS_ALLOW_RESTRICTED === "1" || env.RECONNEXUS_ALLOW_RESTRICTED === "true") {
    overlay.network = { allowRestrictedAddresses: true };
  }
  return overlay as PartialConfig;
}

export interface LoadOptions {
  cwd?: string;
  configPath?: string;
  env?: NodeJS.ProcessEnv;
  overrides?: PartialConfig;
}

/**
 * Load configuration from defaults → config file → environment → explicit overrides,
 * then validate the merged result. Database URL and migrations dir are resolved to absolute paths.
 */
export function loadConfig(options: LoadOptions = {}): ReconNexusConfig {
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env;
  const repoRoot = findRepoRoot(cwd) ?? cwd;

  const defaults: PartialConfig = {
    schemaVersion: 1,
    database: {
      url: `postgres://${env.USER ?? "postgres"}@127.0.0.1:5432/reconnexus`,
      poolSize: 10,
      statementTimeoutMs: 60000,
    },
    redis: { enabled: false, url: "redis://127.0.0.1:6379" },
    artifacts: { root: join(repoRoot, ".reconnexus", "artifacts") },
    logging: { level: "info", format: "json" },
    network: { allowRestrictedAddresses: false, requestTimeoutMs: 15000, maxRedirects: 5 },
    providers: {},
    migrationsDir: join(repoRoot, "db", "migrations"),
  };

  let fileConfig: PartialConfig = {};
  const explicit = options.configPath ?? env.RECONNEXUS_CONFIG;
  if (explicit) {
    fileConfig = readConfigFile(isAbsolute(explicit) ? explicit : resolve(cwd, explicit));
  } else {
    for (const name of CONFIG_FILE_NAMES) {
      const candidate = join(repoRoot, name);
      if (existsSync(candidate)) {
        fileConfig = readConfigFile(candidate);
        break;
      }
    }
  }

  let merged = deepMerge(defaults as Record<string, unknown>, fileConfig as Record<string, unknown>);
  merged = deepMerge(merged, envOverlay(env) as Record<string, unknown>);
  if (options.overrides) merged = deepMerge(merged, options.overrides as Record<string, unknown>);

  const parsed = ConfigSchema.safeParse(merged);
  if (!parsed.success) {
    throw new ConfigError("configuration failed validation", parsed.error.flatten());
  }
  const cfg = parsed.data;

  // Expand ~ and make paths absolute relative to repo root.
  const expand = (p: string): string => {
    const expanded = p.startsWith("~") ? join(homedir(), p.slice(1)) : p;
    return isAbsolute(expanded) ? expanded : resolve(repoRoot, expanded);
  };
  cfg.artifacts = { ...cfg.artifacts, root: expand(cfg.artifacts.root) };
  cfg.migrationsDir = expand(cfg.migrationsDir);
  if (cfg.defaultPolicyFile) cfg.defaultPolicyFile = expand(cfg.defaultPolicyFile);

  return cfg;
}

export function validateConfig(raw: unknown): { ok: true; config: ReconNexusConfig } | { ok: false; errors: unknown } {
  const parsed = ConfigSchema.safeParse(raw);
  if (!parsed.success) return { ok: false, errors: parsed.error.flatten() };
  return { ok: true, config: parsed.data };
}
