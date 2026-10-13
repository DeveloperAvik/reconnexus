import { accessSync, constants } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { connect } from "node:net";
import { Client } from "pg";
import type { ProviderHealthReport } from "@reconnexus/contracts";
import type { ReconNexusConfig } from "@reconnexus/configuration";
import { execCapture } from "./exec.js";
import { PROVIDER_CATALOG, type CatalogEntry } from "../providers/catalog.js";

export * from "./exec.js";

export function findExecutable(name: string, pathEnv = process.env.PATH ?? ""): string | null {
  if (isAbsolute(name)) {
    try {
      accessSync(name, constants.X_OK);
      return name;
    } catch {
      return null;
    }
  }
  for (const dir of pathEnv.split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, name);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      /* keep searching */
    }
  }
  return null;
}

function parseVersion(output: string): string | undefined {
  const m = output.match(/\bv?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)/);
  return m ? m[1] : undefined;
}

export async function checkProvider(
  entry: CatalogEntry,
  overridePath?: string,
): Promise<ProviderHealthReport> {
  const path = overridePath ?? findExecutable(entry.binaryName);
  if (!path) {
    return { name: entry.name, status: "MISSING", message: `binary '${entry.binaryName}' not found on PATH` };
  }
  if (!entry.healthCheck) {
    return { name: entry.name, status: "OK", path, message: "binary present (no version probe)" };
  }
  const res = await execCapture([path, ...entry.healthCheck.argv], { timeoutMs: entry.healthCheck.timeoutMs, maxBytes: 64 * 1024 });
  if (res.spawnError) {
    return { name: entry.name, status: "FAILED_HEALTHCHECK", path, message: res.spawnError };
  }
  if (res.timedOut) {
    return { name: entry.name, status: "FAILED_HEALTHCHECK", path, message: "health check timed out" };
  }
  if (res.exitCode !== entry.healthCheck.expectExitCode) {
    return {
      name: entry.name,
      status: "FAILED_HEALTHCHECK",
      path,
      message: `health check exited ${res.exitCode} (expected ${entry.healthCheck.expectExitCode})`,
    };
  }
  const version = parseVersion(`${res.stdout}\n${res.stderr}`) ?? "unknown";
  return { name: entry.name, status: "OK", path, version, message: "healthy" };
}

export async function checkAllProviders(config?: ReconNexusConfig): Promise<ProviderHealthReport[]> {
  const reports: ProviderHealthReport[] = [];
  for (const entry of PROVIDER_CATALOG) {
    const override = config?.providers[entry.name]?.binaryPath;
    reports.push(await checkProvider(entry, override));
  }
  return reports;
}

export interface DependencyCheck {
  name: string;
  ok: boolean;
  version?: string;
  message: string;
}

export async function checkTool(name: string, argv: string[]): Promise<DependencyCheck> {
  const path = findExecutable(name);
  if (!path) return { name, ok: false, message: `not found on PATH` };
  const res = await execCapture([path, ...argv], { timeoutMs: 10000, maxBytes: 64 * 1024 });
  if (res.spawnError || res.timedOut) {
    return { name, ok: false, message: res.spawnError ?? "timed out" };
  }
  const version = parseVersion(`${res.stdout}\n${res.stderr}`);
  return { name, ok: res.exitCode === 0, ...(version ? { version } : {}), message: path };
}

export async function checkDatabase(config: ReconNexusConfig): Promise<DependencyCheck> {
  const client = new Client({ connectionString: config.database.url, connectionTimeoutMillis: 5000 });
  try {
    await client.connect();
    const res = await client.query("SHOW server_version");
    return { name: "postgres", ok: true, version: res.rows[0]?.server_version, message: redactUrl(config.database.url) };
  } catch (err) {
    return { name: "postgres", ok: false, message: `${redactUrl(config.database.url)}: ${(err as Error).message}` };
  } finally {
    await client.end().catch(() => undefined);
  }
}

export function checkTcp(host: string, port: number, timeoutMs = 3000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host, port });
    const done = (ok: boolean) => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => done(true));
    socket.on("timeout", () => done(false));
    socket.on("error", () => done(false));
  });
}

export async function checkRedis(config: ReconNexusConfig): Promise<DependencyCheck> {
  let url: URL;
  try {
    url = new URL(config.redis.url);
  } catch {
    return { name: "redis", ok: false, message: `invalid redis url ${config.redis.url}` };
  }
  if (!config.redis.enabled) {
    return { name: "redis", ok: true, message: "disabled (not required; Postgres queue is authoritative)" };
  }
  const port = url.port ? Number(url.port) : 6379;
  const ok = await checkTcp(url.hostname, port);
  return { name: "redis", ok, message: ok ? `${url.hostname}:${port}` : `cannot connect to ${url.hostname}:${port}` };
}

function redactUrl(u: string): string {
  try {
    const parsed = new URL(u);
    if (parsed.password) parsed.password = "***";
    return parsed.toString();
  } catch {
    return u;
  }
}
