import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import {
  DiscoveryResultSchema,
  type DiscoveryJob,
  type DiscoveryResult,
} from "@reconnexus/contracts";
import { findRepoRoot, type WorkerConfig } from "@reconnexus/configuration";

export interface RunOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

/** A runner executes a discovery job and returns a truthful result. */
export interface DiscoveryRunner {
  run(job: DiscoveryJob, opts?: RunOptions): Promise<DiscoveryResult>;
  describe(): string;
}

export function resolveWorkerCommand(config: WorkerConfig, cwd: string): { argv: string[]; cwd: string } {
  const repoRoot = findRepoRoot(cwd) ?? cwd;
  if (config.binaryPath) {
    const p = isAbsolute(config.binaryPath) ? config.binaryPath : join(repoRoot, config.binaryPath);
    return { argv: [p], cwd: config.workDir ?? repoRoot };
  }
  const envBin = process.env.RECONNEXUS_WORKER_BIN;
  if (envBin) return { argv: [envBin], cwd: config.workDir ?? repoRoot };
  const defaultBin = join(repoRoot, "bin", "reconnexus-worker");
  if (existsSync(defaultBin)) return { argv: [defaultBin], cwd: config.workDir ?? repoRoot };
  if (config.goRunCommand && config.goRunCommand.length > 0) {
    return { argv: [...config.goRunCommand], cwd: config.workDir ?? join(repoRoot, "workers") };
  }
  // Fall back to `go run` from the workers module.
  return { argv: ["go", "run", "./cmd/reconnexus-worker"], cwd: config.workDir ?? join(repoRoot, "workers") };
}

function baseResult(job: DiscoveryJob, overrides: Partial<DiscoveryResult>): DiscoveryResult {
  return {
    schemaVersion: 1,
    status: "FAILED",
    provider: job.provider,
    providerVersion: "unknown",
    execution: {
      argv: [],
      exitCode: null,
      exitDescription: "",
      durationMs: 0,
      stdoutBytes: 0,
      stderrBytes: 0,
      truncated: false,
      timedOut: false,
      spawnError: "",
    },
    coverage: { attempted: 0, succeeded: 0, failed: 0, skipped: 0, unavailable: 0 },
    records: [],
    diagnostics: [],
    ...overrides,
  };
}

/** Spawns the Go worker binary and validates its JSON output. */
export class GoWorkerRunner implements DiscoveryRunner {
  private readonly argv: string[];
  private readonly cwd: string;
  private readonly env: NodeJS.ProcessEnv;
  private readonly maxStdoutBytes: number;

  constructor(opts: { argv: string[]; cwd: string; env?: NodeJS.ProcessEnv; maxStdoutBytes?: number }) {
    this.argv = opts.argv;
    this.cwd = opts.cwd;
    this.env = opts.env ?? process.env;
    this.maxStdoutBytes = opts.maxStdoutBytes ?? 64 * 1024 * 1024;
  }

  describe(): string {
    return this.argv.join(" ") + ` (cwd ${this.cwd})`;
  }

  run(job: DiscoveryJob, opts: RunOptions = {}): Promise<DiscoveryResult> {
    const timeoutMs = opts.timeoutMs ?? job.timeoutMs ?? 900000;
    return new Promise<DiscoveryResult>((resolve) => {
      const [file, ...args] = this.argv;
      if (!file) {
        resolve(baseResult(job, { status: "FAILED", diagnostics: ["worker command is empty"] }));
        return;
      }
      let child;
      try {
        child = spawn(file, args, { cwd: this.cwd, env: this.env, stdio: ["pipe", "pipe", "pipe"] });
      } catch (err) {
        resolve(baseResult(job, { status: "SOURCE_UNAVAILABLE", coverage: { attempted: 0, succeeded: 0, failed: 0, skipped: 0, unavailable: 1 }, diagnostics: [`cannot start worker: ${(err as Error).message}`] }));
        return;
      }

      let stdout = "";
      let stderr = "";
      let truncated = false;
      let timedOut = false;
      let settled = false;

      const finish = (r: DiscoveryResult): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(r);
      };

      const timer = setTimeout(() => {
        timedOut = true;
        try {
          child.kill("SIGTERM");
        } catch {
          /* ignore */
        }
        setTimeout(() => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* ignore */
          }
        }, 3000).unref?.();
      }, timeoutMs);

      const onAbort = (): void => {
        try {
          child.kill("SIGTERM");
        } catch {
          /* ignore */
        }
      };
      opts.signal?.addEventListener("abort", onAbort, { once: true });

      child.stdout?.on("data", (c: Buffer) => {
        if (stdout.length < this.maxStdoutBytes) stdout += c.toString("utf8").slice(0, this.maxStdoutBytes - stdout.length);
        else truncated = true;
      });
      child.stderr?.on("data", (c: Buffer) => {
        if (stderr.length < 2 * 1024 * 1024) stderr += c.toString("utf8");
      });

      child.on("error", (err) => {
        opts.signal?.removeEventListener("abort", onAbort);
        resolve(
          baseResult(job, {
            status: "SOURCE_UNAVAILABLE",
            coverage: { attempted: 0, succeeded: 0, failed: 0, skipped: 0, unavailable: 1 },
            diagnostics: [`worker spawn failed: ${err.message}`],
          }),
        );
      });

      child.on("close", () => {
        opts.signal?.removeEventListener("abort", onAbort);
        if (timedOut) {
          finish(baseResult(job, { status: "FAILED", execution: { ...baseResult(job, {}).execution, timedOut: true, exitDescription: "worker timed out" }, coverage: { attempted: 1, succeeded: 0, failed: 1, skipped: 0, unavailable: 0 }, diagnostics: ["worker timed out"] }));
          return;
        }
        if (opts.signal?.aborted) {
          finish(baseResult(job, { status: "CANCELLED", coverage: { attempted: 1, succeeded: 0, failed: 0, skipped: 0, unavailable: 0 }, diagnostics: ["cancelled"] }));
          return;
        }
        let parsed: unknown;
        try {
          parsed = JSON.parse(stdout);
        } catch {
          finish(
            baseResult(job, {
              status: "FAILED",
              coverage: { attempted: 1, succeeded: 0, failed: 1, skipped: 0, unavailable: 0 },
              diagnostics: [`worker produced non-JSON output: ${stderr.slice(0, 300)}`],
            }),
          );
          return;
        }
        const validated = DiscoveryResultSchema.safeParse(parsed);
        if (!validated.success) {
          finish(
            baseResult(job, {
              status: "FAILED",
              coverage: { attempted: 1, succeeded: 0, failed: 1, skipped: 0, unavailable: 0 },
              diagnostics: ["worker output failed schema validation", JSON.stringify(validated.error.flatten()).slice(0, 400)],
            }),
          );
          return;
        }
        const result = validated.data as DiscoveryResult;
        if (truncated) result.diagnostics.push("worker stdout was truncated by the control plane");
        finish(result);
      });

      child.stdin?.end(JSON.stringify(job));
    });
  }
}

/** Deterministic in-process runner for tests and dry-runs. */
export class FakeRunner implements DiscoveryRunner {
  constructor(private readonly handler: (job: DiscoveryJob) => DiscoveryResult) {}
  describe(): string {
    return "fake-runner";
  }
  async run(job: DiscoveryJob): Promise<DiscoveryResult> {
    return this.handler(job);
  }
}
