import { spawn } from "node:child_process";

export interface ExecResult {
  argv: string[];
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
  durationMs: number;
  spawnError?: string;
}

export interface ExecOptions {
  timeoutMs?: number;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  maxBytes?: number;
  /** Optional stdin to write. */
  input?: string;
}

/**
 * Structured process invocation. The caller supplies an argv array — a shell is never
 * involved, so untrusted values cannot be interpreted as shell syntax.
 */
export function execCapture(argv: string[], opts: ExecOptions = {}): Promise<ExecResult> {
  const timeoutMs = opts.timeoutMs ?? 30000;
  const maxBytes = opts.maxBytes ?? 4 * 1024 * 1024;
  const started = Date.now();
  const [file, ...args] = argv;

  return new Promise<ExecResult>((resolve) => {
    if (!file) {
      resolve({ argv, exitCode: null, signal: null, stdout: "", stderr: "", timedOut: false, truncated: false, durationMs: 0, spawnError: "empty argv" });
      return;
    }
    let child;
    try {
      child = spawn(file, args, {
        cwd: opts.cwd,
        env: opts.env,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err) {
      resolve({ argv, exitCode: null, signal: null, stdout: "", stderr: "", timedOut: false, truncated: false, durationMs: Date.now() - started, spawnError: (err as Error).message });
      return;
    }

    let stdout = "";
    let stderr = "";
    let truncated = false;
    let timedOut = false;
    let settled = false;

    const append = (target: "out" | "err", chunk: Buffer) => {
      const s = chunk.toString("utf8");
      if (target === "out") {
        if (stdout.length < maxBytes) stdout += s.slice(0, Math.max(0, maxBytes - stdout.length));
        else truncated = true;
      } else {
        if (stderr.length < maxBytes) stderr += s.slice(0, Math.max(0, maxBytes - stderr.length));
        else truncated = true;
      }
    };

    child.stdout?.on("data", (c: Buffer) => append("out", c));
    child.stderr?.on("data", (c: Buffer) => append("err", c));

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
      }, 2000).unref?.();
    }, timeoutMs);

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ argv, exitCode: null, signal: null, stdout, stderr, timedOut, truncated, durationMs: Date.now() - started, spawnError: err.message });
    });

    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ argv, exitCode: code, signal, stdout, stderr, timedOut, truncated, durationMs: Date.now() - started });
    });

    if (opts.input !== undefined) {
      child.stdin?.write(opts.input);
    }
    child.stdin?.end();
  });
}
