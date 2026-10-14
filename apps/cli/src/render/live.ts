import type { OrchestratorEvent } from "@reconnexus/control-plane";
import { color, formatCount, formatDuration, padVisible, statusSymbol, truncateVisible } from "../output.js";

/**
 * Live assessment console.
 *
 * Design constraints, in order of priority:
 *
 *  1. **Never lie.** Every number shown comes from an orchestrator event, which in turn reports
 *     what was persisted. A stage with no measurement shows `pending`/`—`, never `0`/`100%`. There
 *     is no overall percentage of work complete, because stage cost is not known in advance; the
 *     progress shown is "stages finished / stages planned", which is a fact.
 *  2. **Never block the scan.** `onEvent` only mutates in-memory state (O(1)); drawing happens on
 *     a timer that the caller owns. A slow or stuck terminal therefore cannot delay a stage, and a
 *     renderer exception is contained by the orchestrator's event guard.
 *  3. **Keep the streams separate.** Everything here is written to stderr. stdout carries the
 *     command result only (human summary or `--json`), so piping stays usable.
 *
 * Two modes share one state machine: a redrawn frame on a TTY, and timestamped one-line structured
 * events when stderr is not a terminal (or when the operator asked for log-style output).
 */

export type StageViewStatus =
  | "PENDING"
  | "RUNNING"
  | "SUCCEEDED"
  | "PARTIAL"
  | "FAILED"
  | "SKIPPED"
  | "BLOCKED"
  | "CANCELLED"
  | "SOURCE_UNAVAILABLE"
  | "QUEUED";

export interface ProviderView {
  provider: string;
  status: string;
  records: number;
  durationMs: number | null;
  running: boolean;
  reused: boolean;
}

export interface StageView {
  stage: string;
  status: StageViewStatus;
  durationMs: number | null;
  startedMs: number | null;
  records: number;
  attempts: number;
  retries: number;
  reason: string;
  providers: ProviderView[];
}

export interface ScanViewState {
  scanId: string;
  rootDomain: string;
  startUrl: string;
  profile: string;
  startedAtIso: string;
  startedMs: number | null;
  finishedMs: number | null;
  status: "PENDING" | "RUNNING" | "CANCELLING" | string;
  stages: StageView[];
  /** Record counts by discovery record type, summed from provider results. */
  recordsByType: Record<string, number>;
  /** Most recent diagnostics, newest last. */
  notices: string[];
}

export interface LiveRendererOptions {
  write?: (s: string) => void;
  /** True to draw a redrawn frame; false to emit timestamped event lines. */
  tty?: boolean;
  columns?: () => number;
  rows?: () => number;
  now?: () => number;
  /** Repaint interval in ms; 0 disables the internal timer (tests drive `tick()`). */
  intervalMs?: number;
  /** Wall clock used for event timestamps in stream mode. */
  clock?: () => Date;
  /** Maximum notices kept and shown. */
  maxNotices?: number;
}

/** Record types mapped to the asset counters an operator actually looks for. */
const COUNTER_LABELS: Array<[string, string]> = [
  ["HOST_OBSERVATION", "subdomains"],
  ["DNS_RECORD", "dns"],
  ["IP_METADATA", "ips"],
  ["HTTP_OBSERVATION", "services"],
  ["TECHNOLOGY", "tech"],
  ["URL_OBSERVATION", "urls"],
  ["JS_ARTIFACT", "js"],
  ["SOURCE_MAP", "maps"],
  ["API_ENDPOINT", "apis"],
  ["API_SPEC", "specs"],
  ["SECURITY_METADATA", "security"],
  ["SECRET_CANDIDATE", "secrets"],
  ["TAKEOVER_CANDIDATE", "takeover"],
];

const STAGE_NAME_WIDTH = 22;
const DEFAULT_INTERVAL_MS = 120;

/** Stage ids are `NN-some-name`; split them so the number and the name can be separate columns. */
export function stageParts(stage: string): { index: string; name: string } {
  const m = /^(\d+)-(.*)$/.exec(stage);
  if (!m) return { index: "  ", name: stage };
  return { index: m[1]!, name: m[2]!.replace(/-/g, " ") };
}

/** `19:36:02` — a wall-clock stamp for the header and for structured event lines. */
function hhmmss(d: Date): string {
  return d.toISOString().slice(11, 19);
}

export class LiveRenderer {
  readonly state: ScanViewState;
  private readonly write: (s: string) => void;
  private readonly tty: boolean;
  private readonly columns: () => number;
  private readonly rows: () => number;
  private readonly now: () => number;
  private readonly clock: () => Date;
  private readonly maxNotices: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private onResize: (() => void) | null = null;
  private linesDrawn = 0;
  private painting = false;
  private stopped = false;

  constructor(opts: LiveRendererOptions = {}) {
    this.write = opts.write ?? ((s) => void process.stderr.write(s));
    this.tty = opts.tty ?? process.stderr.isTTY === true;
    this.columns = opts.columns ?? (() => (process.stderr.isTTY ? (process.stderr.columns ?? 80) : 120));
    this.rows = opts.rows ?? (() => (process.stderr.isTTY ? (process.stderr.rows ?? 24) : 1000));
    this.now = opts.now ?? (() => Date.now());
    this.clock = opts.clock ?? (() => new Date());
    this.maxNotices = opts.maxNotices ?? 4;
    this.state = {
      scanId: "",
      rootDomain: "",
      startUrl: "",
      profile: "default",
      startedAtIso: "",
      startedMs: null,
      finishedMs: null,
      status: "PENDING",
      stages: [],
      recordsByType: {},
      notices: [],
    };

    const interval = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
    if (this.tty && interval > 0) {
      this.timer = setInterval(() => this.tick(), interval);
      // The repaint timer must never hold the process open.
      this.timer.unref?.();
      if (process.stderr.isTTY) {
        this.onResize = (): void => {
          // A resize invalidates the drawn region: start a fresh frame at the current width.
          this.linesDrawn = 0;
          this.tick();
        };
        process.stderr.on("resize", this.onResize);
      }
    }
  }

  // ---------------------------------------------------------------- state

  private stageView(stage: string): StageView {
    let view = this.state.stages.find((s) => s.stage === stage);
    if (!view) {
      view = { stage, status: "PENDING", durationMs: null, startedMs: null, records: 0, attempts: 0, retries: 0, reason: "", providers: [] };
      this.state.stages.push(view);
    }
    return view;
  }

  private notice(line: string): void {
    this.state.notices.push(line);
    while (this.state.notices.length > this.maxNotices) this.state.notices.shift();
  }

  /** Feed an orchestrator event. Cheap and synchronous by contract. */
  onEvent(e: OrchestratorEvent): void {
    switch (e.type) {
      case "scan-start": {
        this.state.scanId = e.scanId;
        this.state.rootDomain = e.rootDomain;
        this.state.startUrl = e.startUrl;
        this.state.profile = e.profile;
        this.state.startedAtIso = e.startedAt;
        this.state.startedMs = this.now();
        this.state.status = "RUNNING";
        // Seed the plan so pending stages are visible from the first frame.
        for (const stage of e.stageIds) this.stageView(stage);
        if (!this.tty) this.emitLine("scan-start", `${e.rootDomain} stages=${e.stages} profile=${e.profile} scan=${e.scanId}`);
        return;
      }
      case "stage-start": {
        const v = this.stageView(e.stage);
        v.status = "RUNNING";
        v.startedMs = this.now();
        v.attempts = e.attempt;
        if (!this.tty) this.emitLine("stage-start", `${e.stage} attempt=${e.attempt}`);
        return;
      }
      case "provider-start": {
        const v = this.stageView(e.stage);
        const p = v.providers.find((x) => x.provider === e.provider);
        if (p) {
          p.running = true;
        } else {
          v.providers.push({ provider: e.provider, status: "RUNNING", records: 0, durationMs: null, running: true, reused: false });
        }
        if (!this.tty) this.emitLine("provider-start", `${e.stage} ${e.provider}`);
        return;
      }
      case "provider-end": {
        const v = this.stageView(e.stage);
        const existing = v.providers.find((x) => x.provider === e.provider);
        const view: ProviderView = {
          provider: e.provider,
          status: e.status,
          records: e.records,
          durationMs: e.reused ? null : e.durationMs,
          running: false,
          reused: e.reused,
        };
        if (existing) Object.assign(existing, view);
        else v.providers.push(view);
        for (const [type, n] of Object.entries(e.recordsByType)) {
          this.state.recordsByType[type] = (this.state.recordsByType[type] ?? 0) + n;
        }
        if (e.status !== "SUCCEEDED" && e.status !== "SKIPPED") {
          this.notice(`${color.yellow("!")} ${e.stage} ${color.dim("·")} ${e.provider} ${color.dim(e.status.toLowerCase())}`);
        }
        if (!this.tty) {
          this.emitLine(
            "provider-end",
            `${e.stage} ${e.provider} status=${e.status} records=${e.records} duration=${e.reused ? "reused" : `${e.durationMs}ms`}`,
          );
        }
        return;
      }
      case "stage-retry": {
        const v = this.stageView(e.stage);
        v.retries = Math.max(v.retries, e.attempt);
        v.attempts = e.attempt;
        this.notice(`${color.yellow("↻")} ${e.stage} ${color.dim(`retry ${e.attempt} in ${formatDuration(e.backoffMs)}`)}`);
        if (!this.tty) this.emitLine("stage-retry", `${e.stage} attempt=${e.attempt} backoff=${e.backoffMs}ms`);
        return;
      }
      case "stage-end": {
        const v = this.stageView(e.stage);
        v.status = e.status as StageViewStatus;
        v.records = e.records;
        v.attempts = Math.max(v.attempts, e.attempts);
        v.retries = Math.max(0, v.attempts - 1);
        v.reason = e.reason ?? "";
        // A zero-duration stage that never started is reported as "not measured", not as 0ms.
        v.durationMs = v.startedMs === null && e.durationMs === 0 ? null : e.durationMs;
        for (const p of v.providers) p.running = false;
        if (e.status === "FAILED" || e.status === "SOURCE_UNAVAILABLE" || e.status === "BLOCKED") {
          this.notice(`${color.red("✗")} ${e.stage} ${color.dim(e.status.toLowerCase())}${e.reason ? color.dim(` — ${e.reason}`) : ""}`);
        }
        if (!this.tty) {
          this.emitLine(
            "stage-end",
            `${e.stage} status=${e.status} duration=${v.durationMs === null ? "-" : `${v.durationMs}ms`} records=${e.records} attempts=${e.attempts}${
              e.reason ? ` reason=${JSON.stringify(e.reason)}` : ""
            }`,
          );
        }
        return;
      }
      case "scan-end": {
        this.state.status = e.status;
        this.state.finishedMs = this.now();
        if (!this.tty) this.emitLine("scan-end", `status=${e.status} duration=${e.durationMs}ms`);
        return;
      }
    }
  }

  /** Mark a cancellation request, so the console says what is happening while stages wind down. */
  cancelling(): void {
    this.state.status = "CANCELLING";
    if (this.tty) this.tick();
    else this.emitLine("cancel", "cancellation requested; finishing the current stage");
  }

  /**
   * Log sink handed to the logger: a warning or error is written above the live frame rather than
   * on top of the line being drawn.
   */
  logSink = (line: string): void => {
    if (!this.tty) {
      this.write(`${line}\n`);
      return;
    }
    this.clearFrame();
    this.write(`  ${line}\n`);
    this.tick();
  };

  // ---------------------------------------------------------------- rendering

  private emitLine(event: string, detail: string): void {
    this.write(`${this.clock().toISOString()}  ${event.padEnd(14)} ${detail}\n`);
  }

  private elapsedMs(): number | null {
    if (this.state.startedMs === null) return null;
    return (this.state.finishedMs ?? this.now()) - this.state.startedMs;
  }

  private counterLine(): string | null {
    const parts: string[] = [];
    for (const [type, label] of COUNTER_LABELS) {
      const n = this.state.recordsByType[type];
      if (n === undefined || n === 0) continue;
      parts.push(`${color.dim(label)} ${formatCount(n)}`);
    }
    if (parts.length === 0) return null;
    return `  ${color.dim("records")}  ${parts.join(color.dim(" · "))}`;
  }

  private providerCell(v: StageView): string {
    if (v.providers.length === 0) return v.reason ? color.dim(`· ${v.reason}`) : "";
    const cells = v.providers.map((p) => {
      if (p.running) return `${p.provider}${color.cyan(" …")}`;
      const count = p.status === "SKIPPED" || p.status === "BLOCKED" ? "" : ` ${color.dim(formatCount(p.records))}`;
      const mark = p.status === "SUCCEEDED" ? "" : ` ${color.dim(`(${p.status.toLowerCase()})`)}`;
      const reused = p.reused ? color.dim(" ·reused") : "";
      return `${p.provider}${count}${mark}${reused}`;
    });
    return color.dim("· ") + cells.join(color.dim(" · "));
  }

  /** The current frame, as lines without a trailing newline. Also used by tests. */
  frame(): string[] {
    const width = Math.max(40, this.columns());
    const s = this.state;
    const done = s.stages.filter((x) => x.status !== "PENDING" && x.status !== "RUNNING").length;
    const lines: string[] = [];

    const statusText =
      s.status === "RUNNING"
        ? color.cyan("running")
        : s.status === "CANCELLING"
          ? color.yellow("cancelling")
          : s.status === "PENDING"
            ? color.dim("starting")
            : s.status === "SUCCEEDED"
              ? color.green("succeeded")
              : s.status === "PARTIAL"
                ? color.yellow("partial")
                : s.status === "CANCELLED"
                  ? color.yellow("cancelled")
                  : color.red(s.status.toLowerCase());

    lines.push(`  ${color.bold("ReconNexus")} ${color.dim("·")} ${color.bold(s.rootDomain || "—")} ${color.dim("·")} ${statusText}`);
    const elapsed = this.elapsedMs();
    lines.push(
      `  ${color.dim("assessment")} ${s.scanId || "—"}  ${color.dim("profile")} ${s.profile}  ${color.dim("started")} ${
        s.startedAtIso ? hhmmss(new Date(s.startedAtIso)) : "—"
      }  ${color.dim("elapsed")} ${elapsed === null ? "—" : formatDuration(elapsed)}  ${color.dim("stages")} ${done}/${s.stages.length}`,
    );
    lines.push("");

    // Keep the frame inside the terminal: when it would overflow, the oldest finished stages are
    // collapsed into a count rather than scrolling the header away.
    const chrome = 4 + (this.counterLine() ? 1 : 0) + Math.min(s.notices.length, this.maxNotices);
    const budget = Math.max(4, this.rows() - chrome);
    let stages = s.stages;
    let hidden = 0;
    if (stages.length > budget) {
      const tail = stages.slice(-budget + 1);
      hidden = stages.length - tail.length;
      stages = tail;
    }
    if (hidden > 0) lines.push(`  ${color.dim(`… ${hidden} earlier stage${hidden === 1 ? "" : "s"}`)}`);

    for (const v of stages) {
      const { index, name } = stageParts(v.stage);
      const mark = v.status === "PENDING" ? color.dim("·") : v.status === "RUNNING" ? color.cyan("•") : statusSymbol(v.status);
      const dur =
        v.status === "RUNNING" && v.startedMs !== null
          ? color.dim(formatDuration(this.now() - v.startedMs))
          : v.durationMs === null
            ? v.status === "PENDING"
              ? color.dim("pending")
              : color.dim("—")
            : color.dim(formatDuration(v.durationMs));
      const retries = v.retries > 0 ? color.yellow(` ↻${v.retries}`) : "";
      const row = `  ${mark} ${color.dim(index)} ${padVisible(name, STAGE_NAME_WIDTH)} ${padVisible(dur, 8, "right")}${retries} ${this.providerCell(v)}`;
      lines.push(truncateVisible(row, width));
    }

    const counters = this.counterLine();
    if (counters) {
      lines.push("");
      lines.push(truncateVisible(counters, width));
    }
    for (const n of s.notices) lines.push(truncateVisible(`  ${n}`, width));
    return lines;
  }

  /** Repaint. Safe to call at any time; a no-op once stopped. */
  tick(): void {
    if (!this.tty || this.stopped || this.painting) return;
    this.painting = true;
    try {
      const lines = this.frame();
      this.clearFrame();
      this.write(`${lines.join("\n")}\n`);
      this.linesDrawn = lines.length;
    } catch {
      // Rendering is never allowed to break a scan: drop the frame and keep going.
      this.linesDrawn = 0;
    } finally {
      this.painting = false;
    }
  }

  /** Erase the region drawn by the previous frame, leaving the cursor where it began. */
  private clearFrame(): void {
    if (!this.tty || this.linesDrawn === 0) return;
    this.write(`\u001b[${this.linesDrawn}A\r\u001b[0J`);
    this.linesDrawn = 0;
  }

  /**
   * Final paint, then release the terminal. After `stop()` the frame is static text in the
   * scrollback, so the command's own summary on stdout can follow it safely.
   */
  stop(): void {
    if (this.stopped) return;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.onResize && process.stderr.isTTY) {
      process.stderr.removeListener("resize", this.onResize);
      this.onResize = null;
    }
    if (this.tty) {
      this.tick();
      this.write("\n");
    }
    this.stopped = true;
  }
}
