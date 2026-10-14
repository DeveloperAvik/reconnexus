import {
  ExitCode,
  RECONNEXUS_VERSION,
  type CliEnvelope,
  type ExitCodeValue,
  type ScopeDecision,
} from "@reconnexus/contracts";

export interface CommandResult<T> {
  exitCode: ExitCodeValue;
  data?: T;
  warnings?: string[];
  decision?: ScopeDecision;
  /** Human-readable rendering used when `--json` is not set. */
  render?: () => string;
}

export function result<T>(r: CommandResult<T>): CommandResult<T> {
  return r;
}

export function makeEnvelope<T>(command: string, r: CommandResult<T>, error?: { code: string; message: string; details?: unknown }): CliEnvelope<T> {
  const env: CliEnvelope<T> = {
    ok: r.exitCode === ExitCode.SUCCESS,
    command,
    version: RECONNEXUS_VERSION,
    exitCode: r.exitCode,
    at: new Date().toISOString(),
  };
  if (r.data !== undefined) env.data = r.data;
  if (r.warnings && r.warnings.length) env.warnings = r.warnings;
  if (r.decision) env.decision = r.decision;
  if (error) env.error = error;
  return env;
}

export function printHuman(text: string): void {
  process.stdout.write(text.endsWith("\n") ? text : `${text}\n`);
}

export function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

/** True when stderr is emitted to a terminal (used to gate progress rendering, not JSON output). */
export function stderrIsTty(): boolean {
  return process.stderr.isTTY === true;
}

let colorEnabled = process.stdout.isTTY === true && !process.env.NO_COLOR;

export function setColorEnabled(enabled: boolean): void {
  colorEnabled = enabled;
}

function paint(code: string, s: string): string {
  return colorEnabled ? `\u001b[${code}m${s}\u001b[0m` : s;
}

export const color = {
  bold: (s: string): string => paint("1", s),
  dim: (s: string): string => paint("2", s),
  red: (s: string): string => paint("31", s),
  green: (s: string): string => paint("32", s),
  yellow: (s: string): string => paint("33", s),
  blue: (s: string): string => paint("34", s),
  cyan: (s: string): string => paint("36", s),
};

/** Colour a scan/job status label consistently for human output. */
export function statusColor(status: string): string {
  switch (status) {
    case "SUCCEEDED":
    case "COMPLETE":
      return color.green(status);
    case "RUNNING":
      return color.cyan(status);
    case "QUEUED":
      return color.dim(status);
    case "PARTIAL":
    case "SKIPPED":
    case "NOT_ATTEMPTED":
      return color.yellow(status);
    case "FAILED":
    case "SOURCE_UNAVAILABLE":
    case "BLOCKED":
    case "CANCELLED":
      return color.red(status);
    default:
      return status;
  }
}

/**
 * A one-glyph verdict for a status, so a column of results can be scanned without reading words.
 * Deliberately ASCII-safe apart from the check and cross, which terminals render reliably.
 */
export function statusSymbol(status: string): string {
  switch (status) {
    case "SUCCEEDED":
    case "COMPLETE":
    case "COLLECTED":
      return color.green("✓");
    case "PARTIAL":
      return color.yellow("~");
    case "SKIPPED":
    case "NOT_ATTEMPTED":
      return color.dim("–");
    case "RUNNING":
      return color.cyan("•");
    case "QUEUED":
      return color.dim("·");
    case "FAILED":
    case "SOURCE_UNAVAILABLE":
      return color.red("✗");
    case "BLOCKED":
      return color.red("■");
    case "CANCELLED":
      return color.yellow("■");
    default:
      return " ";
  }
}

/** Lower-case status word for inline prose, coloured consistently with `statusColor`. */
export function statusLabel(status: string): string {
  const word = status.toLowerCase().replace(/_/g, " ");
  switch (status) {
    case "SUCCEEDED":
    case "COMPLETE":
    case "COLLECTED":
      return color.green(word);
    case "PARTIAL":
    case "SKIPPED":
    case "NOT_ATTEMPTED":
    case "CANCELLED":
      return color.yellow(word);
    case "FAILED":
    case "SOURCE_UNAVAILABLE":
    case "BLOCKED":
      return color.red(word);
    default:
      return word;
  }
}

/** `1.2s`, `94s`, `3m 14s` — compact enough for a fixed-width column. */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = ms / 1000;
  if (s < 10) return `${s.toFixed(1)}s`;
  if (s < 60) return `${Math.round(s)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${String(Math.round(s % 60)).padStart(2, "0")}s`;
}

/** Thousands separators, so six-figure record counts stay readable. */
export function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

/** Visible width, ignoring the ANSI escapes that `color` inserts. */
export function visibleWidth(s: string): number {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\u001b\[[0-9;]*m/g, "").length;
}

/** Pad to `width` using the visible width, so coloured cells still line up. */
export function padVisible(s: string, width: number, align: "left" | "right" = "left"): string {
  const pad = " ".repeat(Math.max(0, width - visibleWidth(s)));
  return align === "right" ? pad + s : s + pad;
}

/**
 * Truncate to `width` visible columns, copying ANSI escapes whole so a cut never splits an escape
 * sequence (which would garble the terminal). A single-column ellipsis marks the cut, and a reset
 * closes any colour left open by the removed tail.
 */
export function truncateVisible(s: string, width: number): string {
  if (width <= 0) return "";
  if (visibleWidth(s) <= width) return s;
  const budget = width - 1;
  let out = "";
  let visible = 0;
  let i = 0;
  while (i < s.length) {
    // eslint-disable-next-line no-control-regex
    const esc = /^\u001b\[[0-9;]*m/.exec(s.slice(i));
    if (esc) {
      out += esc[0];
      i += esc[0].length;
      continue;
    }
    if (visible >= budget) break;
    out += s[i];
    visible += 1;
    i += 1;
  }
  return `${out}…\u001b[0m`;
}

/** Render rows as aligned columns. `align` is per column and defaults to left. */
export function table(rows: string[][], align: Array<"left" | "right"> = []): string[] {
  const widths: number[] = [];
  for (const row of rows) {
    row.forEach((cell, i) => {
      widths[i] = Math.max(widths[i] ?? 0, visibleWidth(cell));
    });
  }
  return rows.map((row) =>
    row
      .map((cell, i) => (i === row.length - 1 && (align[i] ?? "left") === "left" ? cell : padVisible(cell, widths[i] ?? 0, align[i] ?? "left")))
      .join("  ")
      .trimEnd(),
  );
}

/** A section heading for human output: dim, upper-case, visually quiet, indented with the body. */
export function heading(text: string): string {
  return `  ${color.dim(text.toUpperCase())}`;
}

export function formatDecision(decision: ScopeDecision): string {
  const head = decision.allowed ? color.green("ALLOW") : color.red("DENY");
  const lines = [`${head}  ${decision.code}`, `  reason: ${decision.reason}`];
  if (decision.matchedRule) lines.push(`  matchedRule: ${decision.matchedRule}`);
  if (decision.addressDecisions?.length) {
    lines.push("  addresses:");
    for (const a of decision.addressDecisions) {
      lines.push(`    ${a.allowed ? color.green("allow") : color.red("deny ")} ${a.address} — ${a.reason}`);
    }
  }
  return lines.join("\n");
}
