import { redactValue } from "./redact.js";

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface LoggerOptions {
  level?: LogLevel;
  format?: "json" | "pretty";
  /** Where records are written. Defaults to process.stderr. */
  sink?: (line: string) => void;
  bindings?: Record<string, unknown>;
}

function defaultSink(line: string): void {
  process.stderr.write(`${line}\n`);
}

export class Logger {
  private readonly level: LogLevel;
  private readonly format: "json" | "pretty";
  private readonly sink: (line: string) => void;
  readonly bindings: Record<string, unknown>;

  constructor(opts: LoggerOptions = {}) {
    this.level = opts.level ?? "info";
    this.format = opts.format ?? "json";
    this.sink = opts.sink ?? defaultSink;
    this.bindings = opts.bindings ?? {};
  }

  child(bindings: Record<string, unknown>): Logger {
    return new Logger({
      level: this.level,
      format: this.format,
      sink: this.sink,
      bindings: { ...this.bindings, ...bindings },
    });
  }

  /**
   * A copy of this logger with selected options replaced. Used when a caller renders the same
   * information itself — a CLI drawing live progress, for example — and wants the log stream
   * quietened, or redirected so it cannot interleave with a line being drawn.
   */
  derive(opts: { level?: LogLevel; sink?: (line: string) => void }): Logger {
    return new Logger({
      level: opts.level ?? this.level,
      format: this.format,
      sink: opts.sink ?? this.sink,
      bindings: this.bindings,
    });
  }

  /** The level this logger emits at. */
  get currentLevel(): LogLevel {
    return this.level;
  }

  debug(msg: string, fields?: Record<string, unknown>): void {
    this.emit("debug", msg, fields);
  }
  info(msg: string, fields?: Record<string, unknown>): void {
    this.emit("info", msg, fields);
  }
  warn(msg: string, fields?: Record<string, unknown>): void {
    this.emit("warn", msg, fields);
  }
  error(msg: string, fields?: Record<string, unknown>): void {
    this.emit("error", msg, fields);
  }

  private emit(level: LogLevel, msg: string, fields?: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[this.level]) return;
    const time = new Date().toISOString();
    const merged = { ...this.bindings, ...(fields ?? {}) };
    const redacted = redactValue(merged) as Record<string, unknown>;
    if (this.format === "pretty") {
      const extra = Object.keys(redacted).length ? ` ${JSON.stringify(redacted)}` : "";
      this.sink(`${time} ${level.toUpperCase().padEnd(5)} ${msg}${extra}`);
      return;
    }
    this.sink(JSON.stringify({ time, level, msg, ...redacted }));
  }
}
