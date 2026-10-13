import type { ExitCodeValue } from "./exit-codes.js";
import type { ScopeDecision } from "./scope.js";

export interface CliError {
  code: string;
  message: string;
  details?: unknown;
}

/** Uniform structured output envelope emitted with `--json`. */
export interface CliEnvelope<T> {
  ok: boolean;
  command: string;
  version: string;
  exitCode: ExitCodeValue;
  data?: T;
  error?: CliError;
  decision?: ScopeDecision;
  warnings?: string[];
  /** ISO timestamp of envelope creation. */
  at: string;
}
