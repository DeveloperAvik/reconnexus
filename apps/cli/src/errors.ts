import { ExitCode, type ExitCodeValue } from "@reconnexus/contracts";
import { ConfigError } from "@reconnexus/configuration";
import { PolicyVersionConflictError } from "@reconnexus/control-plane";
import { ScopePolicyError } from "@reconnexus/scope-policy";

export class CliError extends Error {
  constructor(message: string, readonly code: ExitCodeValue = ExitCode.GENERAL_ERROR, readonly details?: unknown) {
    super(message);
    this.name = "CliError";
  }
}

export class NotImplementedError extends CliError {
  constructor(message: string) {
    super(message, ExitCode.NOT_IMPLEMENTED);
    this.name = "NotImplementedError";
  }
}

export class DependencyError extends CliError {
  constructor(message: string, details?: unknown) {
    super(message, ExitCode.DEPENDENCY_MISSING, details);
    this.name = "DependencyError";
  }
}

export function classifyError(err: unknown): { code: ExitCodeValue; message: string; details?: unknown } {
  if (err instanceof CliError) return { code: err.code, message: err.message, details: err.details };
  if (err instanceof ConfigError) return { code: ExitCode.CONFIG_INVALID, message: err.message, details: err.details };
  if (err instanceof PolicyVersionConflictError) return { code: ExitCode.CONFIG_INVALID, message: err.message };
  if (err instanceof ScopePolicyError) return { code: ExitCode.CONFIG_INVALID, message: err.message };
  const message = err instanceof Error ? err.message : String(err);
  return { code: ExitCode.GENERAL_ERROR, message };
}
