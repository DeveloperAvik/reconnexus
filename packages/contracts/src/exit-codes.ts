/** Stable process exit codes for the ReconNexus CLI. */
export const ExitCode = {
  SUCCESS: 0,
  GENERAL_ERROR: 1,
  USAGE_ERROR: 2,
  NOT_IMPLEMENTED: 3,
  SCOPE_DENIED: 4,
  AUTHORIZATION_INVALID: 5,
  DEPENDENCY_MISSING: 6,
  CONFIG_INVALID: 7,
  PARTIAL: 8,
  CANCELLED: 130,
} as const;

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];

export const ExitCodeDescription: Record<number, string> = {
  [ExitCode.SUCCESS]: "success",
  [ExitCode.GENERAL_ERROR]: "general error",
  [ExitCode.USAGE_ERROR]: "usage error",
  [ExitCode.NOT_IMPLEMENTED]: "not implemented",
  [ExitCode.SCOPE_DENIED]: "scope denied",
  [ExitCode.AUTHORIZATION_INVALID]: "authorization invalid or expired",
  [ExitCode.DEPENDENCY_MISSING]: "required dependency missing",
  [ExitCode.CONFIG_INVALID]: "configuration invalid",
  [ExitCode.PARTIAL]: "scan completed partially",
  [ExitCode.CANCELLED]: "cancelled",
};
