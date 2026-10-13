import { z } from "zod";
import { CapabilitySchema } from "./scope.js";

export const ProviderSourceSchema = z.enum(["external_binary", "builtin", "http_api"]);
export type ProviderSource = z.infer<typeof ProviderSourceSchema>;

export const NetworkBehaviorSchema = z.enum(["NONE", "PASSIVE", "ACTIVE", "ACTIVE_TEMPLATE"]);
export type NetworkBehavior = z.infer<typeof NetworkBehaviorSchema>;

export const HealthCheckSchema = z.object({
  argv: z.array(z.string()).min(1),
  expectExitCode: z.number().int().default(0),
  timeoutMs: z.number().int().positive().default(5000),
});

/**
 * A replaceable provider contract. Providers are invoked via structured argv arrays —
 * never through a shell — and untrusted values never become executable arguments.
 */
export const ProviderDescriptorSchema = z.object({
  name: z.string().min(1),
  displayName: z.string().min(1),
  source: ProviderSourceSchema,
  /** Declared provider version, when known. */
  version: z.string().default("unknown"),
  description: z.string().default(""),
  capabilities: z.array(CapabilitySchema).min(1),
  requiredCredentials: z.array(z.string()).default([]),
  requiresCredentials: z.boolean().default(false),
  networkBehavior: NetworkBehaviorSchema,
  /** Absolute path to a fixed binary; operators cannot substitute this value via scan config. */
  binaryPath: z.string().optional(),
  healthCheck: HealthCheckSchema.optional(),
  timeoutMs: z.number().int().positive().default(300000),
  retryable: z.boolean().default(true),
  /** Maps non-zero exit codes to a human meaning; unknown codes are treated as failures. */
  exitCodes: z.record(z.string(), z.string()).default({}),
  /** Whether the provider supports cooperative cancellation (SIGINT/SIGTERM). */
  supportsCancellation: z.boolean().default(true),
  /** Maximum bytes of stdout retained before truncation. */
  maxOutputBytes: z.number().int().positive().default(16 * 1024 * 1024),
});

export type ProviderDescriptor = z.infer<typeof ProviderDescriptorSchema>;

export const ProviderHealth = {
  OK: "OK",
  MISSING: "MISSING",
  INCOMPATIBLE: "INCOMPATIBLE",
  MISSING_CREDENTIALS: "MISSING_CREDENTIALS",
  FAILED_HEALTHCHECK: "FAILED_HEALTHCHECK",
  UNKNOWN: "UNKNOWN",
} as const;
export type ProviderHealthValue = (typeof ProviderHealth)[keyof typeof ProviderHealth];

export interface ProviderHealthReport {
  name: string;
  status: ProviderHealthValue;
  version?: string;
  path?: string;
  message: string;
}
