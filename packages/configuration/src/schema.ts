import { z } from "zod";

export const LoggingConfigSchema = z.object({
  level: z.enum(["debug", "info", "warn", "error"]).default("info"),
  format: z.enum(["json", "pretty"]).default("json"),
});

export const DatabaseConfigSchema = z.object({
  url: z.string().min(1),
  poolSize: z.number().int().positive().default(10),
  statementTimeoutMs: z.number().int().positive().default(60000),
});

export const RedisConfigSchema = z.object({
  enabled: z.boolean().default(false),
  url: z.string().default("redis://127.0.0.1:6379"),
});

export const ArtifactsConfigSchema = z.object({
  root: z.string().min(1),
  maxBytes: z.number().int().positive().default(8 * 1024 * 1024),
});

export const NetworkConfigSchema = z.object({
  /**
   * Global hard floor: when false, private/loopback/link-local/metadata destinations
   * are denied even if a policy grants INTERNAL_NETWORK. Defaults to false (deny).
   */
  allowRestrictedAddresses: z.boolean().default(false),
  requestTimeoutMs: z.number().int().positive().default(15000),
  maxRedirects: z.number().int().nonnegative().default(5),
});

export const ProviderConfigSchema = z.object({
  enabled: z.boolean().default(true),
  binaryPath: z.string().optional(),
  credentialsEnv: z.record(z.string(), z.string()).default({}),
});

export const WorkerConfigSchema = z.object({
  /** Absolute path to the compiled worker binary. */
  binaryPath: z.string().optional(),
  /**
   * Fixed argv used to launch the worker when no binary is configured, e.g.
   * ["go", "run", "./cmd/reconnexus-worker"]. Never derived from user input.
   */
  goRunCommand: z.array(z.string()).optional(),
  /** Working directory for the worker process. */
  workDir: z.string().optional(),
});

export const ConfigSchema = z.object({
  schemaVersion: z.literal(1),
  database: DatabaseConfigSchema,
  redis: RedisConfigSchema.default({}),
  artifacts: ArtifactsConfigSchema,
  logging: LoggingConfigSchema.default({}),
  network: NetworkConfigSchema.default({}),
  providers: z.record(z.string(), ProviderConfigSchema).default({}),
  worker: WorkerConfigSchema.default({}),
  defaultPolicyFile: z.string().optional(),
  migrationsDir: z.string().min(1),
});

export type ReconNexusConfig = z.infer<typeof ConfigSchema>;
export type ProviderConfig = z.infer<typeof ProviderConfigSchema>;
export type DatabaseConfig = z.infer<typeof DatabaseConfigSchema>;
export type RedisConfig = z.infer<typeof RedisConfigSchema>;
export type ArtifactsConfig = z.infer<typeof ArtifactsConfigSchema>;
export type NetworkConfig = z.infer<typeof NetworkConfigSchema>;
export type LoggingConfig = z.infer<typeof LoggingConfigSchema>;
export type WorkerConfig = z.infer<typeof WorkerConfigSchema>;

export const PartialConfigSchema = z.object({
  schemaVersion: z.literal(1).optional(),
  database: DatabaseConfigSchema.partial().optional(),
  redis: RedisConfigSchema.partial().optional(),
  artifacts: ArtifactsConfigSchema.partial().optional(),
  logging: LoggingConfigSchema.partial().optional(),
  network: NetworkConfigSchema.partial().optional(),
  providers: z.record(z.string(), ProviderConfigSchema.partial()).optional(),
  worker: WorkerConfigSchema.partial().optional(),
  defaultPolicyFile: z.string().optional(),
  migrationsDir: z.string().optional(),
});
export type PartialConfig = z.infer<typeof PartialConfigSchema>;
