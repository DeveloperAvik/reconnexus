import type { ReconNexusConfig } from "@reconnexus/configuration";
import type { ArtifactStore } from "@reconnexus/evidence-contracts";
import type { Logger } from "@reconnexus/logging";
import type { DiscoveryJobKindValue } from "@reconnexus/contracts";
import type { Db } from "../db/pool.js";
import type { DiscoveryRunner } from "../worker/client.js";

export interface OrchestratorDeps {
  db: Db;
  runner: DiscoveryRunner;
  store: ArtifactStore;
  logger: Logger;
  config: ReconNexusConfig;
  providerOverrides?: Partial<Record<DiscoveryJobKindValue, string[]>>;
  workerId?: string;
  signal?: AbortSignal;
  maxAttempts?: number;
  /** Port selection for the port-scan stage (e.g. "80,443,8000-8100"); omitted uses the provider default list. */
  portScanPorts?: string;
  /** Template tags for the template-check stage; omitted uses the provider's safe default set. */
  templateTags?: string;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  /** Report-boundary redactor (defaults to the centralized redactor); injectable for tests. */
  redactor?: (value: unknown) => unknown;
  /** Optional progress callback (used by the CLI to render human-readable progress). */
  onEvent?: (event: OrchestratorEvent) => void;
}

/**
 * Progress events. Consumers render them; they are never the source of truth for a result (the
 * persisted job/coverage/provider rows are), and emitting one must never affect the scan.
 */
export type OrchestratorEvent =
  | {
      type: "scan-start";
      scanId: string;
      rootDomain: string;
      startUrl: string;
      /** Number of stages in this run's plan, and their ids in execution order. */
      stages: number;
      stageIds: string[];
      profile: string;
      startedAt: string;
    }
  | { type: "stage-start"; stage: string; attempt: number }
  | { type: "provider-start"; stage: string; provider: string }
  | {
      type: "provider-end";
      stage: string;
      provider: string;
      status: string;
      records: number;
      durationMs: number;
      /** Record counts by discovery record type, exactly as returned by the provider. */
      recordsByType: Record<string, number>;
      /** True when a previously persisted result was reused instead of re-running the provider. */
      reused: boolean;
    }
  | { type: "stage-retry"; stage: string; attempt: number; backoffMs: number }
  | { type: "stage-end"; stage: string; status: string; durationMs: number; records: number; attempts: number; reason?: string }
  | { type: "scan-end"; status: string; durationMs: number };

export interface ProviderOutcomeSummary {
  stage: string;
  provider: string;
  outcome: string;
  records: number;
  reason: string;
  providerVersion: string;
  /** `null` when the provider's result was reused and no fresh duration was measured. */
  durationMs: number | null;
  timedOut: boolean;
  truncated: boolean;
}

export interface ScanRunSummary {
  scanId: string;
  status: string;
  stages: Array<{ stage: string; status: string; providers: ProviderOutcomeSummary[]; reason?: string; durationMs?: number }>;
  assetsCreated: number;
  observations: number;
  relationships: number;
  /** Where this run's outputs live, so a caller can tell an operator what to open next. */
  artifactsRoot: string;
  profile: string;
}
