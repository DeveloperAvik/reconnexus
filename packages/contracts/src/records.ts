import { z } from "zod";
import { Severity, SourceReliability, ValidationState, CoverageStatus, JobStatus } from "./status.js";

export const AssetTypeSchema = z.enum([
  "DOMAIN",
  "SUBDOMAIN",
  "HOST",
  "IP",
  "CIDR",
  "ASN",
  "URL",
  "SERVICE",
  "JS_ARTIFACT",
  "API_ENDPOINT",
  "CERTIFICATE",
  "TECHNOLOGY",
]);
export type AssetType = z.infer<typeof AssetTypeSchema>;

export const ObservationSchema = z.object({
  id: z.string().uuid().optional(),
  projectId: z.string().uuid(),
  scanId: z.string().uuid(),
  assetId: z.string().uuid(),
  source: z.string().min(1),
  sourceReliability: z.enum(Object.values(SourceReliability) as [string, ...string[]]),
  observedAt: z.string().datetime({ offset: true }),
  firstSeen: z.string().datetime({ offset: true }).optional(),
  lastSeen: z.string().datetime({ offset: true }).optional(),
  kind: z.string().min(1),
  data: z.record(z.string(), z.unknown()).default({}),
});
export type Observation = z.infer<typeof ObservationSchema>;

export const EvidenceArtifactSchema = z.object({
  id: z.string().uuid().optional(),
  projectId: z.string().uuid(),
  scanId: z.string().uuid(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  contentType: z.string().min(1),
  sizeBytes: z.number().int().nonnegative(),
  storageUri: z.string().min(1),
  redacted: z.boolean().default(false),
  createdAt: z.string().datetime({ offset: true }),
});
export type EvidenceArtifact = z.infer<typeof EvidenceArtifactSchema>;

export const FindingSchema = z.object({
  id: z.string().uuid().optional(),
  projectId: z.string().uuid(),
  scanId: z.string().uuid(),
  assetId: z.string().uuid().optional(),
  category: z.string().min(1),
  title: z.string().min(1),
  description: z.string().default(""),
  severity: z.enum(Object.values(Severity) as [string, ...string[]]),
  confidence: z.number().min(0).max(1),
  validation: z.enum(Object.values(ValidationState) as [string, ...string[]]),
  sourceReliability: z.enum(Object.values(SourceReliability) as [string, ...string[]]),
  firstSeen: z.string().datetime({ offset: true }),
  lastSeen: z.string().datetime({ offset: true }),
  evidenceIds: z.array(z.string().uuid()).default([]),
});
export type Finding = z.infer<typeof FindingSchema>;

export const CoverageRecordSchema = z.object({
  projectId: z.string().uuid(),
  scanId: z.string().uuid(),
  stage: z.string().min(1),
  status: z.enum(Object.values(CoverageStatus) as [string, ...string[]]),
  expected: z.number().int().nonnegative().default(0),
  collected: z.number().int().nonnegative().default(0),
  notes: z.string().default(""),
});
export type CoverageRecord = z.infer<typeof CoverageRecordSchema>;

export const JobRecordSchema = z.object({
  id: z.string().uuid().optional(),
  scanId: z.string().uuid(),
  projectId: z.string().uuid(),
  stage: z.string().min(1),
  jobKey: z.string().min(1),
  dependsOn: z.array(z.string()).default([]),
  status: z.enum(Object.values(JobStatus) as [string, ...string[]]),
  attempts: z.number().int().nonnegative().default(0),
  maxAttempts: z.number().int().positive().default(3),
  notBefore: z.string().datetime({ offset: true }).optional(),
  deadline: z.string().datetime({ offset: true }).optional(),
  lastError: z.string().optional(),
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
});
export type JobRecord = z.infer<typeof JobRecordSchema>;
