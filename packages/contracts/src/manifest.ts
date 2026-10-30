import { z } from "zod";
import { LimitsSchema } from "./scope.js";

export const StageId = {
  INPUT_AUTHORIZATION: "00-input-authorization",
  TARGET_INTELLIGENCE: "01-target-intelligence",
  SUBDOMAIN_DISCOVERY: "02-subdomain-discovery",
  DNS_INFRA: "03-dns-infra",
  HTTP_PROBE: "04-http-probe",
  URL_COLLECTION: "05-url-collection",
  URL_CATEGORIZATION: "06-url-categorization",
  JS_INTELLIGENCE: "07-js-intelligence",
  API_DISCOVERY: "08-api-discovery",
  SECRET_DETECTION: "09-secret-detection",
  SECURITY_CHECKS: "10-security-checks",
  CORRELATION: "11-correlation",
  REPORTING: "12-reporting",
  // Numeric labels are stable identifiers; the execution order is `OrderedStages` below
  // (takeover and login-interface discovery run after correlation and before reporting so the
  // report includes their findings).
  TAKEOVER: "13-subdomain-takeover",
  LOGIN_FINDER: "14-login-finder",
  PORT_SCAN: "15-port-scan",
  TEMPLATE_CHECKS: "16-template-checks",
  CONTENT_DISCOVERY: "17-content-discovery",
  CLOUD_STORAGE: "18-cloud-storage",
} as const;
export type StageIdValue = (typeof StageId)[keyof typeof StageId];

export const OrderedStages: StageIdValue[] = [
  StageId.INPUT_AUTHORIZATION,
  StageId.TARGET_INTELLIGENCE,
  StageId.SUBDOMAIN_DISCOVERY,
  StageId.DNS_INFRA,
  StageId.PORT_SCAN,
  StageId.HTTP_PROBE,
  StageId.URL_COLLECTION,
  StageId.URL_CATEGORIZATION,
  StageId.JS_INTELLIGENCE,
  StageId.API_DISCOVERY,
  StageId.SECRET_DETECTION,
  StageId.SECURITY_CHECKS,
  StageId.TEMPLATE_CHECKS,
  StageId.CORRELATION,
  StageId.TAKEOVER,
  StageId.LOGIN_FINDER,
  StageId.CONTENT_DISCOVERY,
  StageId.CLOUD_STORAGE,
  StageId.REPORTING,
];

export const ScanManifestSchema = z.object({
  schemaVersion: z.literal(1),
  scanId: z.string().uuid(),
  projectId: z.string().uuid(),
  policyId: z.string().uuid(),
  policyVersion: z.number().int().positive(),
  startUrl: z.string().url(),
  rootDomain: z.string().min(1),
  createdAt: z.string().datetime({ offset: true }),
  stages: z.array(z.string()),
  requestedCapabilities: z.array(z.string()).default([]),
  enabledProviders: z.record(z.string(), z.boolean()).default({}),
  limits: LimitsSchema,
});

export type ScanManifest = z.infer<typeof ScanManifestSchema>;
