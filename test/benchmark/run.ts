/**
 * Local, dependency-free micro-benchmarks. Run with:  npx tsx test/benchmark/run.ts
 * Kept separate from the deterministic unit-test suite. Reports wall-clock ns/op and ops/sec on
 * the current machine; no performance target is claimed.
 */
import { parseUrl } from "@reconnexus/normalization";
import { formatReport } from "../../apps/cli/src/commands/report.js";
import type { Report } from "@reconnexus/contracts";

const URLS = [
  "HTTP://Example.COM:80/Path?b=2&a=1#frag",
  "https://user.example.co.uk/a/../b/c?x=1&x=2&y=%2Fz",
  "http://example.com/%2e%2e/admin?next=https%3A%2F%2Fevil.test",
  "https://cdn.example.com/static/js/app.min.js?v=9f2c1a",
  "http://example.com//double//slash",
  "https://example.com/a/b/../c/./d?q=1",
];

function bench(name: string, iterations: number, fn: () => void): void {
  for (let i = 0; i < Math.min(1000, iterations); i++) fn(); // warm-up
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) fn();
  const ns = Number(process.hrtime.bigint() - start);
  const perOp = ns / iterations;
  console.log(`${name.padEnd(34)} ${perOp.toFixed(0).padStart(8)} ns/op   ${(1e9 / perOp).toFixed(0).padStart(11)} ops/sec`);
}

const report: Report = {
  schemaVersion: 1,
  scanId: "11111111-1111-1111-1111-111111111111",
  projectId: "22222222-2222-2222-2222-222222222222",
  rootDomain: "example.com",
  startUrl: "https://example.com/",
  scanStatus: "PARTIAL",
  reportStatus: "PARTIAL",
  generatedAt: "2026-01-01T00:00:00.000Z",
  stages: Array.from({ length: 13 }, (_, i) => ({ stage: `0${i}-stage`, jobStatus: "SUCCEEDED", attempts: 1, coverageStatus: "COLLECTED", expected: 1, collected: 1, notes: "x" })),
  coverageGaps: [],
  assetCounts: { URL: 500, HOST: 42, JS_ARTIFACT: 17 },
  observationCounts: { total: 1000, byKind: { url: 500, "secret-finding": 20 }, bySource: { "builtin-crawler": 500 } },
  secretFindings: Array.from({ length: 50 }, (_, i) => ({ ruleId: "aws-access-key-id", category: "CLOUD_CREDENTIAL", status: "HIGH_CONFIDENCE", confidence: 0.95, artifact: `https://example.com/${i}.js`, host: "example.com", location: `${i}:3`, redactedSnippet: `x='[REDACTED]';` })),
  correlations: Array.from({ length: 20 }, (_, i) => ({ relation: "SHARES_SECRET_FINGERPRINT", status: "OBSERVED", subject: `https://example.com/${i}.js`, related: [`https://example.com/${i + 100}.js`], ruleId: "aws-access-key-id", hmacKeyed: true, correlationGroup: "0123456789abcdef", sourceStage: "11-correlation", evidence: "rule x", confidence: 0.9 })),
  limitations: ["x", "y", "z"],
  summary: "benchmark fixture",
};

console.log("ReconNexus micro-benchmarks (single run; not a target)");
let idx = 0;
bench("URL canonicalization (parseUrl)", 200000, () => {
  parseUrl(URLS[idx % URLS.length]!);
  idx++;
});
bench("report human format", 20000, () => formatReport(report, "human"));
bench("report json format", 20000, () => formatReport(report, "json"));
bench("report csv format", 20000, () => formatReport(report, "csv"));
bench("report jsonl format", 20000, () => formatReport(report, "jsonl"));
