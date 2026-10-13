import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GoWorkerRunner } from "@reconnexus/control-plane";
import type { DiscoveryJob } from "@reconnexus/contracts";

let dir: string;
let script: string;

const SCRIPT = `#!/usr/bin/env node
let d="";
process.stdin.on("data",(c)=>{d+=c;});
process.stdin.on("end",()=>{
  const mode=process.env.FAKE_MODE||"ok";
  if(mode==="malformed"){ process.stdout.write("this is not json"); process.exit(0); }
  if(mode==="timeout"||mode==="abort"){ setInterval(()=>{},1000); return; }
  const res={schemaVersion:1,status:"SUCCEEDED",provider:"fake",providerVersion:"1.0",
    execution:{argv:["fake"],exitCode:0,exitDescription:"",durationMs:1,stdoutBytes:1,stderrBytes:0,truncated:false,timedOut:false,spawnError:""},
    coverage:{attempted:1,succeeded:1,failed:0,skipped:0,unavailable:0},records:[],diagnostics:[]};
  process.stdout.write(JSON.stringify(res));
});
`;

function fakeJob(): DiscoveryJob {
  return {
    schemaVersion: 1,
    scanId: "11111111-1111-1111-1111-111111111111",
    projectId: "22222222-2222-2222-2222-222222222222",
    stage: "02",
    jobKey: "k",
    kind: "SUBDOMAINS",
    provider: "fake",
    policy: {} as never,
    inputs: {},
    limits: { maxConcurrency: 1, requestsPerSecond: 1, crawlDepth: 0, maxRuntimeSeconds: 1, maxArtifactBytes: 1000 },
    allowRestrictedAddresses: false,
  };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "rn-worker-"));
  script = join(dir, "fake-worker.mjs");
  writeFileSync(script, SCRIPT, { mode: 0o755 });
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("GoWorkerRunner", () => {
  it("parses a valid worker result", async () => {
    const runner = new GoWorkerRunner({ argv: [process.execPath, script], cwd: dir, env: { ...process.env, FAKE_MODE: "ok" } });
    const r = await runner.run(fakeJob());
    expect(r.status).toBe("SUCCEEDED");
    expect(r.provider).toBe("fake");
  });

  it("treats malformed worker output as a failure, never success", async () => {
    const runner = new GoWorkerRunner({ argv: [process.execPath, script], cwd: dir, env: { ...process.env, FAKE_MODE: "malformed" } });
    const r = await runner.run(fakeJob());
    expect(r.status).toBe("FAILED");
    expect(r.diagnostics.join(" ")).toContain("non-JSON");
  });

  it("times out and reports a truthful failure", async () => {
    const runner = new GoWorkerRunner({ argv: [process.execPath, script], cwd: dir, env: { ...process.env, FAKE_MODE: "timeout" } });
    const r = await runner.run(fakeJob(), { timeoutMs: 250 });
    expect(r.status).toBe("FAILED");
    expect(r.execution.timedOut).toBe(true);
  }, 15000);

  it("cancels via AbortSignal", async () => {
    const runner = new GoWorkerRunner({ argv: [process.execPath, script], cwd: dir, env: { ...process.env, FAKE_MODE: "abort" } });
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 150);
    const r = await runner.run(fakeJob(), { signal: controller.signal, timeoutMs: 10000 });
    expect(r.status).toBe("CANCELLED");
  }, 15000);

  it("reports SOURCE_UNAVAILABLE when the worker binary cannot be started", async () => {
    const runner = new GoWorkerRunner({ argv: [join(dir, "does-not-exist")], cwd: dir });
    const r = await runner.run(fakeJob());
    expect(r.status).toBe("SOURCE_UNAVAILABLE");
    expect(r.coverage.unavailable).toBe(1);
  });
});
