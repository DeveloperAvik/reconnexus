import { describe, expect, it } from "vitest";
import { checkHmacKey, fingerprintCorrelationStatus } from "@reconnexus/control-plane";
import { doctorCommand } from "../../apps/cli/src/commands/doctor.js";
import { loadContext } from "../../apps/cli/src/context.js";

const STRONG = "synthetic-test-key-0123456789abcdef0123";

describe("checkHmacKey", () => {
  it("reports NOT_SET for a missing key and for an empty key", () => {
    for (const env of [{}, { RECONNEXUS_HMAC_KEY: "" }]) {
      const r = checkHmacKey(env);
      expect(r.state).toBe("NOT_SET");
      expect(r.message).toContain("secret detection still works");
      expect(r.message).toContain("fingerprint correlation is disabled");
    }
  });
  it("reports WEAK for a short key without disclosing it", () => {
    const key = "short-synth";
    const r = checkHmacKey({ RECONNEXUS_HMAC_KEY: key });
    expect(r.state).toBe("WEAK");
    expect(JSON.stringify(r)).not.toContain(key);
  });
  it("applies the same 16-byte threshold as the worker, in UTF-8 bytes", () => {
    expect(checkHmacKey({ RECONNEXUS_HMAC_KEY: "k".repeat(15) }).state).toBe("WEAK");
    expect(checkHmacKey({ RECONNEXUS_HMAC_KEY: "k".repeat(16) }).state).toBe("CONFIGURED");
    expect(checkHmacKey({ RECONNEXUS_HMAC_KEY: "   " }).state).toBe("WEAK"); // set, but weak
    expect(checkHmacKey({ RECONNEXUS_HMAC_KEY: "é".repeat(8) }).state).toBe("CONFIGURED"); // 16 bytes
  });
  it("reports CONFIGURED for an adequate key without disclosing it", () => {
    const r = checkHmacKey({ RECONNEXUS_HMAC_KEY: STRONG });
    expect(r.state).toBe("CONFIGURED");
    expect(JSON.stringify(r)).not.toContain(STRONG);
  });
});

describe("fingerprintCorrelationStatus", () => {
  const keyed = new Map([["a", true], ["b", false]]);
  it("is NO_SECRET_FINDINGS with nothing to correlate", () => {
    expect(fingerprintCorrelationStatus([], keyed)).toEqual({ state: "NO_SECRET_FINDINGS", note: "" });
  });
  it("is ENABLED when every finding has a keyed fingerprint", () => {
    expect(fingerprintCorrelationStatus([{ artifact: "a", fingerprint: "f1" }], keyed).state).toBe("ENABLED");
  });
  it("is DISABLED_NO_HMAC_KEY when no finding is usable, and says detection is unaffected", () => {
    const r = fingerprintCorrelationStatus([{ artifact: "b", fingerprint: "" }, { artifact: "a", fingerprint: "" }], keyed);
    expect(r.state).toBe("DISABLED_NO_HMAC_KEY");
    expect(r.note).toContain("secret detection is unaffected");
    expect(r.note).not.toMatch(/failed/i);
  });
  it("is PARTIAL_UNKEYED for a mix", () => {
    const r = fingerprintCorrelationStatus([{ artifact: "a", fingerprint: "f1" }, { artifact: "b", fingerprint: "" }], keyed);
    expect(r.state).toBe("PARTIAL_UNKEYED");
    expect(r.note).toContain("1 of 2");
  });
});

describe("doctor surfaces the HMAC key state", () => {
  const withKey = async (value: string | undefined) => {
    const prev = process.env.RECONNEXUS_HMAC_KEY;
    if (value === undefined) delete process.env.RECONNEXUS_HMAC_KEY;
    else process.env.RECONNEXUS_HMAC_KEY = value;
    try {
      const res = await doctorCommand(loadContext({}));
      return { res, text: res.render ? res.render() : "" };
    } finally {
      if (prev === undefined) delete process.env.RECONNEXUS_HMAC_KEY;
      else process.env.RECONNEXUS_HMAC_KEY = prev;
    }
  };

  it("warns (without failing) when the key is missing or empty", async () => {
    for (const v of [undefined, ""]) {
      const { res, text } = await withKey(v);
      expect(text).toContain("RECONNEXUS_HMAC_KEY");
      expect(text).toContain("WARN");
      expect(text).toContain("correlation is disabled");
      expect((res.warnings ?? []).some((w) => w.includes("RECONNEXUS_HMAC_KEY"))).toBe(true);
    }
  }, 30000);

  it("warns for a weak key without exposing it, and never changes the exit code", async () => {
    const weak = "weak-synth-key";
    const w = await withKey(weak);
    expect(w.text).toContain("WARN");
    expect(w.text).not.toContain(weak);
    expect(JSON.stringify(w.res.data)).not.toContain(weak);
    expect((w.res.warnings ?? []).some((x) => x.includes("RECONNEXUS_HMAC_KEY"))).toBe(true);
    const codes = new Set([(await withKey(undefined)).res.exitCode, w.res.exitCode, (await withKey(STRONG)).res.exitCode]);
    expect(codes.size).toBe(1); // exit-code contract is independent of the HMAC key
  }, 60000);

  it("is quiet and never prints the key when configured", async () => {
    const { res, text } = await withKey(STRONG);
    expect(text).toContain("correlation is enabled");
    expect(text).not.toContain(STRONG);
    expect(JSON.stringify(res.data)).not.toContain(STRONG);
    expect((res.warnings ?? []).some((w) => w.includes("RECONNEXUS_HMAC_KEY"))).toBe(false);
  }, 30000);
});
