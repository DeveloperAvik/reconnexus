import { describe, expect, it } from "vitest";
import { CorrelationRecordSchema } from "@reconnexus/contracts";

const base = {
  relation: "SHARES_SECRET_FINGERPRINT",
  status: "OBSERVED",
  subject: "https://example.com/a.js",
  related: ["https://example.com/b.js"],
  ruleId: "aws-access-key-id",
  hmacKeyed: true,
  correlationGroup: "0123456789abcdef",
  sourceRecordIds: ["11111111-1111-1111-1111-111111111111"],
  sourceStage: "11-correlation",
  evidence: "rule aws-access-key-id; correlation group 0123456789abcdef (2 artifacts)",
  confidence: 0.9,
};

describe("correlation record contract", () => {
  it("accepts a well-formed correlation record", () => {
    const r = CorrelationRecordSchema.safeParse(base);
    expect(r.success, JSON.stringify(r.success ? {} : r.error.flatten())).toBe(true);
  });

  it("rejects an unknown relation", () => {
    expect(CorrelationRecordSchema.safeParse({ ...base, relation: "CONFIRMED_EXPLOIT" }).success).toBe(false);
  });

  it("rejects a CONFIRMED/VALIDATED status", () => {
    expect(CorrelationRecordSchema.safeParse({ ...base, status: "CONFIRMED" }).success).toBe(false);
    expect(CorrelationRecordSchema.safeParse({ ...base, status: "VALIDATED" }).success).toBe(false);
  });

  it("rejects confidence outside [0,1]", () => {
    expect(CorrelationRecordSchema.safeParse({ ...base, confidence: 1.4 }).success).toBe(false);
  });

  it("rejects non-uuid source record ids", () => {
    expect(CorrelationRecordSchema.safeParse({ ...base, sourceRecordIds: ["not-a-uuid"] }).success).toBe(false);
  });
});
