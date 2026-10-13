import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { REDACTED, Logger, isSensitiveKey, redactString, redactValue } from "@reconnexus/logging";

describe("redaction", () => {
  it("detects sensitive keys", () => {
    expect(isSensitiveKey("api_key")).toBe(true);
    expect(isSensitiveKey("Authorization")).toBe(true);
    expect(isSensitiveKey("user_password")).toBe(true);
    expect(isSensitiveKey("username")).toBe(false);
  });

  it("redacts sensitive object keys but preserves others", () => {
    const out = redactValue({ apiKey: "abc", username: "bob", nested: { token: "t", host: "example.com" } }) as Record<string, unknown>;
    expect(out.apiKey).toBe(REDACTED);
    expect(out.username).toBe("bob");
    expect((out.nested as Record<string, unknown>).token).toBe(REDACTED);
    expect((out.nested as Record<string, unknown>).host).toBe("example.com");
  });

  it("redacts secret-shaped values in the synthetic fixture", () => {
    const fixture = readFileSync(fileURLToPath(new URL("../fixtures/secrets.synthetic.txt", import.meta.url)), "utf8");
    const redacted = redactString(fixture);
    expect(redacted).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(redacted).not.toContain("eyJzdWIi");
    expect(redacted).not.toContain("xoxb-0000000000");
    expect(redacted).not.toContain("ghp_ABCDEFGHIJKLMNOP");
    expect(redacted).not.toContain("AIzaSyA00000000000000000");
    expect(redacted).not.toContain("-----BEGIN RSA PRIVATE KEY-----");
    expect(redacted).not.toContain("S3cr3t-P4ss");
  });

  it("does not log secrets via the logger", () => {
    const lines: string[] = [];
    const logger = new Logger({ level: "debug", format: "json", sink: (l) => lines.push(l) });
    logger.info("connecting", { databaseUrl: "postgres://user:S3cr3t@host/db", api_key: "topsecret" });
    const joined = lines.join("\n");
    expect(joined).not.toContain("S3cr3t");
    expect(joined).not.toContain("topsecret");
  });
});
