export const REDACTED = "[REDACTED]";

const SENSITIVE_KEY_RE =
  /(^|[_-])(pass(word|wd)?|secret|token|apikey|api[_-]?key|auth(orization)?|cookie|set[_-]?cookie|credential|private[_-]?key|session[_-]?id|bearer|client[_-]?secret|access[_-]?key|signing[_-]?secret)([_-]|$)/i;

const VALUE_PATTERNS: Array<{ name: string; re: RegExp; mask: (m: string) => string }> = [
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, mask: () => `${REDACTED}:jwt` },
  { name: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/g, mask: (m) => `${m.slice(0, 4)}${"*".repeat(12)}${REDACTED}` },
  { name: "private_key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, mask: () => REDACTED },
  { name: "bearer", re: /\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*/gi, mask: () => `Bearer ${REDACTED}` },
  { name: "basic_auth_url", re: /:\/\/[^/\s:@]+:[^/\s:@]+@/g, mask: () => `://${REDACTED}@` },
  { name: "slack_token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, mask: () => REDACTED },
  { name: "github_token", re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, mask: () => REDACTED },
  { name: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{30,}\b/g, mask: () => REDACTED },
];

/** Scrub known secret-shaped substrings from a string. Safe on arbitrary text. */
export function redactString(input: string): string {
  let out = input;
  for (const { re, mask } of VALUE_PATTERNS) {
    out = out.replace(re, (m) => mask(m));
  }
  return out;
}

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_RE.test(key);
}

/** Recursively redact an arbitrary value. Cycles are handled; depth is bounded. */
export function redactValue(value: unknown, depth = 0): unknown {
  if (depth > 12) return "[depth-limit]";
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactString(value);
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") return value;
  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1));
  if (value instanceof Error) return redactString(value.message);
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSensitiveKey(k) ? REDACTED : redactValue(v, depth + 1);
    }
    return out;
  }
  return String(value);
}
