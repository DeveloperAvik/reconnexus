import { describe, expect, it } from "vitest";
import { cloudStorageCandidateFor, cloudStorageFindings, contentFindings, corsFindings, emailSecurityFindings, exposedServiceFindings, openRedirectCandidateFor, openRedirectFindings, plannedStagesFor, templateFindings, type CloudStorageFindingInput, type ContentFindingInput, type CorsFindingInput, type EmailSecurityFindingInput, type OpenRedirectFindingInput, type PortFindingInput, type TemplateFindingInput } from "@reconnexus/control-plane";

const port = (over: Partial<PortFindingInput>): PortFindingInput => ({ host: "a.example.com", ip: "93.184.216.34", port: 6379, protocol: "tcp", state: "OPEN", service: "redis", product: "Redis", version: "7.0", ...over });
const tpl = (over: Partial<TemplateFindingInput>): TemplateFindingInput => ({
  url: "https://a.example.com/.git/config", host: "a.example.com", templateId: "git-config", name: "Git Config", severity: "MEDIUM", description: "exposed",
  tags: ["exposure"], references: ["https://ref.test"], matcherName: "", extracted: [], confidence: 0.7, ...over,
});

describe("exposed-service findings", () => {
  it("reports risky open ports as OBSERVED, one per address and port", () => {
    const f = exposedServiceFindings([port({}), port({ host: "b.example.com" }), port({ port: 443 }), port({ port: 3306, state: "FILTERED" }), port({ port: 3389 })]);
    expect(f.map((x) => x.title).sort()).toEqual(["RDP reachable on 93.184.216.34:3389/tcp", "Redis reachable on 93.184.216.34:6379/tcp"]);
    const redis = f.find((x) => x.title.startsWith("Redis"))!;
    expect(redis).toMatchObject({ severity: "HIGH", validation: "OBSERVED", category: "EXPOSED_SERVICE", sourceStage: "15-port-scan" });
    expect(redis.evidenceRefs).toEqual(expect.arrayContaining(["a.example.com", "b.example.com"]));
    expect(redis.subject).toBe("a.example.com");
  });

  it("has stable ids and never marks anything validated", () => {
    expect(exposedServiceFindings([port({})])[0]!.id).toBe(exposedServiceFindings([port({ host: "z.example.com" })])[0]!.id);
    expect(exposedServiceFindings([port({})]).every((x) => x.validation !== "VALIDATED")).toBe(true);
  });
});

describe("template findings", () => {
  it("keeps INFO matches as inventory and caps CRITICAL at HIGH, always SUSPECTED", () => {
    const f = templateFindings([tpl({}), tpl({ templateId: "tech", severity: "INFO" }), tpl({ templateId: "big", severity: "CRITICAL" })]);
    expect(f).toHaveLength(2);
    expect(f.find((x) => x.title.includes("big"))!.severity).toBe("HIGH");
    expect(f.every((x) => x.validation === "SUSPECTED" && x.sourceStage === "16-template-checks")).toBe(true);
  });

  it("de-duplicates the same match and carries references", () => {
    const f = templateFindings([tpl({}), tpl({})]);
    expect(f).toHaveLength(1);
    expect(f[0]!.references).toEqual(["https://ref.test"]);
    expect(f[0]!.subject).toBe("a.example.com");
  });
});

const content = (over: Partial<ContentFindingInput>): ContentFindingInput => ({
  url: "https://a.example.com/.git/HEAD", host: "a.example.com", path: "/.git/HEAD", category: "VCS", status: "CONFIRMED", severity: "HIGH",
  confidence: 0.9, httpStatus: 200, evidence: "content marker present: git HEAD reference", ...over,
});

describe("content-discovery findings", () => {
  it("reports confirmed hits and MEDIUM+ possibilities, always SUSPECTED", () => {
    const f = contentFindings([
      content({}),
      content({ url: "https://a.example.com/backup/", path: "/backup/", category: "BACKUP", status: "POSSIBLE", severity: "MEDIUM", confidence: 0.4 }),
    ]);
    expect(f).toHaveLength(2);
    expect(f.every((x) => x.validation === "SUSPECTED" && x.category === "EXPOSED_CONTENT" && x.sourceStage === "17-content-discovery")).toBe(true);
    expect(f.find((x) => x.title.startsWith("Exposed"))!.severity).toBe("HIGH");
    expect(f.find((x) => x.title.startsWith("Possibly"))).toBeDefined();
  });

  it("keeps INFO hits and weak LOW possibilities as inventory", () => {
    expect(contentFindings([
      content({ severity: "INFO", status: "POSSIBLE", evidence: "path exists but access is denied" }),
      content({ url: "https://a.example.com/x", severity: "LOW", status: "POSSIBLE" }),
    ])).toHaveLength(0);
  });

  it("deduplicates by URL and has stable ids", () => {
    expect(contentFindings([content({}), content({})])).toHaveLength(1);
    expect(contentFindings([content({})])[0]!.id).toBe(contentFindings([content({})])[0]!.id);
  });

  it("is planned only when the policy grants CONTENT_DISCOVERY", () => {
    expect(plannedStagesFor(["ACTIVE_HTTP"])).not.toContain("17-content-discovery");
    expect(plannedStagesFor(["ACTIVE_HTTP", "CONTENT_DISCOVERY"])).toContain("17-content-discovery");
  });
});

const bucket = (over: Partial<CloudStorageFindingInput>): CloudStorageFindingInput => ({
  url: "https://static.example.com/", host: "static.example.com", cloudProvider: "S3", bucket: "static.example.com",
  status: "LISTABLE", confidence: 0.9, httpStatus: 200, objectCount: 12, evidence: "HTTP 200 with a <ListBucketResult> object listing", ...over,
});

describe("cloud storage candidate derivation", () => {
  it("derives the bucket name from a legacy per-bucket vhost CNAME", () => {
    expect(cloudStorageCandidateFor("static.example.com", "mybucket.s3.amazonaws.com")).toEqual({ provider: "S3", bucket: "mybucket" });
    expect(cloudStorageCandidateFor("static.example.com", "mybucket.s3.us-east-1.amazonaws.com.")).toEqual({ provider: "S3", bucket: "mybucket" });
  });

  it("falls back to the custom domain itself for a bare CNAME to the shared endpoint", () => {
    expect(cloudStorageCandidateFor("static.example.com", "s3.amazonaws.com")).toEqual({ provider: "S3", bucket: "static.example.com" });
    expect(cloudStorageCandidateFor("static.example.com", "s3-eu-west-1.amazonaws.com")).toEqual({ provider: "S3", bucket: "static.example.com" });
    expect(cloudStorageCandidateFor("static.example.com", "storage.googleapis.com")).toEqual({ provider: "GCS", bucket: "static.example.com" });
    expect(cloudStorageCandidateFor("static.example.com", "c.storage.googleapis.com")).toEqual({ provider: "GCS", bucket: "static.example.com" });
  });

  it("never matches a website-hosting endpoint (intentionally public content, not a listing)", () => {
    expect(cloudStorageCandidateFor("static.example.com", "mybucket.s3-website-us-east-1.amazonaws.com")).toBeNull();
    expect(cloudStorageCandidateFor("static.example.com", "s3-website-us-east-1.amazonaws.com")).toBeNull();
  });

  it("never matches an unrelated CNAME", () => {
    expect(cloudStorageCandidateFor("static.example.com", "cdn.example.net")).toBeNull();
    expect(cloudStorageCandidateFor("static.example.com", "myapp.herokuapp.com")).toBeNull();
  });
});

describe("cloud storage findings", () => {
  it("reports LISTABLE as a HIGH, SUSPECTED finding naming the provider and bucket", () => {
    const f = cloudStorageFindings([bucket({})]);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "HIGH", validation: "SUSPECTED", category: "EXPOSED_CLOUD_STORAGE", sourceStage: "18-cloud-storage", subject: "static.example.com" });
    expect(f[0]!.title).toContain("static.example.com");
  });

  it("keeps NOT_LISTABLE and INCONCLUSIVE as inventory, never a finding", () => {
    expect(cloudStorageFindings([bucket({ status: "NOT_LISTABLE" }), bucket({ status: "INCONCLUSIVE", url: "https://b.example.com/" })])).toHaveLength(0);
  });

  it("deduplicates by host+bucket and has stable ids", () => {
    expect(cloudStorageFindings([bucket({}), bucket({})])).toHaveLength(1);
    expect(cloudStorageFindings([bucket({})])[0]!.id).toBe(cloudStorageFindings([bucket({})])[0]!.id);
  });

  it("is planned only when the policy grants CLOUD_STORAGE_CHECK", () => {
    expect(plannedStagesFor(["ACTIVE_HTTP"])).not.toContain("18-cloud-storage");
    expect(plannedStagesFor(["ACTIVE_HTTP", "CLOUD_STORAGE_CHECK"])).toContain("18-cloud-storage");
  });
});

describe("open-redirect candidate derivation", () => {
  it("matches a known redirect-shaped parameter with a non-empty value", () => {
    expect(openRedirectCandidateFor("https://a.example.com/login?next=/dashboard")).toEqual({ parameter: "next" });
    expect(openRedirectCandidateFor("https://a.example.com/go?redirect_uri=https://b.example.com/")).toEqual({ parameter: "redirect_uri" });
  });

  it("never matches an unrelated or empty parameter", () => {
    expect(openRedirectCandidateFor("https://a.example.com/search?q=shoes")).toBeNull();
    expect(openRedirectCandidateFor("https://a.example.com/login?next=")).toBeNull();
    expect(openRedirectCandidateFor("https://a.example.com/login")).toBeNull();
  });

  it("returns null for an unparseable URL", () => {
    expect(openRedirectCandidateFor("not a url")).toBeNull();
  });
});

const cors = (over: Partial<CorsFindingInput>): CorsFindingInput => ({
  url: "https://a.example.com/api/account", host: "a.example.com", status: "REFLECTS_ARBITRARY_ORIGIN_WITH_CREDENTIALS", confidence: 0.9,
  allowOrigin: "https://cors-probe.reconnexus.invalid", allowCredentials: true, testedOrigin: "https://cors-probe.reconnexus.invalid",
  httpStatus: 200, evidence: "Access-Control-Allow-Origin reflected the arbitrary Origin sent, with Access-Control-Allow-Credentials: true", ...over,
});

describe("CORS misconfiguration findings", () => {
  it("reports credentialed reflection as HIGH and reflection alone as MEDIUM, both SUSPECTED", () => {
    const f = corsFindings([cors({}), cors({ url: "https://b.example.com/", host: "b.example.com", status: "REFLECTS_ARBITRARY_ORIGIN", allowCredentials: false })]);
    expect(f).toHaveLength(2);
    expect(f.every((x) => x.validation === "SUSPECTED" && x.category === "CORS_MISCONFIGURATION" && x.sourceStage === "19-cors-redirect")).toBe(true);
    expect(f.find((x) => x.subject === "a.example.com")!.severity).toBe("HIGH");
    expect(f.find((x) => x.subject === "b.example.com")!.severity).toBe("MEDIUM");
  });

  it("keeps NOT_VULNERABLE as inventory, never a finding", () => {
    expect(corsFindings([cors({ status: "NOT_VULNERABLE" })])).toHaveLength(0);
  });

  it("deduplicates by URL and has stable ids", () => {
    expect(corsFindings([cors({}), cors({})])).toHaveLength(1);
    expect(corsFindings([cors({})])[0]!.id).toBe(corsFindings([cors({})])[0]!.id);
  });

  it("is planned only when the policy grants CORS_REDIRECT_CHECK", () => {
    expect(plannedStagesFor(["ACTIVE_HTTP"])).not.toContain("19-cors-redirect");
    expect(plannedStagesFor(["ACTIVE_HTTP", "CORS_REDIRECT_CHECK"])).toContain("19-cors-redirect");
  });
});

const redirect = (over: Partial<OpenRedirectFindingInput>): OpenRedirectFindingInput => ({
  url: "https://a.example.com/login?next=/dashboard", testedUrl: "https://a.example.com/login?next=https%3A%2F%2Fredirect-canary.reconnexus.invalid%2F",
  host: "a.example.com", parameter: "next", status: "CONFIRMED", confidence: 0.9, httpStatus: 302, location: "https://redirect-canary.reconnexus.invalid/",
  evidence: "redirected to the injected externally-controlled value", ...over,
});

describe("open-redirect findings", () => {
  it("reports CONFIRMED as a MEDIUM, SUSPECTED finding naming the parameter", () => {
    const f = openRedirectFindings([redirect({})]);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "MEDIUM", validation: "SUSPECTED", category: "OPEN_REDIRECT", sourceStage: "19-cors-redirect", subject: "a.example.com" });
    expect(f[0]!.title).toContain("next");
  });

  it("keeps NOT_VULNERABLE as inventory, never a finding", () => {
    expect(openRedirectFindings([redirect({ status: "NOT_VULNERABLE" })])).toHaveLength(0);
  });

  it("deduplicates by host+parameter and has stable ids", () => {
    expect(openRedirectFindings([redirect({}), redirect({})])).toHaveLength(1);
    expect(openRedirectFindings([redirect({})])[0]!.id).toBe(openRedirectFindings([redirect({})])[0]!.id);
  });

  it("is planned only when the policy grants CORS_REDIRECT_CHECK", () => {
    expect(plannedStagesFor(["ACTIVE_HTTP"])).not.toContain("19-cors-redirect");
    expect(plannedStagesFor(["ACTIVE_HTTP", "CORS_REDIRECT_CHECK"])).toContain("19-cors-redirect");
  });
});

const email = (over: Partial<EmailSecurityFindingInput>): EmailSecurityFindingInput => ({
  host: "example.com", category: "SPF", status: "ABSENT", confidence: 0.8, value: "", evidence: "no SPF (v=spf1) TXT record found", ...over,
});

describe("email security findings", () => {
  it("reports SPF/DMARC ABSENT, WEAK and MISCONFIGURED, always SUSPECTED", () => {
    const f = emailSecurityFindings([
      email({}),
      email({ category: "DMARC", status: "WEAK", host: "b.example.com", evidence: "DMARC policy is p=none" }),
      email({ category: "SPF", status: "MISCONFIGURED", host: "c.example.com", evidence: "SPF record ends in '+all'" }),
    ]);
    expect(f).toHaveLength(3);
    expect(f.every((x) => x.validation === "SUSPECTED" && x.category === "EMAIL_SECURITY_WEAKNESS" && x.sourceStage === "20-email-security")).toBe(true);
    expect(f.find((x) => x.subject === "b.example.com")!.severity).toBe("MEDIUM");
    expect(f.find((x) => x.subject === "c.example.com")!.severity).toBe("MEDIUM");
    expect(f.find((x) => x.subject === "example.com")!.severity).toBe("LOW");
  });

  it("never reports DKIM NOT_DETECTED (absence from a selector guess is not evidence)", () => {
    expect(emailSecurityFindings([email({ category: "DKIM", status: "NOT_DETECTED", evidence: "no DKIM record found" })])).toHaveLength(0);
  });

  it("keeps STRONG and DETECTED as inventory, never a finding", () => {
    expect(emailSecurityFindings([email({ status: "STRONG" }), email({ category: "DKIM", status: "DETECTED" })])).toHaveLength(0);
  });

  it("deduplicates by host+category and has stable ids", () => {
    expect(emailSecurityFindings([email({}), email({})])).toHaveLength(1);
    expect(emailSecurityFindings([email({})])[0]!.id).toBe(emailSecurityFindings([email({})])[0]!.id);
  });

  it("is planned unconditionally, like other core DNS-based stages", () => {
    expect(plannedStagesFor(["DNS"])).toContain("20-email-security");
    expect(plannedStagesFor([])).toContain("20-email-security");
  });
});
