import {
  Capability,
  ScopeDecisionCode,
  ScopePolicySchema,
  ScopeTargetKind,
  type ScopeAuditRecord,
  type ScopeCheckRequest,
  type ScopeDecision,
  type ScopePolicy,
} from "@reconnexus/contracts";
import {
  canonicalHost,
  classifyIp,
  hostMatchesDomain,
  ipEquals,
  ipInCidrList,
  isSubdomainOf,
  parseIp,
  registrableDomain,
  tryParseUrl,
  type ParsedIp,
} from "@reconnexus/normalization";

export class ScopePolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopePolicyError";
  }
}

export interface ScopeEngineOptions {
  /** Global hard floor. When false (default), restricted address space is always denied. */
  allowRestrictedAddresses?: boolean;
  /** Optional audit sink; every decision is recorded for the audit trail. */
  auditSink?: (record: ScopeAuditRecord) => void;
}

interface Target {
  host: string;
  ip?: ParsedIp;
  path?: string;
}

export class ScopeEngine {
  private readonly allowRestricted: boolean;
  private readonly auditSink: ((record: ScopeAuditRecord) => void) | undefined;

  constructor(private readonly policy: ScopePolicy, opts: ScopeEngineOptions = {}) {
    this.allowRestricted = opts.allowRestrictedAddresses ?? false;
    this.auditSink = opts.auditSink;
  }

  getPolicy(): ScopePolicy {
    return this.policy;
  }

  private authorize(req: ScopeCheckRequest, decision: ScopeDecision): ScopeDecision {
    this.auditSink?.({
      at: (req.now ?? new Date()).toISOString(),
      projectId: this.policy.projectId,
      policyVersion: this.policy.policyVersion,
      kind: req.kind,
      value: req.value,
      capability: req.capability,
      decision,
    });
    return decision;
  }

  private deny(code: ScopeDecision["code"], reason: string, matchedRule?: string): ScopeDecision {
    return { allowed: false, code, reason, ...(matchedRule ? { matchedRule } : {}) };
  }

  /** Extract host/ip/path from the request target, or return a denial. */
  private resolveTarget(req: ScopeCheckRequest): Target | ScopeDecision {
    if (req.kind === ScopeTargetKind.URL) {
      const parsed = tryParseUrl(req.value, { allowedSchemes: ["http", "https"] });
      if (!parsed) return this.deny(ScopeDecisionCode.INVALID_TARGET, `not a valid http(s) URL: ${req.value}`);
      const ip = parsed.isIpLiteral ? parseIp(parsed.host) : null;
      return ip ? { host: parsed.host, ip, path: parsed.path } : { host: parsed.host, path: parsed.path };
    }
    if (req.kind === ScopeTargetKind.HOST || req.kind === ScopeTargetKind.DOMAIN) {
      const host = canonicalHost(req.value);
      if (host.length === 0) return this.deny(ScopeDecisionCode.INVALID_TARGET, "empty host");
      const ip = parseIp(host);
      return ip ? { host, ip } : { host };
    }
    if (req.kind === ScopeTargetKind.IP) {
      const ip = parseIp(req.value);
      if (!ip) return this.deny(ScopeDecisionCode.INVALID_TARGET, `not an IP literal: ${req.value}`);
      return { host: ip.canonical, ip };
    }
    if (req.kind === ScopeTargetKind.CIDR) {
      return { host: canonicalHost(req.value) };
    }
    return this.deny(ScopeDecisionCode.INVALID_TARGET, `unknown target kind ${req.kind}`);
  }

  check(req: ScopeCheckRequest): ScopeDecision {
    const now = req.now ?? new Date();

    // (1) Authorization validity period.
    const from = new Date(this.policy.authorization.validFrom).getTime();
    const until = new Date(this.policy.authorization.validUntil).getTime();
    const t = now.getTime();
    if (Number.isNaN(from) || Number.isNaN(until)) {
      return this.authorize(req, this.deny(ScopeDecisionCode.AUTHORIZATION_EXPIRED, "authorization has invalid validity dates"));
    }
    if (t < from) {
      return this.authorize(
        req,
        this.deny(ScopeDecisionCode.AUTHORIZATION_NOT_YET_VALID, `authorization is not valid until ${this.policy.authorization.validFrom}`),
      );
    }
    if (t > until) {
      return this.authorize(
        req,
        this.deny(ScopeDecisionCode.AUTHORIZATION_EXPIRED, `authorization expired at ${this.policy.authorization.validUntil}`),
      );
    }

    // (2) Capability permission.
    if (!this.policy.authorization.capabilities.includes(req.capability)) {
      return this.authorize(
        req,
        this.deny(ScopeDecisionCode.CAPABILITY_NOT_PERMITTED, `capability ${req.capability} is not authorized by policy v${this.policy.policyVersion}`),
      );
    }

    const resolved = this.resolveTarget(req);
    if ("allowed" in resolved) return this.authorize(req, resolved);

    // (3) Exclusions take precedence over inclusions.
    const excluded = this.matchExclusion(resolved);
    if (excluded) return this.authorize(req, excluded);

    // (4) Address-space restrictions (connection-time hardening). Evaluated before the
    // positive match so that a restricted destination is reported as such even when the
    // name/IP would otherwise be out of scope; this is the stronger security signal.
    const addresses = this.collectAddresses(resolved, req);
    const addressDecisions = addresses.map((a) => this.evaluateAddress(a));
    const blocked = addressDecisions.find((d) => !d.allowed);
    if (blocked) {
      return this.authorize(req, {
        allowed: false,
        code: ScopeDecisionCode.RESTRICTED_ADDRESS_SPACE,
        reason: `destination address ${blocked.address} is not permitted: ${blocked.reason}`,
        addressDecisions,
      });
    }

    // (5) Positive scope match is required.
    const inclusion = this.matchInclusion(resolved);
    if (!inclusion.ok) {
      return this.authorize(
        req,
        this.deny(ScopeDecisionCode.NOT_IN_SCOPE, `target ${resolved.host} is not covered by the scope policy`, undefined),
      );
    }

    return this.authorize(req, {
      allowed: true,
      code: ScopeDecisionCode.ALLOWED,
      reason: `in scope (${inclusion.reason})`,
      ...(inclusion.rule ? { matchedRule: inclusion.rule } : {}),
      ...(addressDecisions.length ? { addressDecisions } : {}),
    });
  }

  private evaluateAddress(address: string): { address: string; allowed: boolean; reason: string } {
    const ip = parseIp(address);
    if (!ip) return { address, allowed: false, reason: "not a parseable IP literal" };

    const cls = classifyIp(ip);
    const explicitlyAllowedIp =
      this.policy.inScope.ips.some((v) => parseIp(v) && sameIp(parseIp(v)!, ip)) ||
      ipInCidrList(ip, this.policy.inScope.cidrs) !== null;

    if (cls.isSpecial) {
      // A specific in-scope IP/CIDR entry is an explicit authorization to that exact destination.
      if (explicitlyAllowedIp) {
        return { address, allowed: true, reason: "explicitly authorized in-scope address" };
      }
      if (!this.allowRestricted || !this.policy.authorization.capabilities.includes(Capability.INTERNAL_NETWORK)) {
        return {
          address,
          allowed: false,
          reason: `restricted address space (${describeSpecial(cls)}) requires INTERNAL_NETWORK capability and network.allowRestrictedAddresses`,
        };
      }
    }
    return { address, allowed: true, reason: "routable public address" };
  }

  private collectAddresses(target: Target, req: ScopeCheckRequest): string[] {
    const out: string[] = [];
    if (target.ip) out.push(target.ip.canonical);
    for (const a of req.resolvedAddresses ?? []) out.push(a);
    return Array.from(new Set(out));
  }

  private matchExclusion(target: Target): ScopeDecision | null {
    if (target.ip) {
      if (this.policy.exclusions.ips.some((v) => parseIp(v) && sameIp(parseIp(v)!, target.ip!))) {
        return this.deny(ScopeDecisionCode.EXCLUDED, `IP ${target.ip.canonical} is excluded`);
      }
      const cidr = ipInCidrList(target.ip, this.policy.exclusions.cidrs);
      if (cidr) return this.deny(ScopeDecisionCode.EXCLUDED, `IP ${target.ip.canonical} falls in excluded CIDR`);
    }
    for (const h of this.policy.exclusions.hosts) {
      if (canonicalHost(h) === target.host) return this.deny(ScopeDecisionCode.EXCLUDED, `host ${target.host} is excluded`);
    }
    for (const d of this.policy.exclusions.domains) {
      if (hostMatchesDomain(target.host, d.value, d.includeSubdomains) || isSubdomainOf(target.host, d.value)) {
        return this.deny(ScopeDecisionCode.EXCLUDED, `host ${target.host} is excluded by domain rule ${d.value}`);
      }
    }
    if (target.path) {
      for (const p of this.policy.exclusions.paths) {
        if (p.length > 0 && target.path.startsWith(p)) {
          return this.deny(ScopeDecisionCode.EXCLUDED_PATH, `path ${target.path} is excluded by rule ${p}`);
        }
      }
    }
    return null;
  }

  private matchInclusion(target: Target): { ok: boolean; rule?: string; reason: string } {
    if (target.ip) {
      const ipRule = this.policy.inScope.ips.find((v) => parseIp(v) && sameIp(parseIp(v)!, target.ip!));
      if (ipRule) return { ok: true, rule: `ip:${ipRule}`, reason: "exact IP match" };
      const cidr = ipInCidrList(target.ip, this.policy.inScope.cidrs);
      if (cidr) return { ok: true, rule: `cidr:${cidr.base.canonical}/${cidr.prefix}`, reason: "CIDR match" };
      return { ok: false, reason: "no IP/CIDR inclusion" };
    }

    for (const h of this.policy.inScope.hosts) {
      if (canonicalHost(h) === target.host) return { ok: true, rule: `host:${h}`, reason: "exact host match" };
    }
    for (const d of this.policy.inScope.domains) {
      if (hostMatchesDomain(target.host, d.value, d.includeSubdomains)) {
        return { ok: true, rule: `domain:${d.value}${d.includeSubdomains ? " (+subdomains)" : ""}`, reason: "domain match" };
      }
    }
    // Registrable-domain inference: if a policy lists an apex domain, a host whose
    // registrable domain equals it is in scope even without subdomain wildcarding,
    // because the host is a subdomain of an authorized domain.
    const reg = registrableDomain(target.host);
    if (reg) {
      for (const d of this.policy.inScope.domains) {
        if (canonicalHost(d.value) === reg) {
          return { ok: true, rule: `domain:${d.value}`, reason: "registrable-domain match" };
        }
      }
    }
    return { ok: false, reason: "no domain/host inclusion" };
  }
}

function describeSpecial(cls: ReturnType<typeof classifyIp>): string {
  const parts: string[] = [];
  if (cls.isLoopback) parts.push("loopback");
  if (cls.isPrivate) parts.push("private");
  if (cls.isLinkLocal) parts.push("link-local");
  if (cls.isMetadata) parts.push("cloud-metadata");
  if (cls.isCGNAT) parts.push("cgnat");
  if (cls.isReserved) parts.push("reserved");
  if (cls.isMulticast) parts.push("multicast");
  if (cls.isUnspecified) parts.push("unspecified");
  if (cls.isBroadcast) parts.push("broadcast");
  return parts.join(", ") || "special";
}

function sameIp(a: ParsedIp, b: ParsedIp): boolean {
  return ipEquals(a, b);
}

export function loadPolicyFromJson(raw: unknown): ScopePolicy {
  const parsed = ScopePolicySchema.safeParse(raw);
  if (!parsed.success) {
    throw new ScopePolicyError(`invalid scope policy: ${JSON.stringify(parsed.error.flatten())}`);
  }
  return parsed.data as ScopePolicy;
}
