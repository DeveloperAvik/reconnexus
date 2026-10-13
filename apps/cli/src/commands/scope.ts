import {
  ExitCode,
  ScopeTargetKind,
  type CapabilityName,
  type ScopeTargetKindValue,
} from "@reconnexus/contracts";
import { ScopeEngine, resolveAndCheck } from "@reconnexus/scope-policy";
import type { Context } from "../context.js";
import { CliError } from "../errors.js";
import { formatDecision, result, type CommandResult } from "../output.js";
import { loadPolicyFile, resolvePolicy } from "../policy.js";

export interface ScopeCheckOptions {
  policy?: string;
  kind?: string;
  capability?: string;
  resolve?: boolean;
  allowRestricted?: boolean;
  now?: Date;
}

export async function scopeCheckCommand(
  ctx: Context,
  target: string,
  opts: ScopeCheckOptions,
): Promise<CommandResult<unknown>> {
  const { policy } = resolvePolicy(opts.policy, ctx.config.defaultPolicyFile);

  const kind = (opts.kind ?? "URL").toUpperCase() as ScopeTargetKindValue;
  if (!Object.values(ScopeTargetKind).includes(kind)) {
    throw new CliError(`invalid --kind '${opts.kind}'. Expected one of ${Object.values(ScopeTargetKind).join(", ")}`, ExitCode.USAGE_ERROR);
  }
  const capability = (opts.capability ?? "ACTIVE_HTTP") as CapabilityName;

  const engine = new ScopeEngine(policy, {
    allowRestrictedAddresses: opts.allowRestricted ?? ctx.config.network.allowRestrictedAddresses,
  });

  const request = { kind, value: target, capability, ...(opts.now ? { now: opts.now } : {}) };
  const decision = opts.resolve ? await resolveAndCheck(engine, request, { resolve: true }) : engine.check(request);

  const exitCode = decision.allowed ? ExitCode.SUCCESS : ExitCode.SCOPE_DENIED;
  return result({
    exitCode,
    data: { target, kind, capability, decision },
    decision,
    render: () => formatDecision(decision),
  });
}

export async function scopeValidateCommand(ctx: Context, file: string): Promise<CommandResult<unknown>> {
  const policy = loadPolicyFile(file);
  return result({
    exitCode: ExitCode.SUCCESS,
    data: { valid: true, policyId: policy.policyId, projectId: policy.projectId, version: policy.policyVersion },
    render: () =>
      `policy OK\n  policyId: ${policy.policyId}\n  projectId: ${policy.projectId}\n  version: ${policy.policyVersion}\n  capabilities: ${policy.authorization.capabilities.join(", ")}\n  valid: ${policy.authorization.validFrom} → ${policy.authorization.validUntil}`,
  });
}

export async function scopeShowCommand(ctx: Context, file: string): Promise<CommandResult<unknown>> {
  const policy = loadPolicyFile(file);
  return result({
    exitCode: ExitCode.SUCCESS,
    data: policy,
    render: () => JSON.stringify(policy, null, 2),
  });
}
