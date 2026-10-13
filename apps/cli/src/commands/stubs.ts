import type { Context } from "../context.js";
import { NotImplementedError } from "../errors.js";
import type { CommandResult } from "../output.js";

/**
 * Command groups whose backing stages are not implemented yet. They fail loudly with
 * NOT_IMPLEMENTED (exit 3) rather than returning empty successful results.
 */
const STAGE_FOR: Record<string, string> = {
  assets: "Phase 3 (asset discovery)",
  urls: "Phase 4 (URL intelligence)",
  apis: "Phase 5 (JavaScript and API intelligence)",
  secrets: "Phase 6 (secret and exposure analysis)",
  findings: "Phases 6-7 (findings and correlation)",
  coverage: "Phase 2-7 (coverage accounting)",
  report: "Phase 7 (reporting)",
};

export function notImplementedCommand(group: string) {
  return async (_ctx: Context, _args?: unknown): Promise<CommandResult<unknown>> => {
    const stage = STAGE_FOR[group] ?? "a later phase";
    throw new NotImplementedError(
      `'${group}' is not implemented in this build. It depends on ${stage}.`,
    );
  };
}
