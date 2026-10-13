import { loadConfig, type ReconNexusConfig } from "@reconnexus/configuration";
import { Logger, type LogLevel } from "@reconnexus/logging";

export interface GlobalOptions {
  json?: boolean;
  config?: string;
  logLevel?: string;
  logFormat?: string;
  quiet?: boolean;
}

export interface Context {
  config: ReconNexusConfig;
  logger: Logger;
  json: boolean;
}

export function loadContext(opts: GlobalOptions): Context {
  const config = loadConfig({ ...(opts.config ? { configPath: opts.config } : {}) });
  const json = opts.json === true;
  const level = (opts.logLevel as LogLevel | undefined) ?? config.logging.level;
  const format: "json" | "pretty" =
    opts.logFormat === "pretty" || opts.logFormat === "json"
      ? (opts.logFormat as "json" | "pretty")
      : json
        ? "json"
        : process.stdout.isTTY
          ? "pretty"
          : "json";
  const logger = new Logger({ level, format });
  return { config, logger, json };
}
