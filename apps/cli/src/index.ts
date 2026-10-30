import { Command, Option } from "commander";
import { ExitCode, RECONNEXUS_VERSION } from "@reconnexus/contracts";
import { loadContext, type Context } from "./context.js";
import { classifyError } from "./errors.js";
import { color, makeEnvelope, printHuman, printJson, setColorEnabled, type CommandResult } from "./output.js";
import { initCommand } from "./commands/init.js";
import { doctorCommand } from "./commands/doctor.js";
import { providersCheckCommand, providersListCommand, providersMatrixCommand } from "./commands/providers.js";
import { scopeCheckCommand, scopeShowCommand, scopeValidateCommand } from "./commands/scope.js";
import { configMigrateCommand, configShowCommand, configValidateCommand } from "./commands/config.js";
import {
  scanCancelCommand,
  scanListCommand,
  scanResumeCommand,
  scanRunCommand,
  scanStartCommand,
  scanStatusCommand,
} from "./commands/scan.js";
import { coverageCommand } from "./commands/coverage.js";
import { assetsDiffCommand, assetsListCommand } from "./commands/assets.js";
import { httpCommand, technologiesCommand } from "./commands/http.js";
import { vulnsCommand } from "./commands/vulns.js";
import { paramsCommand, urlsListCommand } from "./commands/urls.js";
import { apisCommand, jsCommand, specsCommand } from "./commands/js.js";
import { securityCommand } from "./commands/security.js";
import { secretsCommand } from "./commands/secrets.js";
import { correlationsCommand } from "./commands/correlations.js";
import { reportCommand } from "./commands/report.js";
import { takeoverCommand } from "./commands/takeover.js";
import { adminCommand, cpanelCommand } from "./commands/finder.js";
import { bucketsCommand } from "./commands/buckets.js";
import { corsCommand } from "./commands/cors.js";
import { redirectsCommand } from "./commands/redirects.js";
import { contentCommand } from "./commands/content.js";
import { portsCommand } from "./commands/ports.js";
import { riskCommand } from "./commands/risk.js";
import { changesCommand } from "./commands/changes.js";
import { findingsCommand } from "./commands/findings.js";

function applyColorMode(program: Command): void {
  const mode = (program.opts().color as string | undefined) ?? "auto";
  if (mode === "always") setColorEnabled(true);
  else if (mode === "never") setColorEnabled(false);
  else setColorEnabled(process.stdout.isTTY === true && !process.env.NO_COLOR);
}

function globalOptions(program: Command): Context | { error: unknown } {
  try {
    applyColorMode(program);
    return loadContext(program.opts());
  } catch (err) {
    return { error: err };
  }
}

function emit<T>(command: string, ctx: Context | null, r: CommandResult<T>): void {
  const json = ctx?.json ?? true;
  if (json) {
    printJson(makeEnvelope(command, r));
  } else if (r.render) {
    printHuman(r.render());
  }
  if (r.warnings?.length && !json) {
    for (const w of r.warnings) process.stderr.write(`  ${color.yellow("!")} ${color.dim(w)}\n`);
  }
  process.exitCode = r.exitCode;
}

function emitError(command: string, ctx: Context | null, err: unknown): void {
  const { code, message, details } = classifyError(err);
  const json = ctx?.json ?? true;
  if (json) {
    printJson(makeEnvelope(command, { exitCode: code }, { code: String(code), message, ...(details !== undefined ? { details } : {}) }));
  } else {
    process.stderr.write(`error: ${message}\n`);
  }
  process.exitCode = code;
}

async function run<T>(command: string, program: Command, build: (ctx: Context) => Promise<CommandResult<T>> | CommandResult<T>): Promise<void> {
  const ctxOrErr = globalOptions(program);
  if ("error" in ctxOrErr) {
    emitError(command, null, ctxOrErr.error);
    return;
  }
  const ctx = ctxOrErr;
  try {
    const r = await build(ctx);
    emit(command, ctx, r);
  } catch (err) {
    emitError(command, ctx, err);
  }
}

function buildProgram(): Command {
  const program = new Command();
  program
    .name("reconnexus")
    .description("CLI reconnaissance and web/API attack-surface intelligence platform")
    .version(RECONNEXUS_VERSION, "--version", "print version and exit")
    .option("--json", "emit structured JSON output", false)
    .option("--config <path>", "path to reconnexus.config.json")
    .option("--log-level <level>", "debug|info|warn|error")
    .option("--log-format <format>", "json|pretty")
    .option("--quiet", "suppress non-error logging", false)
    .addOption(new Option("--color <mode>", "colored output: auto|always|never").choices(["auto", "always", "never"]).default("auto"))
    .showHelpAfterError()
    .addHelpText(
      "after",
      [
        "",
        "Getting started:",
        "  reconnexus init --domain example.com --authorized-by you    scaffold config + scope policy",
        "  reconnexus config migrate                                    create the database schema",
        "  reconnexus scan start https://example.com/ --run             authorize and run a scan",
        "  reconnexus scan list                                         list recent scans",
        "  reconnexus report <scanId>                                   redacted evidence report",
        "  reconnexus report <scanId> --format html --out report.html   shareable HTML report",
        "",
        "Authorized use only. A scan refuses targets outside the supplied scope policy.",
      ].join("\n"),
    );

  // init
  program
    .command("init")
    .description("scaffold reconnexus.config.json and a starter scope policy")
    .option("--domain <domain>", "authorized domain")
    .option("--authorized-by <who>", "who authorized the assessment")
    .option("--reference <ref>", "authorization reference / ticket")
    .option("--out <path>", "policy output path (default policies/<domain>.json)")
    .option("--force", "overwrite existing files", false)
    .action((opts) =>
      run("init", program, (ctx) =>
        initCommand(ctx, {
          ...(opts.domain ? { domain: opts.domain } : {}),
          ...(opts.authorizedBy ? { authorizedBy: opts.authorizedBy } : {}),
          ...(opts.reference ? { reference: opts.reference } : {}),
          ...(opts.out ? { out: opts.out } : {}),
          force: opts.force === true,
        }),
      ),
    );

  // doctor
  program
    .command("doctor")
    .description("check runtime, dependencies, providers, and paths")
    .action(() => run("doctor", program, (ctx) => doctorCommand(ctx)));

  // providers
  const providers = program.command("providers").description("inspect external providers");
  providers
    .command("list")
    .description("list known providers and their health")
    .action(() => run("providers list", program, (ctx) => providersListCommand(ctx)));
  providers
    .command("check <name>")
    .description("health-check a single provider")
    .action((name: string) => run(`providers check ${name}`, program, (ctx) => providersCheckCommand(ctx, name)));
  providers
    .command("matrix")
    .description("emit the machine-readable provider compatibility matrix")
    .action(() => run("providers matrix", program, (ctx) => providersMatrixCommand(ctx)));

  // scope
  const scope = program.command("scope").description("scope policy validation and enforcement");
  scope
    .command("check <target>")
    .description("evaluate whether a target is in scope for a capability")
    .option("--policy <file>", "path to scope policy JSON")
    .addOption(new Option("--kind <kind>", "target kind").choices(["URL", "HOST", "DOMAIN", "IP", "CIDR"]))
    .option("--capability <capability>", "capability to authorize")
    .option("--resolve", "resolve DNS and validate every address (network-disabled by default)", false)
    .option("--allow-restricted", "allow restricted address space (requires INTERNAL_NETWORK)", false)
    .action((target: string, opts) =>
      run("scope check", program, (ctx) =>
        scopeCheckCommand(ctx, target, {
          ...(opts.policy ? { policy: opts.policy } : {}),
          ...(opts.kind ? { kind: opts.kind } : {}),
          ...(opts.capability ? { capability: opts.capability } : {}),
          resolve: opts.resolve === true,
          allowRestricted: opts.allowRestricted === true,
        }),
      ),
    );
  scope
    .command("validate <file>")
    .description("schema-validate a scope policy file")
    .action((file: string) => run("scope validate", program, (ctx) => scopeValidateCommand(ctx, file)));
  scope
    .command("show <file>")
    .description("print a scope policy file")
    .action((file: string) => run("scope show", program, (ctx) => scopeShowCommand(ctx, file)));

  // config
  const config = program.command("config").description("configuration inspection and migrations");
  config.command("show").description("print effective configuration (secrets redacted)").action(() => run("config show", program, (ctx) => configShowCommand(ctx)));
  config.command("validate").description("validate effective configuration").action(() => run("config validate", program, (ctx) => configValidateCommand(ctx)));
  config
    .command("migrate")
    .description("apply database migrations")
    .option("--status", "show migration status instead of applying", false)
    .action((opts) => run("config migrate", program, (ctx) => configMigrateCommand(ctx, { status: opts.status === true })));

  // scan
  const scan = program.command("scan").description("scan lifecycle");
  scan
    .command("start <url>")
    .description("validate and authorize a start URL (Stage 00) and create a scan")
    .option("--policy <file>", "path to scope policy JSON (default: policies/*.json)")
    .option("--workspace <name>", "workspace name", "default")
    .option("--allow-restricted", "allow restricted address space (requires INTERNAL_NETWORK)", false)
    .option("--run", "immediately run the scan after creating it", false)
    .addOption(new Option("--profile <name>", "scan profile: quick, standard, deep or stealth (never exceeds the policy's limits)").choices(["quick", "standard", "deep", "stealth"]))
    .action((url: string, opts) =>
      run("scan start", program, (ctx) =>
        scanStartCommand(ctx, url, {
          ...(opts.policy ? { policy: opts.policy } : {}),
          ...(opts.workspace ? { workspace: opts.workspace } : {}),
          ...(opts.profile ? { profile: opts.profile } : {}),
          allowRestricted: opts.allowRestricted === true,
          run: opts.run === true,
        }),
      ),
    );
  const scanRunOptions = (cmd: import("commander").Command): import("commander").Command =>
    cmd
      .option("--providers <list>", "comma-separated subdomain providers")
      .option("--dns-providers <list>", "comma-separated DNS providers")
      .option("--ip-providers <list>", "comma-separated IP metadata providers")
      .option("--http-providers <list>", "comma-separated HTTP probe providers")
      .option("--url-providers <list>", "comma-separated URL collection providers")
      .option("--js-providers <list>", "comma-separated JavaScript analysis providers")
      .option("--api-providers <list>", "comma-separated API specification providers")
      .option("--security-providers <list>", "comma-separated security metadata providers")
      .option("--secret-providers <list>", "comma-separated secret-scan providers")
      .option("--login-providers <list>", "comma-separated login/cPanel finder providers")
      .option("--port-providers <list>", "comma-separated port-scan providers (stage runs only if the policy grants PORT_SCAN)")
      .option("--template-providers <list>", "comma-separated template-check providers (stage runs only if the policy grants ACTIVE_TEMPLATE_CHECK)")
      .option("--template-tags <tags>", "template tags to include, e.g. exposure,misconfig (intrusive tags are always excluded)")
      .option("--cloud-storage-providers <list>", "comma-separated cloud-storage providers (stage runs only if the policy grants CLOUD_STORAGE_CHECK)")
      .option("--content-providers <list>", "comma-separated content-discovery providers (stage runs only if the policy grants CONTENT_DISCOVERY)")
      .option("--cors-redirect-providers <list>", "comma-separated CORS/open-redirect providers (stage runs only if the policy grants CORS_REDIRECT_CHECK)")
      .option("--ports <spec>", "TCP ports to scan, e.g. 80,443,8000-8100 (default: a built-in list of common service ports)")
      .option("--max-attempts <n>", "maximum attempts per stage", (v: string) => Number(v));

  scanRunOptions(
    scan.command("run <scanId>").description("execute the implemented stages of a scan (subdomains, DNS, infrastructure)"),
  ).action((id: string, opts) =>
    run("scan run", program, (ctx) =>
      scanRunCommand(ctx, id, {
        ...(opts.providers ? { providers: opts.providers } : {}),
        ...(opts.dnsProviders ? { dnsProviders: opts.dnsProviders } : {}),
        ...(opts.ipProviders ? { ipProviders: opts.ipProviders } : {}),
        ...(opts.httpProviders ? { httpProviders: opts.httpProviders } : {}),
        ...(opts.urlProviders ? { urlProviders: opts.urlProviders } : {}),
        ...(opts.jsProviders ? { jsProviders: opts.jsProviders } : {}),
        ...(opts.apiProviders ? { apiProviders: opts.apiProviders } : {}),
        ...(opts.securityProviders ? { securityProviders: opts.securityProviders } : {}),
        ...(opts.secretProviders ? { secretProviders: opts.secretProviders } : {}),
        ...(opts.loginProviders ? { loginProviders: opts.loginProviders } : {}),
        ...(opts.portProviders ? { portProviders: opts.portProviders } : {}),
        ...(opts.ports ? { ports: opts.ports } : {}),
        ...(opts.templateProviders ? { templateProviders: opts.templateProviders } : {}),
        ...(opts.templateTags ? { templateTags: opts.templateTags } : {}),
        ...(opts.contentProviders ? { contentProviders: opts.contentProviders } : {}),
        ...(opts.cloudStorageProviders ? { cloudStorageProviders: opts.cloudStorageProviders } : {}),
        ...(opts.corsRedirectProviders ? { corsRedirectProviders: opts.corsRedirectProviders } : {}),
        ...(opts.maxAttempts ? { maxAttempts: opts.maxAttempts } : {}),
      }),
    ),
  );

  scanRunOptions(scan.command("resume <scanId>").description("resume a scan from its persisted checkpoints")).action((id: string, opts) =>
    run("scan resume", program, (ctx) =>
      scanResumeCommand(ctx, id, {
        ...(opts.providers ? { providers: opts.providers } : {}),
        ...(opts.dnsProviders ? { dnsProviders: opts.dnsProviders } : {}),
        ...(opts.ipProviders ? { ipProviders: opts.ipProviders } : {}),
        ...(opts.httpProviders ? { httpProviders: opts.httpProviders } : {}),
        ...(opts.urlProviders ? { urlProviders: opts.urlProviders } : {}),
        ...(opts.jsProviders ? { jsProviders: opts.jsProviders } : {}),
        ...(opts.apiProviders ? { apiProviders: opts.apiProviders } : {}),
        ...(opts.securityProviders ? { securityProviders: opts.securityProviders } : {}),
        ...(opts.secretProviders ? { secretProviders: opts.secretProviders } : {}),
        ...(opts.loginProviders ? { loginProviders: opts.loginProviders } : {}),
        ...(opts.portProviders ? { portProviders: opts.portProviders } : {}),
        ...(opts.ports ? { ports: opts.ports } : {}),
        ...(opts.templateProviders ? { templateProviders: opts.templateProviders } : {}),
        ...(opts.templateTags ? { templateTags: opts.templateTags } : {}),
        ...(opts.contentProviders ? { contentProviders: opts.contentProviders } : {}),
        ...(opts.cloudStorageProviders ? { cloudStorageProviders: opts.cloudStorageProviders } : {}),
        ...(opts.corsRedirectProviders ? { corsRedirectProviders: opts.corsRedirectProviders } : {}),
        ...(opts.maxAttempts ? { maxAttempts: opts.maxAttempts } : {}),
      }),
    ),
  );

  scan
    .command("list")
    .description("list recent scans")
    .option("--limit <n>", "maximum number of scans to show", (v: string) => Number(v))
    .action((opts) => run("scan list", program, (ctx) => scanListCommand(ctx, { ...(opts.limit ? { limit: opts.limit } : {}) })));
  scan.command("status <scanId>").description("show scan, job, coverage and provider status").action((id: string) => run("scan status", program, (ctx) => scanStatusCommand(ctx, id)));
  scan.command("cancel <scanId>").description("cancel a scan").action((id: string) => run("scan cancel", program, (ctx) => scanCancelCommand(ctx, id)));

  // coverage
  program
    .command("coverage <scanId>")
    .description("show stage coverage and provider outcomes")
    .action((id: string) => run("coverage", program, (ctx) => coverageCommand(ctx, id)));

  // assets
  const assets = program.command("assets").description("inspect discovered assets");
  assets
    .command("list <scanId>")
    .description("list discovered assets for a scan's project")
    .option("--type <types>", "comma-separated asset types")
    .option("--limit <n>", "maximum number of assets to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("assets list", program, (ctx) =>
        assetsListCommand(ctx, id, {
          ...(opts.type ? { type: opts.type } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );
  assets
    .command("diff <baselineScanId> <currentScanId>")
    .description("compare the assets observed in two scans of the same project")
    .option("--type <types>", "comma-separated asset types to compare")
    .option("--limit <n>", "maximum added/removed rows to show per side", (v: string) => Number(v))
    .action((baseline: string, current: string, opts) =>
      run("assets diff", program, (ctx) =>
        assetsDiffCommand(ctx, baseline, current, {
          ...(opts.type ? { type: opts.type } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  // http probing / fingerprinting
  program
    .command("http <scanId>")
    .description("list HTTP probe observations (status, title, server, TLS)")
    .action((id: string) => run("http", program, (ctx) => httpCommand(ctx, id)));
  program
    .command("technologies <scanId>")
    .description("list technology observations with supporting evidence")
    .action((id: string) => run("technologies", program, (ctx) => technologiesCommand(ctx, id)));
  program
    .command("vulns <scanId>")
    .description("correlate observed technologies with CVE advisories (candidates, never confirmed)")
    .option("--product <substr>", "filter by product or CVE id substring")
    .option("--state <list>", "comma-separated applicability states to show")
    .option("--advisories <file>", "offline advisory database (JSON array) to match against")
    .option("--kev <file>", "CISA KEV catalog JSON to mark known-exploited CVEs")
    .option("--online", "query the NVD API (network) instead of a local database")
    .option("--max-products <n>", "maximum distinct products to look up", (v: string) => Number(v))
    .addOption(new Option("--format <format>", "output format").choices(["human", "json"]))
    .action((id: string, opts) =>
      run("vulns", program, (ctx) =>
        vulnsCommand(ctx, id, {
          ...(opts.product ? { product: opts.product } : {}),
          ...(opts.state ? { state: opts.state } : {}),
          ...(opts.advisories ? { advisories: opts.advisories } : {}),
          ...(opts.kev ? { kev: opts.kev } : {}),
          ...(opts.online ? { online: true } : {}),
          ...(opts.maxProducts !== undefined ? { maxProducts: opts.maxProducts } : {}),
          ...(opts.format ? { format: opts.format } : {}),
        }),
      ),
    );

  // URL intelligence
  program
    .command("urls <scanId>")
    .description("list collected URLs (filter by host/provider/category/param/method/status)")
    .option("--host <substr>", "filter by host substring")
    .option("--provider <name>", "filter by provider")
    .option("--category <category>", "filter by URL classification")
    .option("--param <name>", "filter by parameter name")
    .option("--method <method>", "filter by collection method (CRAWL/PASSIVE/ROBOTS/SITEMAP/SEED)")
    .option("--status <code>", "filter by HTTP status code")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .option("--stats", "show collection statistics instead of rows", false)
    .action((id: string, opts) =>
      run("urls", program, (ctx) =>
        urlsListCommand(ctx, id, {
          ...(opts.host ? { host: opts.host } : {}),
          ...(opts.provider ? { provider: opts.provider } : {}),
          ...(opts.category ? { category: opts.category } : {}),
          ...(opts.param ? { param: opts.param } : {}),
          ...(opts.method ? { method: opts.method } : {}),
          ...(opts.status ? { status: opts.status } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
          stats: opts.stats === true,
        }),
      ),
    );
  program
    .command("params <scanId>")
    .description("parameter inventory and classification summary")
    .action((id: string) => run("params", program, (ctx) => paramsCommand(ctx, id)));

  // JavaScript & API intelligence
  program
    .command("js <scanId>")
    .description("list JavaScript artifacts and source maps")
    .option("--status <status>", "filter by artifact status")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("js", program, (ctx) => jsCommand(ctx, id, { ...(opts.status ? { status: opts.status } : {}), ...(opts.limit ? { limit: opts.limit } : {}) })),
    );
  program
    .command("apis <scanId>")
    .description("list API endpoints (filter by host/method/via/documented/unresolved)")
    .option("--host <substr>", "filter by origin substring")
    .option("--method <method>", "filter by HTTP method")
    .option("--via <source>", "filter by source (JS/SPEC/HTTP)")
    .option("--documented", "only endpoints declared in a specification", false)
    .option("--unresolved", "only unresolved dynamic candidates", false)
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("apis", program, (ctx) =>
        apisCommand(ctx, id, {
          ...(opts.host ? { host: opts.host } : {}),
          ...(opts.method ? { method: opts.method } : {}),
          ...(opts.via ? { via: opts.via } : {}),
          documented: opts.documented === true,
          unresolved: opts.unresolved === true,
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );
  program
    .command("specs <scanId>")
    .description("list API specifications and parse outcomes")
    .action((id: string) => run("specs", program, (ctx) => specsCommand(ctx, id)));

  // Security metadata & exposure intelligence
  program
    .command("security <scanId>")
    .description("list security-metadata observations (TLS/headers/cookies/CORS/HSTS/content-type)")
    .option("--category <category>", "filter by category (TLS/HEADER/COOKIE/CORS/HSTS/CONTENT_TYPE)")
    .option("--status <status>", "filter by status (OBSERVED/INFERRED/INCONSISTENT/NOT_OBSERVED/UNKNOWN/COLLECTION_FAILED)")
    .option("--host <substr>", "filter by service substring")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("security", program, (ctx) =>
        securityCommand(ctx, id, {
          ...(opts.category ? { category: opts.category } : {}),
          ...(opts.status ? { status: opts.status } : {}),
          ...(opts.host ? { host: opts.host } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  // Secret detection (redacted output only — no flag can reveal raw values)
  program
    .command("secrets <scanId>")
    .description("list redacted secret-detection findings (never prints raw values)")
    .option("--rule <ruleId>", "filter by rule id")
    .option("--category <category>", "filter by category")
    .option("--status <status>", "filter by status (CANDIDATE/HIGH_CONFIDENCE/SUPPRESSED/ANALYSIS_FAILED)")
    .option("--confidence <n>", "minimum confidence (0-1)", (v: string) => Number(v))
    .option("--artifact <substr>", "filter by artifact URL substring")
    .option("--host <substr>", "filter by host substring")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("secrets", program, (ctx) =>
        secretsCommand(ctx, id, {
          ...(opts.rule ? { rule: opts.rule } : {}),
          ...(opts.category ? { category: opts.category } : {}),
          ...(opts.status ? { status: opts.status } : {}),
          ...(opts.confidence !== undefined ? { confidence: opts.confidence } : {}),
          ...(opts.artifact ? { artifact: opts.artifact } : {}),
          ...(opts.host ? { host: opts.host } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  // Stage 11 correlation
  program
    .command("correlations <scanId>")
    .description("show Stage 11 correlation results (redacted; distinguishes not-run/failed/partial/empty)")
    .option("--relation <relation>", "filter by relation (SHARES_SECRET_FINGERPRINT/MULTI_SOURCE_CORROBORATION)")
    .option("--subject <substr>", "filter by subject asset substring")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("correlations", program, (ctx) =>
        correlationsCommand(ctx, id, {
          ...(opts.relation ? { relation: opts.relation } : {}),
          ...(opts.subject ? { subject: opts.subject } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  // Subdomain-takeover candidates
  program
    .command("takeover <scanId>")
    .description("list subdomain-takeover candidates (candidate-only; never a confirmed takeover)")
    .option("--status <status>", "filter by status (SUSPECTED/CANDIDATE/NOT_VULNERABLE/INCONCLUSIVE)")
    .option("--service <name>", "filter by service substring")
    .option("--host <substr>", "filter by host substring")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("takeover", program, (ctx) =>
        takeoverCommand(ctx, id, {
          ...(opts.status ? { status: opts.status } : {}),
          ...(opts.service ? { service: opts.service } : {}),
          ...(opts.host ? { host: opts.host } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  // Administrative login and hosting-control-panel interfaces (read-only discovery)
  const finderOptions = (cmd: Command): Command =>
    cmd
      .option("--status <status>", "filter by status (DETECTED/POSSIBLE)")
      .option("--host <substr>", "filter by host substring")
      .option("--confidence <n>", "minimum confidence (0-1)", (v: string) => Number(v))
      .option("--limit <n>", "maximum rows to show", (v: string) => Number(v));

  finderOptions(
    program
      .command("admin <scanId>")
      .description("list discovered admin login interfaces (unauthenticated GET only)"),
  ).action((id: string, opts) =>
    run("admin", program, (ctx) =>
      adminCommand(ctx, id, {
        ...(opts.status ? { status: opts.status } : {}),
        ...(opts.host ? { host: opts.host } : {}),
        ...(opts.confidence !== undefined ? { confidence: opts.confidence } : {}),
        ...(opts.limit ? { limit: opts.limit } : {}),
      }),
    ),
  );

  finderOptions(
    program
      .command("cpanel <scanId>")
      .description("list discovered cPanel/WHM/webmail interfaces (unauthenticated GET only)"),
  ).action((id: string, opts) =>
    run("cpanel", program, (ctx) =>
      cpanelCommand(ctx, id, {
        ...(opts.status ? { status: opts.status } : {}),
        ...(opts.host ? { host: opts.host } : {}),
        ...(opts.confidence !== undefined ? { confidence: opts.confidence } : {}),
        ...(opts.limit ? { limit: opts.limit } : {}),
      }),
    ),
  );

  // Open TCP ports and identified services (port-scan stage; requires the PORT_SCAN capability)
  program
    .command("ports <scanId>")
    .description("list open TCP ports and identified services from the port-scan stage")
    .option("--host <substr>", "filter by host substring")
    .option("--port <n>", "filter by port number", (v: string) => Number(v))
    .option("--service <name>", "filter by service name substring")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("ports", program, (ctx) =>
        portsCommand(ctx, id, {
          ...(opts.host ? { host: opts.host } : {}),
          ...(opts.port !== undefined ? { port: opts.port } : {}),
          ...(opts.service ? { service: opts.service } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  // CNAME-fronted cloud storage buckets (cloud-storage stage; requires CLOUD_STORAGE_CHECK)
  program
    .command("buckets <scanId>")
    .description("list cloud storage buckets found by the cloud-storage stage")
    .option("--host <substr>", "filter by host substring")
    .option("--status <status>", "filter by status (LISTABLE, NOT_LISTABLE, INCONCLUSIVE)")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("buckets", program, (ctx) =>
        bucketsCommand(ctx, id, {
          ...(opts.host ? { host: opts.host } : {}),
          ...(opts.status ? { status: opts.status } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  // Exposed files, backups, debug endpoints and directory listings (content-discovery stage; requires CONTENT_DISCOVERY)
  program
    .command("content <scanId>")
    .description("list exposed paths found by the content-discovery stage")
    .option("--host <substr>", "filter by host substring")
    .option("--category <name>", "filter by category (VCS, CONFIG, BACKUP, DEBUG, LOG, DIRECTORY_LISTING, METADATA)")
    .option("--status <status>", "filter by status (CONFIRMED or POSSIBLE)")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("content", program, (ctx) =>
        contentCommand(ctx, id, {
          ...(opts.host ? { host: opts.host } : {}),
          ...(opts.category ? { category: opts.category } : {}),
          ...(opts.status ? { status: opts.status } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  // CORS reflection probes (cors-redirect stage; requires CORS_REDIRECT_CHECK)
  program
    .command("cors <scanId>")
    .description("list CORS reflection probes found by the cors-redirect stage")
    .option("--host <substr>", "filter by host substring")
    .option("--status <status>", "filter by status (REFLECTS_ARBITRARY_ORIGIN_WITH_CREDENTIALS, REFLECTS_ARBITRARY_ORIGIN, NOT_VULNERABLE)")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("cors", program, (ctx) =>
        corsCommand(ctx, id, {
          ...(opts.host ? { host: opts.host } : {}),
          ...(opts.status ? { status: opts.status } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  // Open-redirect probes (cors-redirect stage; requires CORS_REDIRECT_CHECK)
  program
    .command("redirects <scanId>")
    .description("list open-redirect probes found by the cors-redirect stage")
    .option("--host <substr>", "filter by host substring")
    .option("--status <status>", "filter by status (CONFIRMED, NOT_VULNERABLE)")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("redirects", program, (ctx) =>
        redirectsCommand(ctx, id, {
          ...(opts.host ? { host: opts.host } : {}),
          ...(opts.status ? { status: opts.status } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  // Per-host risk ranking
  program
    .command("risk <scanId>")
    .description("rank hosts by how much attention they deserve (derived from findings, ports and login interfaces)")
    .option("--top <n>", "show only the n highest-ranked hosts", (v: string) => Number(v))
    .option("--min-score <n>", "minimum score (0-100)", (v: string) => Number(v))
    .option("--level <level>", "only hosts at this level (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL)")
    .option("--explain", "show the factors behind each score", false)
    .action((id: string, opts) =>
      run("risk", program, (ctx) =>
        riskCommand(ctx, id, {
          ...(opts.top ? { top: opts.top } : {}),
          ...(opts.minScore !== undefined ? { minScore: opts.minScore } : {}),
          ...(opts.level ? { level: opts.level } : {}),
          explain: opts.explain === true,
        }),
      ),
    );

  // Scan-to-scan change intelligence
  program
    .command("changes <baselineScanId> <currentScanId>")
    .description("compare two scans: assets, DNS, HTTP/TLS, technology, API, JS and findings (read-only)")
    .option("--category <list>", "comma-separated categories (assets,dns,http,tls,technology,api,js,findings)")
    .option("--status <list>", "comma-separated outcomes (ADDED,REMOVED,CHANGED,UNCHANGED,UNKNOWN)")
    .option("--limit <n>", "maximum change rows per category (totals stay exact)", (v: string) => Number(v))
    .addOption(new Option("--format <format>", "output format").choices(["human", "json", "html"]))
    .action((baseline: string, current: string, opts) =>
      run("changes", program, (ctx) =>
        changesCommand(ctx, baseline, current, {
          ...(opts.category ? { category: opts.category } : {}),
          ...(opts.status ? { status: opts.status } : {}),
          ...(opts.limit !== undefined ? { limit: opts.limit } : {}),
          ...(opts.format ? { format: opts.format } : {}),
        }),
      ),
    );

  // Stage 12 reporting
  program
    .command("report <scanId>")
    .description("generate a redacted, evidence-backed report (human/json/jsonl/csv/html)")
    .addOption(new Option("--format <format>", "output format").choices(["human", "json", "jsonl", "csv", "html"]))
    .option("--out <path>", "write the report to a file instead of stdout")
    .option("--max-rows <n>", "maximum rows per inventory section (totals stay exact)", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("report", program, (ctx) =>
        reportCommand(ctx, id, {
          ...(opts.format ? { format: opts.format } : {}),
          ...(opts.out ? { out: opts.out } : {}),
          ...(opts.maxRows !== undefined ? { maxRows: opts.maxRows } : {}),
        }),
      ),
    );

  // Findings (derived from secret/takeover/security-metadata candidates; see `report`)
  program
    .command("findings <scanId>")
    .description("list the scan's redacted findings (same list embedded in `report`)")
    .option("--category <category>", "filter by finding category")
    .option("--severity <severity>", "filter by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)")
    .option("--validation <state>", "filter by validation state (SUSPECTED/INDETERMINATE/REJECTED)")
    .option("--subject <substr>", "filter by affected-asset substring")
    .option("--limit <n>", "maximum rows to show", (v: string) => Number(v))
    .action((id: string, opts) =>
      run("findings", program, (ctx) =>
        findingsCommand(ctx, id, {
          ...(opts.category ? { category: opts.category } : {}),
          ...(opts.severity ? { severity: opts.severity } : {}),
          ...(opts.validation ? { validation: opts.validation } : {}),
          ...(opts.subject ? { subject: opts.subject } : {}),
          ...(opts.limit ? { limit: opts.limit } : {}),
        }),
      ),
    );

  program.configureOutput({
    writeErr: (str) => process.stderr.write(str),
  });

  return program;
}

async function main(): Promise<void> {
  const program = buildProgram();

  // No arguments: show help and exit successfully (friendlier than a usage error).
  if (process.argv.slice(2).length === 0) {
    program.outputHelp();
    process.exitCode = ExitCode.SUCCESS;
    return;
  }

  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    const { code, message } = classifyError(err);
    process.stderr.write(`error: ${message}\n`);
    process.exitCode = code;
    return;
  }
  // Global flags were given but no command ran: show help rather than a silent error.
  if (process.exitCode === undefined) {
    program.outputHelp();
    process.exitCode = ExitCode.SUCCESS;
  }
}

void main();
