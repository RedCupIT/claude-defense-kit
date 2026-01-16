#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import { exec } from "child_process";
import { parseArgs } from "./cli.js";
import { detectClaudeCode } from "./detectors/claude-code.js";
import { scanMcpServers } from "./scanners/mcp.js";
import { scanFilesystem } from "./scanners/filesystem.js";
import { scanCredentials } from "./scanners/credentials.js";
import { scanCapabilities } from "./scanners/capabilities.js";
import {
  scanMcpIntegrity,
  scanClaudeInstallation,
} from "./scanners/integrity.js";
import { scanIdentityExposure } from "./scanners/identity.js";
import {
  scanConfigInventory,
  getInventorySummary,
} from "./scanners/config-inventory.js";
import { computeEffectiveConfig } from "./analyzers/effective-config.js";
import { calculateRiskScore } from "./analyzers/risk-score.js";
import {
  analyzeBlastRadius,
  generateAttackChains,
} from "./analyzers/blast-radius.js";
import { generateRecommendations } from "./analyzers/recommendations.js";
import { generateSecurityIssues } from "./analyzers/issues.js";
import { generateTerminalReport } from "./reporters/terminal.js";
import { generateJsonReport } from "./reporters/json.js";
import { generateHtmlReport } from "./reporters/html.js";
import { startServer } from "./server.js";
import type {
  ScanResults,
  ScanResultsWithIssues,
  CliOptions,
} from "./types/index.js";

// Open URL in default browser (cross-platform)
function openBrowser(url: string): void {
  const platform = process.platform;
  let command: string;

  switch (platform) {
    case "darwin":
      command = `open "${url}"`;
      break;
    case "win32":
      command = `start "" "${url}"`;
      break;
    default:
      command = `xdg-open "${url}"`;
  }

  exec(command, (err) => {
    if (err) {
      console.error(`Could not open browser: ${err.message}`);
      console.error(`Open this file manually: ${url}`);
    }
  });
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv);

  // Default behavior: start interactive server
  if (options.openBrowser && !options.output && options.format === "terminal") {
    console.log("Starting AI Agent Security Audit...\n");
    await startServer(options.scope);
    return;
  }

  // Non-interactive mode: generate static report
  if (options.verbose) {
    console.error("Starting AI agent security audit...\n");
  }

  // Run the scan
  const results = await runScan(options);

  // Generate the report in requested format
  let report: string;
  switch (options.format) {
    case "json":
      report = generateJsonReport(results);
      break;
    case "html":
      report = generateHtmlReport(results);
      break;
    case "terminal":
    default:
      report = generateTerminalReport(results, options.color);
      break;
  }

  // Output the report
  if (options.output) {
    fs.writeFileSync(options.output, report, "utf-8");
    if (
      options.openBrowser &&
      (options.format === "html" || options.format === "terminal")
    ) {
      const htmlPath =
        options.format === "html"
          ? options.output
          : options.output.replace(/\.[^.]+$/, ".html");

      if (options.format !== "html") {
        const htmlReport = generateHtmlReport(results);
        fs.writeFileSync(htmlPath, htmlReport, "utf-8");
      }

      console.log(`Report written to: ${options.output}`);
      openBrowser(path.resolve(htmlPath));
    } else {
      console.log(`Report written to: ${options.output}`);
    }
  } else {
    console.log(report);
  }
}

async function runScan(options: CliOptions): Promise<ScanResultsWithIssues> {
  const log = options.verbose ? (msg: string) => console.error(msg) : () => {};

  // Scan configuration inventory (managed, user, projects)
  log("Scanning configuration inventory...");
  const configInventory = await scanConfigInventory({
    scanProjects: true,
    projectScanDepth: 4,
  });

  // Log inventory summary in verbose mode
  if (options.verbose) {
    const summary = getInventorySummary(configInventory);
    for (const line of summary) {
      console.error(line);
    }
    console.error("");
  }

  // Detect AI agents
  log("Detecting AI agents...");
  const agent = await detectClaudeCode();

  // Scan MCP servers
  log("Scanning MCP servers...");
  const mcpServers = await scanMcpServers(agent);

  // Scan filesystem access
  log("Scanning filesystem access...");
  const filesystem = await scanFilesystem();

  // Scan for credentials
  log("Scanning for sensitive files...");
  const credentials = await scanCredentials();

  // Merge sensitive files from credentials scan into filesystem
  filesystem.sensitiveFiles.push(...credentials);

  // Analyze capabilities
  log("Analyzing capabilities...");
  const capabilities = await scanCapabilities(mcpServers);

  // Scan MCP server integrity
  log("Checking MCP server integrity...");
  const integrity = await scanMcpIntegrity(mcpServers);

  // Scan identity exposure
  log("Scanning identity exposure...");
  const identityExposure = await scanIdentityExposure();

  // Scan Claude installation integrity
  log("Checking Claude Code installation...");
  const claudeInstallation = await scanClaudeInstallation();

  // Calculate risk score
  log("Calculating risk score...");
  const riskScore = calculateRiskScore({
    agent,
    mcpServers,
    filesystem,
    capabilities,
  });

  // Analyze blast radius
  log("Analyzing blast radius...");
  const blastRadius = analyzeBlastRadius({
    agent,
    mcpServers,
    filesystem,
    capabilities,
  });

  // Generate attack chains
  log("Generating attack scenarios...");
  const attackChains = generateAttackChains({
    agent,
    mcpServers,
    filesystem,
    capabilities,
  });

  // Generate recommendations
  log("Generating recommendations...");
  const recommendations = generateRecommendations({
    agent,
    mcpServers,
    filesystem,
    capabilities,
    riskScore,
  });

  // Compute effective configuration
  log("Computing effective configuration...");
  const projectPath =
    options.scope.type === "project" ? options.scope.projectPath : null;
  const effectiveConfig = computeEffectiveConfig(configInventory, projectPath);

  const baseResults: ScanResults = {
    timestamp: new Date().toISOString(),
    agent,
    mcpServers,
    filesystem,
    capabilities,
    riskScore,
    blastRadius,
    attackChains,
    recommendations,
    integrity,
    identityExposure,
    claudeInstallation,
    configInventory,
    effectiveConfig,
  };

  // Generate security issues for the interactive UX
  log("Generating security issues...");
  const issues = generateSecurityIssues(baseResults);

  return {
    ...baseResults,
    issues,
  };
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
