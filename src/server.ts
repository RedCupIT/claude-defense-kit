import express from "express";
import { exec } from "child_process";
import * as fs from "fs";
import { detectClaudeCode } from "./detectors/claude-code.js";
import { scanMcpServers } from "./scanners/mcp.js";
import { scanFilesystem } from "./scanners/filesystem.js";
import { scanCredentials } from "./scanners/credentials.js";
import { scanCapabilities } from "./scanners/capabilities.js";
import {
  scanMcpIntegrity,
  scanClaudeInstallation,
  acceptCurrentHash,
  getBaselinePath,
  acceptClaudeInstallationHash,
} from "./scanners/integrity.js";
import { scanIdentityExposure } from "./scanners/identity.js";
import { scanConfigInventory } from "./scanners/config-inventory.js";
import { computeEffectiveConfig } from "./analyzers/effective-config.js";
import { calculateRiskScore } from "./analyzers/risk-score.js";
import {
  analyzeBlastRadius,
  generateAttackChains,
} from "./analyzers/blast-radius.js";
import { generateRecommendations } from "./analyzers/recommendations.js";
import { generateSecurityIssues } from "./analyzers/issues.js";
import { generateHtmlReport } from "./reporters/html.js";
import {
  generateLandingPage,
  generateScanningPage,
  generateReportShell,
} from "./reporters/landing.js";
import {
  denyPath,
  disableMcpServer,
  revertConfig,
  hasBackup,
  getConfigPath,
  readClaudeConfig,
  getDenyPathDiff,
  getDisableMcpDiff,
  denyTool,
  getDenyToolDiff,
  enableTool,
  getEnableToolDiff,
  denyBashCommand,
  getDenyBashDiff,
  getSandboxDiff,
  updateSandboxConfig,
  allowDirectory,
  denyDirectory,
  removePermission,
  getPermissions,
  getAllowDirectoryDiff,
  getDenyDirectoryDiff,
  getRemovePermissionDiff,
  SECURITY_PROFILES,
  getApplyProfileDiff,
  applySecurityProfile,
  setConfigScope,
  getConfigScope,
  configExists,
} from "./config/writer.js";
import type {
  ScanResults,
  ScanResultsWithIssues,
  ConfigScope,
  CliOptions,
} from "./types/index.js";

const DEFAULT_PORT = 3847;

// Run the full scan
async function runScan(): Promise<ScanResultsWithIssues> {
  const agent = await detectClaudeCode();
  const mcpServers = await scanMcpServers(agent);
  const filesystem = await scanFilesystem();
  const credentials = await scanCredentials();

  filesystem.sensitiveFiles.push(...credentials);

  const capabilities = await scanCapabilities(mcpServers);
  const integrity = await scanMcpIntegrity(mcpServers);
  const identityExposure = await scanIdentityExposure();
  const claudeInstallation = await scanClaudeInstallation();

  const partialResults = {
    agent,
    mcpServers,
    filesystem,
    capabilities,
  };

  const riskScore = calculateRiskScore(partialResults);
  const blastRadius = analyzeBlastRadius(partialResults);
  const attackChains = generateAttackChains(partialResults);
  const recommendations = generateRecommendations({
    ...partialResults,
    riskScore,
  });

  // Scan configuration inventory
  const configInventory = await scanConfigInventory({
    scanProjects: true,
    projectScanDepth: 4,
  });

  // Compute effective configuration
  const scope = getConfigScope();
  const projectPath = scope.type === "project" ? scope.projectPath : null;
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

  // Generate security issues for the new UX
  const issues = generateSecurityIssues(baseResults);

  return {
    ...baseResults,
    issues,
  };
}

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
    }
  });
}

export async function startServer(
  scope?: ConfigScope,
  options?: CliOptions,
): Promise<void> {
  const port = options?.port || DEFAULT_PORT;
  const shouldOpenBrowser = options?.openBrowser !== false;

  // Set the config scope if provided
  if (scope) {
    setConfigScope(scope);
    const scopeType =
      scope.type === "project" ? `project (${scope.projectPath})` : "global";
    console.log(`Config scope: ${scopeType}`);

    // Check if project config exists
    if (scope.type === "project" && !configExists()) {
      console.log(
        `Note: No config file exists at ${scope.projectPath}/.claude/settings.json`,
      );
      console.log(
        "A new config file will be created when you apply your first fix.\n",
      );
    }
  }

  const app = express();
  app.use(express.json());

  // Serve the scanning interstitial page (instant load)
  app.get("/", (_req, res) => {
    const html = generateScanningPage();
    res.type("html").send(html);
  });

  // Serve the full report (uses cached scan if available via query param)
  app.get("/report", async (req, res) => {
    try {
      // Check if client has cached results (passed via query param)
      const useCached = req.query.cached === "true";

      if (useCached) {
        // Client will inject cached data via JavaScript
        // Send a shell page that reads from sessionStorage
        const shellHtml = generateReportShell();
        res.type("html").send(shellHtml);
      } else {
        // No cache, run fresh scan
        const results = await runScan();
        const html = generateHtmlReport(results);
        res.type("html").send(html);
      }
    } catch (err) {
      console.error("Scan error:", err);
      res.status(500).send("Error running scan");
    }
  });

  // API endpoint to get pre-rendered report HTML from scan data
  app.post("/api/render-report", async (req, res) => {
    try {
      const scanData = req.body;
      if (!scanData || !scanData.agent) {
        return res.status(400).json({ error: "Invalid scan data" });
      }
      const html = generateHtmlReport(scanData);
      res.type("html").send(html);
    } catch (err) {
      console.error("Render report error:", err);
      res.status(500).send("Error rendering report");
    }
  });

  // Serve the landing/about page
  app.get("/about", (_req, res) => {
    const html = generateLandingPage();
    res.type("html").send(html);
  });

  // API: Run a fresh scan and return JSON
  app.get("/api/scan", async (_req, res) => {
    try {
      const results = await runScan();
      res.json(results);
    } catch (err) {
      console.error("Scan error:", err);
      res.status(500).json({ error: "Error running scan" });
    }
  });

  // API: Get current config
  app.get("/api/config", (_req, res) => {
    try {
      const config = readClaudeConfig();
      res.json({
        config,
        path: getConfigPath(),
        hasBackup: hasBackup(),
      });
    } catch (err) {
      console.error("Config read error:", err);
      res.status(500).json({ error: "Error reading config" });
    }
  });

  // API: View config file in browser
  app.get("/api/config/view", (req, res) => {
    try {
      // Check if a specific path was requested
      const requestedPath = req.query.path as string | undefined;

      let configPath: string;
      let json: string;

      if (requestedPath) {
        // Read the specific file requested
        if (!fs.existsSync(requestedPath)) {
          return res.status(404).send(`File not found: ${requestedPath}`);
        }
        const content = fs.readFileSync(requestedPath, "utf-8");
        try {
          const parsed = JSON.parse(content);
          json = JSON.stringify(parsed, null, 2);
        } catch {
          // If not valid JSON, show raw content
          json = content;
        }
        configPath = requestedPath.replace(process.env.HOME || "", "~");
      } else {
        // Fall back to current scope's config
        const config = readClaudeConfig();
        configPath = getConfigPath().replace(process.env.HOME || "", "~");
        json = JSON.stringify(config, null, 2);
      }

      const html = `<!DOCTYPE html>
<html>
<head>
  <title>${configPath}</title>
  <style>
    body {
      font-family: monospace;
      background: #0d1117;
      color: #c9d1d9;
      padding: 24px;
      margin: 0;
    }
    pre {
      white-space: pre-wrap;
      word-wrap: break-word;
    }
    h1 {
      font-size: 1rem;
      color: #8b949e;
      margin-bottom: 16px;
    }
  </style>
</head>
<body>
  <h1>${configPath}</h1>
  <pre>${json}</pre>
</body>
</html>`;
      res.type("html").send(html);
    } catch (err) {
      console.error("Config view error:", err);
      res.status(500).send("Error reading config");
    }
  });

  // API: Preview deny path change (returns diff)
  app.post("/api/preview/deny-path", (req, res) => {
    try {
      const { path } = req.body;
      if (!path) {
        return res.status(400).json({ error: "path is required" });
      }
      const diff = getDenyPathDiff(path);
      const alreadyApplied = diff.before === diff.after;
      res.json({
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
        before: diff.before,
        after: diff.after,
        alreadyApplied,
      });
    } catch (err) {
      console.error("Preview deny path error:", err);
      res.status(500).json({ error: "Error generating preview" });
    }
  });

  // API: Preview disable MCP change (returns diff)
  app.post("/api/preview/disable-mcp", (req, res) => {
    try {
      const { name } = req.body;
      if (!name) {
        return res.status(400).json({ error: "name is required" });
      }
      const diff = getDisableMcpDiff(name);
      res.json({
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
        before: diff.before,
        after: diff.after,
      });
    } catch (err) {
      console.error("Preview disable MCP error:", err);
      res.status(500).json({ error: "Error generating preview" });
    }
  });

  // API: Deny path access
  app.post("/api/deny-path", async (req, res) => {
    try {
      const { path } = req.body;
      if (!path) {
        return res.status(400).json({ error: "path is required" });
      }
      denyPath(path);
      res.json({
        success: true,
        message: `Denied access to ${path}`,
        configPath: getConfigPath(),
      });
    } catch (err) {
      console.error("Deny path error:", err);
      res.status(500).json({ error: "Error denying path" });
    }
  });

  // API: Disable MCP server
  app.post("/api/disable-mcp", async (req, res) => {
    try {
      const { name } = req.body;
      if (!name) {
        return res.status(400).json({ error: "name is required" });
      }
      disableMcpServer(name);
      res.json({
        success: true,
        message: `Disabled MCP server: ${name}`,
        configPath: getConfigPath(),
      });
    } catch (err) {
      console.error("Disable MCP error:", err);
      res.status(500).json({ error: "Error disabling MCP server" });
    }
  });

  // API: Undo last change
  app.post("/api/undo", async (_req, res) => {
    try {
      if (!hasBackup()) {
        return res.status(400).json({ error: "No backup available" });
      }
      const success = revertConfig();
      if (success) {
        res.json({
          success: true,
          message: "Reverted to previous config",
        });
      } else {
        res.status(500).json({ error: "Failed to revert config" });
      }
    } catch (err) {
      console.error("Undo error:", err);
      res.status(500).json({ error: "Error reverting config" });
    }
  });

  // API: Preview deny tool change (returns diff)
  app.post("/api/preview/deny-tool", (req, res) => {
    try {
      const { name } = req.body;
      if (!name) {
        return res.status(400).json({ error: "name is required" });
      }
      const diff = getDenyToolDiff(name);
      res.json({
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
        before: diff.before,
        after: diff.after,
      });
    } catch (err) {
      console.error("Preview deny tool error:", err);
      res.status(500).json({ error: "Error generating preview" });
    }
  });

  // API: Deny tool
  app.post("/api/deny-tool", (req, res) => {
    try {
      const { name } = req.body;
      if (!name) {
        return res.status(400).json({ error: "name is required" });
      }
      denyTool(name);
      res.json({
        success: true,
        message: `Disabled tool: ${name}`,
        configPath: getConfigPath(),
      });
    } catch (err) {
      console.error("Deny tool error:", err);
      res.status(500).json({ error: "Error disabling tool" });
    }
  });

  // API: Preview enable tool change (returns diff)
  app.post("/api/preview/enable-tool", (req, res) => {
    try {
      const { name } = req.body;
      if (!name) {
        return res.status(400).json({ error: "name is required" });
      }
      const diff = getEnableToolDiff(name);
      res.json({
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
        before: diff.before,
        after: diff.after,
      });
    } catch (err) {
      console.error("Preview enable tool error:", err);
      res.status(500).json({ error: "Error generating preview" });
    }
  });

  // API: Enable tool (remove from disallowed list)
  app.post("/api/enable-tool", (req, res) => {
    try {
      const { name } = req.body;
      if (!name) {
        return res.status(400).json({ error: "name is required" });
      }
      enableTool(name);
      res.json({
        success: true,
        message: `Enabled tool: ${name}`,
        configPath: getConfigPath(),
      });
    } catch (err) {
      console.error("Enable tool error:", err);
      res.status(500).json({ error: "Error enabling tool" });
    }
  });

  // API: Preview deny bash command change (returns diff)
  app.post("/api/preview/deny-bash", (req, res) => {
    try {
      const { pattern } = req.body;
      if (!pattern) {
        return res.status(400).json({ error: "pattern is required" });
      }
      const diff = getDenyBashDiff(pattern);
      res.json({
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
        before: diff.before,
        after: diff.after,
      });
    } catch (err) {
      console.error("Preview deny bash error:", err);
      res.status(500).json({ error: "Error generating preview" });
    }
  });

  // API: Deny bash command
  app.post("/api/deny-bash", (req, res) => {
    try {
      const { pattern } = req.body;
      if (!pattern) {
        return res.status(400).json({ error: "pattern is required" });
      }
      denyBashCommand(pattern);
      res.json({
        success: true,
        message: `Blocked bash command: ${pattern}`,
        configPath: getConfigPath(),
      });
    } catch (err) {
      console.error("Deny bash error:", err);
      res.status(500).json({ error: "Error blocking bash command" });
    }
  });

  // API: Preview sandbox config change (returns diff)
  app.post("/api/preview/sandbox", (req, res) => {
    try {
      const { path, value } = req.body;
      if (!path) {
        return res.status(400).json({ error: "path is required" });
      }
      const diff = getSandboxDiff(path, value);
      res.json({
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
        before: diff.before,
        after: diff.after,
      });
    } catch (err) {
      console.error("Preview sandbox error:", err);
      res.status(500).json({ error: "Error generating preview" });
    }
  });

  // API: Update sandbox config
  app.post("/api/update-sandbox", (req, res) => {
    try {
      const { path, value } = req.body;
      if (!path) {
        return res.status(400).json({ error: "path is required" });
      }
      updateSandboxConfig(path, value);
      res.json({
        success: true,
        message: `Updated sandbox.${path}`,
        configPath: getConfigPath(),
      });
    } catch (err) {
      console.error("Update sandbox error:", err);
      res.status(500).json({ error: "Error updating sandbox config" });
    }
  });

  // API: Accept current hash as new baseline
  app.post("/api/accept-hash", (req, res) => {
    try {
      const { serverName, targetPath, hash } = req.body;
      if (!serverName || !targetPath || !hash) {
        return res.status(400).json({
          error: "serverName, targetPath, and hash are required",
        });
      }
      acceptCurrentHash(serverName, targetPath, hash);
      res.json({
        success: true,
        message: `Accepted new hash for ${serverName}`,
        baselinePath: getBaselinePath().replace(process.env.HOME || "", "~"),
      });
    } catch (err) {
      console.error("Accept hash error:", err);
      res.status(500).json({ error: "Error accepting hash" });
    }
  });

  // ============================================
  // Directory Access Control Endpoints
  // ============================================

  // API: Get current permissions
  app.get("/api/permissions", (_req, res) => {
    try {
      const permissions = getPermissions();
      res.json(permissions);
    } catch (err) {
      console.error("Get permissions error:", err);
      res.status(500).json({ error: "Error getting permissions" });
    }
  });

  // API: Preview allow directory change
  app.post("/api/preview/allow-directory", (req, res) => {
    try {
      const { directory } = req.body;
      if (!directory) {
        return res.status(400).json({ error: "directory is required" });
      }
      const diff = getAllowDirectoryDiff(directory);
      res.json({
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
        before: diff.before,
        after: diff.after,
      });
    } catch (err) {
      console.error("Preview allow directory error:", err);
      res.status(500).json({ error: "Error generating preview" });
    }
  });

  // API: Allow directory access
  app.post("/api/allow-directory", (req, res) => {
    try {
      const { directory } = req.body;
      if (!directory) {
        return res.status(400).json({ error: "directory is required" });
      }
      allowDirectory(directory);
      res.json({
        success: true,
        message: `Allowed access to ${directory}/**`,
        configPath: getConfigPath(),
      });
    } catch (err) {
      console.error("Allow directory error:", err);
      res.status(500).json({ error: "Error allowing directory" });
    }
  });

  // API: Preview deny directory change
  app.post("/api/preview/deny-directory", (req, res) => {
    try {
      const { directory } = req.body;
      if (!directory) {
        return res.status(400).json({ error: "directory is required" });
      }
      const diff = getDenyDirectoryDiff(directory);
      res.json({
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
        before: diff.before,
        after: diff.after,
      });
    } catch (err) {
      console.error("Preview deny directory error:", err);
      res.status(500).json({ error: "Error generating preview" });
    }
  });

  // API: Deny directory access
  app.post("/api/deny-directory", (req, res) => {
    try {
      const { directory } = req.body;
      if (!directory) {
        return res.status(400).json({ error: "directory is required" });
      }
      denyDirectory(directory);
      res.json({
        success: true,
        message: `Denied access to ${directory}/**`,
        configPath: getConfigPath(),
      });
    } catch (err) {
      console.error("Deny directory error:", err);
      res.status(500).json({ error: "Error denying directory" });
    }
  });

  // API: Preview remove permission change
  app.post("/api/preview/remove-permission", (req, res) => {
    try {
      const { rule, type } = req.body;
      if (!rule || !type) {
        return res.status(400).json({ error: "rule and type are required" });
      }
      const diff = getRemovePermissionDiff(rule, type);
      res.json({
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
        before: diff.before,
        after: diff.after,
      });
    } catch (err) {
      console.error("Preview remove permission error:", err);
      res.status(500).json({ error: "Error generating preview" });
    }
  });

  // API: Remove permission rule
  app.post("/api/remove-permission", (req, res) => {
    try {
      const { rule, type } = req.body;
      if (!rule || !type) {
        return res.status(400).json({ error: "rule and type are required" });
      }
      removePermission(rule, type);
      res.json({
        success: true,
        message: `Removed ${type} rule: ${rule}`,
        configPath: getConfigPath(),
      });
    } catch (err) {
      console.error("Remove permission error:", err);
      res.status(500).json({ error: "Error removing permission" });
    }
  });

  // ============================================
  // Security Profile Endpoints
  // ============================================

  // API: Get available security profiles
  app.get("/api/profiles", (_req, res) => {
    try {
      const profiles = Object.entries(SECURITY_PROFILES).map(
        ([key, profile]) => ({
          id: key,
          name: profile.name,
          description: profile.description,
        }),
      );
      res.json(profiles);
    } catch (err) {
      console.error("Get profiles error:", err);
      res.status(500).json({ error: "Error getting profiles" });
    }
  });

  // API: Preview apply security profile
  app.post("/api/preview/apply-profile", (req, res) => {
    try {
      const { profileId } = req.body;
      if (!profileId || !(profileId in SECURITY_PROFILES)) {
        return res.status(400).json({ error: "Valid profileId is required" });
      }
      const diff = getApplyProfileDiff(
        profileId as keyof typeof SECURITY_PROFILES,
      );
      const profile =
        SECURITY_PROFILES[profileId as keyof typeof SECURITY_PROFILES];
      res.json({
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
        before: diff.before,
        after: diff.after,
        profile: {
          name: profile.name,
          description: profile.description,
        },
      });
    } catch (err) {
      console.error("Preview apply profile error:", err);
      res.status(500).json({ error: "Error generating preview" });
    }
  });

  // API: Apply security profile
  app.post("/api/apply-profile", (req, res) => {
    try {
      const { profileId } = req.body;
      if (!profileId || !(profileId in SECURITY_PROFILES)) {
        return res.status(400).json({ error: "Valid profileId is required" });
      }
      applySecurityProfile(profileId as keyof typeof SECURITY_PROFILES);
      const profile =
        SECURITY_PROFILES[profileId as keyof typeof SECURITY_PROFILES];
      res.json({
        success: true,
        message: `Applied ${profile.name}`,
        configPath: getConfigPath(),
      });
    } catch (err) {
      console.error("Apply profile error:", err);
      res.status(500).json({ error: "Error applying profile" });
    }
  });

  // ============================================
  // Configuration Inventory Endpoints
  // ============================================

  // API: Get configuration inventory
  app.get("/api/inventory", async (_req, res) => {
    try {
      const inventory = await scanConfigInventory({
        scanProjects: true,
        projectScanDepth: 4,
      });
      res.json(inventory);
    } catch (err) {
      console.error("Inventory error:", err);
      res.status(500).json({ error: "Error scanning configuration inventory" });
    }
  });

  // API: Get effective config for a project
  // This endpoint does a FULL inventory scan to properly merge global + project configs
  app.get("/api/effective-config", async (req, res) => {
    try {
      const projectPath = (req.query.project as string) || null;

      // Do a full inventory scan to get ALL configs (global + projects)
      // This is necessary to properly compute the effective merged config
      const fullInventory = await scanConfigInventory({
        scanProjects: true,
        projectScanDepth: 4,
      });

      // Compute effective config with proper merging of global + project
      const effectiveConfig = computeEffectiveConfig(
        fullInventory,
        projectPath,
      );
      res.json(effectiveConfig);
    } catch (err) {
      console.error("Effective config error:", err);
      res.status(500).json({ error: "Error computing effective config" });
    }
  });

  // API: Switch scope and rescan
  app.post("/api/switch-scope", async (req, res) => {
    try {
      const { projectPath } = req.body;
      if (projectPath) {
        setConfigScope({ type: "project", projectPath });
      } else {
        setConfigScope({ type: "global" });
      }
      res.json({
        success: true,
        scope: getConfigScope(),
        configPath: getConfigPath().replace(process.env.HOME || "", "~"),
      });
    } catch (err) {
      console.error("Switch scope error:", err);
      res.status(500).json({ error: "Error switching scope" });
    }
  });

  // Start server
  app.listen(port, () => {
    const url = `http://localhost:${port}`;
    console.log(`Claude Defense Kit running at ${url}`);
    console.log("Press Ctrl+C to stop the server\n");
    if (shouldOpenBrowser) {
      openBrowser(url);
    }
  });
}
