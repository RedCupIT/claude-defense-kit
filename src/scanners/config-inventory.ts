/**
 * Configuration Inventory Scanner
 *
 * Discovers and inventories all Claude Code configuration across scopes:
 * - Managed (IT-deployed, highest precedence)
 * - User (~/.claude/)
 * - Project (.claude/ in repositories)
 *
 * This provides the foundation for scope-aware security analysis.
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { execSync } from "child_process";
import type {
  Platform,
  ConfigInventory,
  ManagedConfigScope,
  ManagedSettings,
  ManagedMcpConfig,
  UserConfigScope,
  UserSettings,
  UserMcpConfig,
  ProjectConfigInfo,
  ProjectSettings,
  ProjectMcpConfig,
} from "../types/index.js";

// Platform-specific paths for managed configuration
const MANAGED_CONFIG_PATHS: Record<Platform, string> = {
  darwin: "/Library/Application Support/ClaudeCode",
  linux: "/etc/claude-code",
  win32: "C:\\Program Files\\ClaudeCode",
};

/**
 * Get the current platform
 */
function getPlatform(): Platform {
  const platform = process.platform;
  if (platform === "darwin" || platform === "linux" || platform === "win32") {
    return platform;
  }
  // Default to linux for unknown platforms
  return "linux";
}

/**
 * Safely read and parse a JSON file
 */
function readJsonFile<T>(filePath: string): T | null {
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }
    const content = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(content) as T;
  } catch {
    return null;
  }
}

/**
 * Get file modification time as ISO string
 */
function getModTime(filePath: string): string | null {
  try {
    const stats = fs.statSync(filePath);
    return stats.mtime.toISOString();
  } catch {
    return null;
  }
}

/**
 * Detect Claude Code version by running `claude --version`
 */
function detectClaudeCodeVersion(): string | null {
  try {
    const output = execSync("claude --version 2>/dev/null", {
      encoding: "utf-8",
      timeout: 5000,
    });
    // Parse version from output (e.g., "claude 2.0.62")
    const match = output.match(/claude\s+(\d+\.\d+\.\d+)/i);
    return match ? match[1] : output.trim();
  } catch {
    return null;
  }
}

/**
 * Find Claude Code installation path
 */
function findClaudeCodeInstallPath(): string | null {
  try {
    const output = execSync("which claude 2>/dev/null || where claude 2>nul", {
      encoding: "utf-8",
      timeout: 5000,
    });
    return output.trim() || null;
  } catch {
    return null;
  }
}

/**
 * Scan managed (IT-deployed) configuration
 */
function scanManagedConfig(platform: Platform): ManagedConfigScope {
  const managedPath = MANAGED_CONFIG_PATHS[platform];

  const result: ManagedConfigScope = {
    detected: false,
    path: managedPath,
    settings: null,
    mcpConfig: null,
    enforces: {
      sandboxing: false,
      permissionRestrictions: false,
      mcpRestrictions: false,
      pluginRestrictions: false,
      hookRestrictions: false,
    },
  };

  // Check if managed directory exists
  if (!fs.existsSync(managedPath)) {
    return result;
  }

  result.detected = true;

  // Read managed-settings.json
  const settingsPath = path.join(managedPath, "managed-settings.json");
  const settings = readJsonFile<ManagedSettings>(settingsPath);
  result.settings = settings;

  // Read managed-mcp.json
  const mcpPath = path.join(managedPath, "managed-mcp.json");
  const mcpConfig = readJsonFile<ManagedMcpConfig>(mcpPath);
  result.mcpConfig = mcpConfig;

  // Analyze what the managed config enforces
  if (settings) {
    result.enforces.sandboxing = settings.sandbox?.enabled === true;
    result.enforces.permissionRestrictions =
      (settings.permissions?.deny?.length ?? 0) > 0 ||
      settings.permissions?.disableBypassPermissionsMode === "disable";
    result.enforces.mcpRestrictions =
      (settings.allowedMcpServers?.length ?? 0) > 0 ||
      (settings.deniedMcpServers?.length ?? 0) > 0;
    result.enforces.pluginRestrictions =
      settings.strictKnownMarketplaces !== undefined;
    result.enforces.hookRestrictions =
      settings.allowManagedHooksOnly === true ||
      settings.disableAllHooks === true;
  }

  return result;
}

/**
 * Scan user-level configuration
 */
function scanUserConfig(): UserConfigScope {
  const home = os.homedir();
  const claudeDir = path.join(home, ".claude");

  const result: UserConfigScope = {
    settingsPath: path.join(claudeDir, "settings.json"),
    settings: null,
    mcpPath: path.join(home, ".claude.json"),
    mcpConfig: null,
    agentsPath: path.join(claudeDir, "agents"),
    agentCount: 0,
    claudeMdPath: path.join(claudeDir, "CLAUDE.md"),
    hasClaudeMd: false,
  };

  // Read user settings
  result.settings = readJsonFile<UserSettings>(result.settingsPath);

  // Read user MCP config
  result.mcpConfig = readJsonFile<UserMcpConfig>(result.mcpPath);

  // Count agents
  if (fs.existsSync(result.agentsPath)) {
    try {
      const files = fs.readdirSync(result.agentsPath);
      result.agentCount = files.filter(
        (f) => f.endsWith(".md") || f.endsWith(".yaml") || f.endsWith(".yml")
      ).length;
    } catch {
      // Ignore errors
    }
  }

  // Check for CLAUDE.md
  result.hasClaudeMd = fs.existsSync(result.claudeMdPath);

  return result;
}

/**
 * Scan a single project directory for Claude configuration
 */
function scanProjectConfig(projectPath: string): ProjectConfigInfo | null {
  const claudeDir = path.join(projectPath, ".claude");

  // Must have .claude directory to be considered a Claude project
  if (!fs.existsSync(claudeDir)) {
    return null;
  }

  // Skip home directory - that's the global config, not a project
  const home = os.homedir();
  if (projectPath === home || fs.realpathSync(projectPath) === home) {
    return null;
  }

  const result: ProjectConfigInfo = {
    path: projectPath,
    name: path.basename(projectPath),
    settings: {
      shared: null,
      local: null,
    },
    mcpConfig: null,
    hasClaudeMd: false,
    hasLocalClaudeMd: false,
    lastModified: null,
  };

  // Read shared settings (.claude/settings.json)
  const sharedSettingsPath = path.join(claudeDir, "settings.json");
  result.settings.shared = readJsonFile<ProjectSettings>(sharedSettingsPath);

  // Read local settings (.claude/settings.local.json)
  const localSettingsPath = path.join(claudeDir, "settings.local.json");
  result.settings.local = readJsonFile<ProjectSettings>(localSettingsPath);

  // Read project MCP config (.mcp.json)
  const mcpPath = path.join(projectPath, ".mcp.json");
  result.mcpConfig = readJsonFile<ProjectMcpConfig>(mcpPath);

  // Check for CLAUDE.md (can be at root or in .claude/)
  result.hasClaudeMd =
    fs.existsSync(path.join(projectPath, "CLAUDE.md")) ||
    fs.existsSync(path.join(claudeDir, "CLAUDE.md"));

  // Check for CLAUDE.local.md
  result.hasLocalClaudeMd = fs.existsSync(
    path.join(projectPath, "CLAUDE.local.md")
  );

  // Get last modified time (use most recent of all config files)
  const configFiles = [
    sharedSettingsPath,
    localSettingsPath,
    mcpPath,
    path.join(projectPath, "CLAUDE.md"),
    path.join(claudeDir, "CLAUDE.md"),
  ];

  let latestMod: Date | null = null;
  for (const file of configFiles) {
    const modTime = getModTime(file);
    if (modTime) {
      const date = new Date(modTime);
      if (!latestMod || date > latestMod) {
        latestMod = date;
      }
    }
  }
  result.lastModified = latestMod?.toISOString() ?? null;

  return result;
}

/**
 * Discover all Claude projects starting from a root directory
 * Uses a breadth-first search with depth limiting
 */
function discoverProjects(
  rootPath: string,
  maxDepth: number = 5
): ProjectConfigInfo[] {
  const projects: ProjectConfigInfo[] = [];
  const visited = new Set<string>();

  // Directories to skip
  const skipDirs = new Set([
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "vendor",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".cache",
    "Library", // Skip macOS Library folder
    "Applications",
  ]);

  function scan(dirPath: string, depth: number): void {
    if (depth > maxDepth) return;

    // Resolve to real path to handle symlinks
    let realPath: string;
    try {
      realPath = fs.realpathSync(dirPath);
    } catch {
      return;
    }

    // Skip if already visited
    if (visited.has(realPath)) return;
    visited.add(realPath);

    // Check if this is a Claude project
    const projectConfig = scanProjectConfig(realPath);
    if (projectConfig) {
      projects.push(projectConfig);
    }

    // Scan subdirectories
    try {
      const entries = fs.readdirSync(dirPath, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (entry.name.startsWith(".") && entry.name !== ".claude") continue;
        if (skipDirs.has(entry.name)) continue;

        const subPath = path.join(dirPath, entry.name);
        scan(subPath, depth + 1);
      }
    } catch {
      // Permission denied or other error, skip
    }
  }

  scan(rootPath, 0);
  return projects;
}

/**
 * Main function: Scan and inventory all Claude Code configuration
 */
export async function scanConfigInventory(
  options: {
    scanProjects?: boolean;
    projectScanRoot?: string;
    projectScanDepth?: number;
  } = {}
): Promise<ConfigInventory> {
  const startTime = Date.now();
  const platform = getPlatform();
  const home = os.homedir();

  // Scan managed config
  const managed = scanManagedConfig(platform);

  // Scan user config
  const user = scanUserConfig();

  // Discover projects
  let projects: ProjectConfigInfo[] = [];
  if (options.scanProjects !== false) {
    const scanRoot = options.projectScanRoot ?? home;
    const scanDepth = options.projectScanDepth ?? 4;
    projects = discoverProjects(scanRoot, scanDepth);
  }

  const scanDurationMs = Date.now() - startTime;

  return {
    scannedAt: new Date().toISOString(),
    scanDurationMs,
    platform,
    claudeCodeVersion: detectClaudeCodeVersion(),
    claudeCodeInstallPath: findClaudeCodeInstallPath(),
    managed,
    user,
    projects,
    isITManaged: managed.detected,
    projectCount: projects.length,
    hasUserConfig: user.settings !== null || user.mcpConfig !== null,
  };
}

/**
 * Quick scan: Only scan managed and user config, skip project discovery
 */
export async function scanConfigInventoryQuick(): Promise<ConfigInventory> {
  return scanConfigInventory({ scanProjects: false });
}

/**
 * Get a summary of the configuration inventory for display
 */
export function getInventorySummary(inventory: ConfigInventory): string[] {
  const lines: string[] = [];

  lines.push(`Platform: ${inventory.platform}`);
  lines.push(`Claude Code: ${inventory.claudeCodeVersion ?? "not detected"}`);

  if (inventory.isITManaged) {
    lines.push("");
    lines.push("🏢 IT-MANAGED DEPLOYMENT DETECTED");
    lines.push(`   Path: ${inventory.managed.path}`);
    if (inventory.managed.enforces.sandboxing) {
      lines.push("   ✓ Sandboxing enforced");
    }
    if (inventory.managed.enforces.permissionRestrictions) {
      lines.push("   ✓ Permission restrictions enforced");
    }
    if (inventory.managed.enforces.mcpRestrictions) {
      lines.push("   ✓ MCP server restrictions enforced");
    }
    if (inventory.managed.enforces.pluginRestrictions) {
      lines.push("   ✓ Plugin marketplace restrictions enforced");
    }
    if (inventory.managed.enforces.hookRestrictions) {
      lines.push("   ✓ Hook restrictions enforced");
    }
  }

  lines.push("");
  lines.push("👤 USER CONFIGURATION");
  lines.push(`   Settings: ${inventory.user.settings ? "found" : "none"}`);
  lines.push(`   MCP Config: ${inventory.user.mcpConfig ? "found" : "none"}`);
  lines.push(`   Agents: ${inventory.user.agentCount}`);
  lines.push(`   CLAUDE.md: ${inventory.user.hasClaudeMd ? "yes" : "no"}`);

  if (inventory.projects.length > 0) {
    lines.push("");
    lines.push(`📁 DISCOVERED PROJECTS (${inventory.projects.length})`);
    for (const project of inventory.projects.slice(0, 10)) {
      const hasConfig =
        project.settings.shared || project.settings.local || project.mcpConfig;
      lines.push(`   ${project.path} ${hasConfig ? "✓" : ""}`);
    }
    if (inventory.projects.length > 10) {
      lines.push(`   ... and ${inventory.projects.length - 10} more`);
    }
  }

  lines.push("");
  lines.push(`Scan completed in ${inventory.scanDurationMs}ms`);

  return lines;
}
