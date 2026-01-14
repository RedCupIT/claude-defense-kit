import * as fs from "fs";
import * as path from "path";
import { getHomeDir } from "../utils/paths.js";
import type { ClaudeCodeConfig, ConfigScope } from "../types/index.js";

// Current config scope (can be set by server/CLI)
let currentScope: ConfigScope = { type: "global" };

// Set the current config scope
export function setConfigScope(scope: ConfigScope): void {
  currentScope = scope;
}

// Get the current config scope
export function getConfigScope(): ConfigScope {
  return currentScope;
}

// Primary config file location (respects current scope)
function getSettingsPath(): string {
  if (currentScope.type === "project" && currentScope.projectPath) {
    return path.join(currentScope.projectPath, ".claude", "settings.json");
  }
  return path.join(getHomeDir(), ".claude", "settings.json");
}

function getBackupPath(): string {
  if (currentScope.type === "project" && currentScope.projectPath) {
    return path.join(
      currentScope.projectPath,
      ".claude",
      "settings.json.backup"
    );
  }
  return path.join(getHomeDir(), ".claude", "settings.json.backup");
}

// Ensure .claude directory exists (respects current scope)
function ensureClaudeDir(): void {
  let claudeDir: string;
  if (currentScope.type === "project" && currentScope.projectPath) {
    claudeDir = path.join(currentScope.projectPath, ".claude");
  } else {
    claudeDir = path.join(getHomeDir(), ".claude");
  }
  if (!fs.existsSync(claudeDir)) {
    fs.mkdirSync(claudeDir, { recursive: true });
  }
}

// Check if config file exists at current scope
export function configExists(): boolean {
  return fs.existsSync(getSettingsPath());
}

// Read the current config
export function readClaudeConfig(): ClaudeCodeConfig {
  const settingsPath = getSettingsPath();

  if (!fs.existsSync(settingsPath)) {
    return {};
  }

  try {
    const content = fs.readFileSync(settingsPath, "utf-8");
    return JSON.parse(content) as ClaudeCodeConfig;
  } catch {
    return {};
  }
}

// Create a backup of the current config
function createBackup(): void {
  const settingsPath = getSettingsPath();
  const backupPath = getBackupPath();

  if (fs.existsSync(settingsPath)) {
    fs.copyFileSync(settingsPath, backupPath);
  }
}

// Write config with automatic backup
export function writeClaudeConfig(config: ClaudeCodeConfig): void {
  ensureClaudeDir();
  createBackup();

  const settingsPath = getSettingsPath();
  const content = JSON.stringify(config, null, 2);
  fs.writeFileSync(settingsPath, content, "utf-8");
}

// Revert to the backup
export function revertConfig(): boolean {
  const settingsPath = getSettingsPath();
  const backupPath = getBackupPath();

  if (!fs.existsSync(backupPath)) {
    return false;
  }

  fs.copyFileSync(backupPath, settingsPath);
  return true;
}

// Get the diff that would be applied for a deny path operation
export function getDenyPathDiff(pattern: string): {
  before: string;
  after: string;
} {
  const config = readClaudeConfig();
  const beforeConfig = JSON.parse(JSON.stringify(config));

  // Apply the change
  if (!config.permissions) {
    config.permissions = {};
  }
  if (!config.permissions.deny) {
    config.permissions.deny = [];
  }

  const denyPattern = `Read(${pattern})`;
  if (!config.permissions.deny.includes(denyPattern)) {
    config.permissions.deny.push(denyPattern);
  }

  return {
    before: JSON.stringify(beforeConfig, null, 2),
    after: JSON.stringify(config, null, 2),
  };
}

// Add a path to the deny list
export function denyPath(pattern: string): void {
  const config = readClaudeConfig();

  if (!config.permissions) {
    config.permissions = {};
  }
  if (!config.permissions.deny) {
    config.permissions.deny = [];
  }

  // Format: Read(~/path/*) to deny read access
  const denyPattern = `Read(${pattern})`;

  if (!config.permissions.deny.includes(denyPattern)) {
    config.permissions.deny.push(denyPattern);
    writeClaudeConfig(config);
  }
}

// Get the diff for disabling an MCP server
export function getDisableMcpDiff(serverName: string): {
  before: string;
  after: string;
} {
  const config = readClaudeConfig();
  const beforeConfig = JSON.parse(JSON.stringify(config));

  if (config.mcpServers && config.mcpServers[serverName]) {
    delete config.mcpServers[serverName];
  }

  return {
    before: JSON.stringify(beforeConfig, null, 2),
    after: JSON.stringify(config, null, 2),
  };
}

// Remove an MCP server from the config
export function disableMcpServer(serverName: string): void {
  const config = readClaudeConfig();

  if (config.mcpServers && config.mcpServers[serverName]) {
    delete config.mcpServers[serverName];
    writeClaudeConfig(config);
  }
}

// Get the diff for denying a tool
export function getDenyToolDiff(toolName: string): {
  before: string;
  after: string;
} {
  const config = readClaudeConfig();
  const beforeConfig = JSON.parse(JSON.stringify(config));

  if (!config.disallowedTools) {
    config.disallowedTools = [];
  }

  if (!config.disallowedTools.includes(toolName)) {
    config.disallowedTools.push(toolName);
  }

  return {
    before: JSON.stringify(beforeConfig, null, 2),
    after: JSON.stringify(config, null, 2),
  };
}

// Add a tool to the disallowed list
export function denyTool(toolName: string): void {
  const config = readClaudeConfig();

  if (!config.disallowedTools) {
    config.disallowedTools = [];
  }

  if (!config.disallowedTools.includes(toolName)) {
    config.disallowedTools.push(toolName);
    writeClaudeConfig(config);
  }
}

// Get the diff for enabling a tool (removing from disallowed list)
export function getEnableToolDiff(toolName: string): {
  before: string;
  after: string;
} {
  const config = readClaudeConfig();
  const beforeConfig = JSON.parse(JSON.stringify(config));

  if (config.disallowedTools) {
    const index = config.disallowedTools.indexOf(toolName);
    if (index > -1) {
      config.disallowedTools.splice(index, 1);
    }
  }

  return {
    before: JSON.stringify(beforeConfig, null, 2),
    after: JSON.stringify(config, null, 2),
  };
}

// Remove a tool from the disallowed list (enable it)
export function enableTool(toolName: string): void {
  const config = readClaudeConfig();

  if (config.disallowedTools) {
    const index = config.disallowedTools.indexOf(toolName);
    if (index > -1) {
      config.disallowedTools.splice(index, 1);
      writeClaudeConfig(config);
    }
  }
}

// Check if a backup exists
export function hasBackup(): boolean {
  return fs.existsSync(getBackupPath());
}

// Get the config file path for display
export function getConfigPath(): string {
  return getSettingsPath();
}

// Get the diff for denying a bash command pattern
export function getDenyBashDiff(pattern: string): {
  before: string;
  after: string;
} {
  const config = readClaudeConfig();
  const beforeConfig = JSON.parse(JSON.stringify(config));

  if (!config.permissions) {
    config.permissions = {};
  }
  if (!config.permissions.deny) {
    config.permissions.deny = [];
  }

  if (!config.permissions.deny.includes(pattern)) {
    config.permissions.deny.push(pattern);
  }

  return {
    before: JSON.stringify(beforeConfig, null, 2),
    after: JSON.stringify(config, null, 2),
  };
}

// Add a bash command pattern to the deny list
export function denyBashCommand(pattern: string): void {
  const config = readClaudeConfig();

  if (!config.permissions) {
    config.permissions = {};
  }
  if (!config.permissions.deny) {
    config.permissions.deny = [];
  }

  if (!config.permissions.deny.includes(pattern)) {
    config.permissions.deny.push(pattern);
    writeClaudeConfig(config);
  }
}

// Get the diff for a sandbox config change
export function getSandboxDiff(
  path: string,
  value: boolean | string[] | number
): { before: string; after: string } {
  const config = readClaudeConfig();
  const beforeConfig = JSON.parse(JSON.stringify(config));

  if (!config.sandbox) {
    config.sandbox = {};
  }

  // Handle nested paths like "network.allowLocalBinding"
  const parts = path.split(".");
  if (parts.length === 1) {
    (config.sandbox as Record<string, unknown>)[path] = value;
  } else if (parts.length === 2 && parts[0] === "network") {
    if (!config.sandbox.network) {
      config.sandbox.network = {};
    }
    (config.sandbox.network as Record<string, unknown>)[parts[1]] = value;
  }

  return {
    before: JSON.stringify(beforeConfig, null, 2),
    after: JSON.stringify(config, null, 2),
  };
}

// Update a sandbox config setting
export function updateSandboxConfig(
  path: string,
  value: boolean | string[] | number
): void {
  const config = readClaudeConfig();

  if (!config.sandbox) {
    config.sandbox = {};
  }

  const parts = path.split(".");
  if (parts.length === 1) {
    (config.sandbox as Record<string, unknown>)[path] = value;
  } else if (parts.length === 2 && parts[0] === "network") {
    if (!config.sandbox.network) {
      config.sandbox.network = {};
    }
    (config.sandbox.network as Record<string, unknown>)[parts[1]] = value;
  }

  writeClaudeConfig(config);
}

// ============================================
// Directory Access Control Functions
// ============================================

// Get the diff for allowing a directory
export function getAllowDirectoryDiff(directory: string): {
  before: string;
  after: string;
} {
  const config = readClaudeConfig();
  const beforeConfig = JSON.parse(JSON.stringify(config));

  if (!config.permissions) {
    config.permissions = {};
  }
  if (!config.permissions.allow) {
    config.permissions.allow = [];
  }

  const allowPattern = `Read(${directory}/**)`;
  if (!config.permissions.allow.includes(allowPattern)) {
    config.permissions.allow.push(allowPattern);
  }

  return {
    before: JSON.stringify(beforeConfig, null, 2),
    after: JSON.stringify(config, null, 2),
  };
}

// Add a directory to the allow list
export function allowDirectory(directory: string): void {
  const config = readClaudeConfig();

  if (!config.permissions) {
    config.permissions = {};
  }
  if (!config.permissions.allow) {
    config.permissions.allow = [];
  }

  const allowPattern = `Read(${directory}/**)`;
  if (!config.permissions.allow.includes(allowPattern)) {
    config.permissions.allow.push(allowPattern);
    writeClaudeConfig(config);
  }
}

// Get the diff for denying a directory
export function getDenyDirectoryDiff(directory: string): {
  before: string;
  after: string;
} {
  const config = readClaudeConfig();
  const beforeConfig = JSON.parse(JSON.stringify(config));

  if (!config.permissions) {
    config.permissions = {};
  }
  if (!config.permissions.deny) {
    config.permissions.deny = [];
  }

  const denyPattern = `Read(${directory}/**)`;
  if (!config.permissions.deny.includes(denyPattern)) {
    config.permissions.deny.push(denyPattern);
  }

  return {
    before: JSON.stringify(beforeConfig, null, 2),
    after: JSON.stringify(config, null, 2),
  };
}

// Add a directory to the deny list
export function denyDirectory(directory: string): void {
  const config = readClaudeConfig();

  if (!config.permissions) {
    config.permissions = {};
  }
  if (!config.permissions.deny) {
    config.permissions.deny = [];
  }

  const denyPattern = `Read(${directory}/**)`;
  if (!config.permissions.deny.includes(denyPattern)) {
    config.permissions.deny.push(denyPattern);
    writeClaudeConfig(config);
  }
}

// Get the diff for removing a permission rule
export function getRemovePermissionDiff(
  rule: string,
  type: "allow" | "deny"
): { before: string; after: string } {
  const config = readClaudeConfig();
  const beforeConfig = JSON.parse(JSON.stringify(config));

  if (config.permissions && config.permissions[type]) {
    const index = config.permissions[type]!.indexOf(rule);
    if (index > -1) {
      config.permissions[type]!.splice(index, 1);
    }
  }

  return {
    before: JSON.stringify(beforeConfig, null, 2),
    after: JSON.stringify(config, null, 2),
  };
}

// Remove a permission rule
export function removePermission(rule: string, type: "allow" | "deny"): void {
  const config = readClaudeConfig();

  if (config.permissions && config.permissions[type]) {
    const index = config.permissions[type]!.indexOf(rule);
    if (index > -1) {
      config.permissions[type]!.splice(index, 1);
      writeClaudeConfig(config);
    }
  }
}

// Get all current permissions
export function getPermissions(): { allow: string[]; deny: string[] } {
  const config = readClaudeConfig();
  return {
    allow: config.permissions?.allow || [],
    deny: config.permissions?.deny || [],
  };
}

// Pre-built security profiles
export const SECURITY_PROFILES = {
  paranoid: {
    name: "Paranoid Mode",
    description: "Maximum restrictions - explicit allowlist only",
    disallowedTools: ["Bash", "Write", "Edit", "WebFetch"],
    permissions: {
      deny: [
        "Read(~/.ssh/**)",
        "Read(~/.aws/**)",
        "Read(~/.gnupg/**)",
        "Read(~/.kube/**)",
        "Read(~/.docker/**)",
        "Read(**/.env)",
        "Read(**/.env.*)",
        "Read(**/credentials*)",
        "Read(**/*secret*)",
        "Read(**/*token*)",
        "Read(**/*password*)",
      ],
      allow: [],
    },
    sandbox: {
      enabled: true,
      allowUnsandboxedCommands: false,
    },
  },
  developer: {
    name: "Developer Mode",
    description: "Balanced for productivity - blocks sensitive directories",
    disallowedTools: [],
    permissions: {
      deny: [
        "Read(~/.ssh/**)",
        "Read(~/.aws/**)",
        "Read(~/.gnupg/**)",
        "Read(**/.env)",
      ],
      allow: [],
    },
    sandbox: {
      enabled: false,
    },
  },
  readonly: {
    name: "Read-Only Mode",
    description: "No write/edit/bash - safe for code review",
    disallowedTools: ["Bash", "Write", "Edit"],
    permissions: {
      deny: ["Read(~/.ssh/**)", "Read(~/.aws/**)"],
      allow: [],
    },
    sandbox: {
      enabled: false,
    },
  },
};

// Get the diff for applying a security profile
export function getApplyProfileDiff(
  profileName: keyof typeof SECURITY_PROFILES
): { before: string; after: string } {
  const config = readClaudeConfig();
  const beforeConfig = JSON.parse(JSON.stringify(config));
  const profile = SECURITY_PROFILES[profileName];

  // Apply profile settings
  config.disallowedTools = profile.disallowedTools;
  config.permissions = {
    ...config.permissions,
    deny: [
      ...new Set([
        ...(config.permissions?.deny || []),
        ...profile.permissions.deny,
      ]),
    ],
  };
  if (profile.sandbox) {
    config.sandbox = { ...config.sandbox, ...profile.sandbox };
  }

  return {
    before: JSON.stringify(beforeConfig, null, 2),
    after: JSON.stringify(config, null, 2),
  };
}

// Apply a security profile
export function applySecurityProfile(
  profileName: keyof typeof SECURITY_PROFILES
): void {
  const config = readClaudeConfig();
  const profile = SECURITY_PROFILES[profileName];

  config.disallowedTools = profile.disallowedTools;
  config.permissions = {
    ...config.permissions,
    deny: [
      ...new Set([
        ...(config.permissions?.deny || []),
        ...profile.permissions.deny,
      ]),
    ],
  };
  if (profile.sandbox) {
    config.sandbox = { ...config.sandbox, ...profile.sandbox };
  }

  writeClaudeConfig(config);
}
