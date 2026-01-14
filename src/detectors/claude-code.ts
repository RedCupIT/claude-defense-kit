import * as path from 'path';
import * as fs from 'fs';
import { execSync } from 'child_process';
import {
  getClaudeConfigPaths,
  pathExists,
  readJsonFile,
  isFile,
  getHomeDir,
} from '../utils/paths.js';
import type { AgentInfo, ClaudeCodeConfig, ToolPermissions, ConfigFileInfo } from '../types/index.js';
import { CONFIG_FILE_EDUCATION } from '../data/educational.js';

// Paths to check for Claude Code configuration
const CONFIG_FILES = [
  'settings.json',
  'claude_desktop_config.json',
  'config.json',
];

// Claude Code specific files
const CLAUDE_CODE_MARKERS = [
  '.claude',
  '.claude.json',
  'projects.json',
  'settings.local.json',
];

export async function detectClaudeCode(): Promise<AgentInfo> {
  const result: AgentInfo = {
    name: 'Claude Code',
    detected: false,
  };

  // Try to detect Claude Code CLI version
  try {
    const versionOutput = execSync('claude --version 2>/dev/null', {
      encoding: 'utf-8',
      timeout: 5000,
    }).trim();

    if (versionOutput) {
      result.detected = true;
      // Parse version from output (e.g., "claude-code 1.0.12")
      const versionMatch = versionOutput.match(/[\d.]+/);
      if (versionMatch) {
        result.version = versionMatch[0];
      }
    }
  } catch {
    // CLI not found or errored, continue checking config files
  }

  // Check for config directories
  const configPaths = getClaudeConfigPaths();

  for (const configPath of configPaths) {
    if (pathExists(configPath)) {
      result.detected = true;
      result.configPath = configPath;
      break;
    }
  }

  // Check for config files in home directory
  const home = getHomeDir();
  for (const marker of CLAUDE_CODE_MARKERS) {
    const markerPath = path.join(home, marker);
    if (pathExists(markerPath)) {
      result.detected = true;
      if (!result.configPath) {
        result.configPath = isFile(markerPath) ? home : markerPath;
      }
      break;
    }
  }

  // Get tool permissions and config files
  if (result.detected) {
    const perms = getToolPermissions();
    result.permissions = {
      allowed: perms.allowed,
      denied: perms.denied,
      hasExplicitConfig: perms.allowed.length > 0 || perms.denied.length > 0,
    };
    result.configFiles = getScannedConfigFiles();
  }

  return result;
}

// Get the Claude Code configuration
export function getClaudeCodeConfig(): ClaudeCodeConfig | null {
  const configPaths = getClaudeConfigPaths();
  const home = getHomeDir();

  // Also check home directory
  configPaths.unshift(home);

  for (const basePath of configPaths) {
    // Check for .claude.json in home
    const dotClaudeJson = path.join(basePath, '.claude.json');
    if (isFile(dotClaudeJson)) {
      const config = readJsonFile<ClaudeCodeConfig>(dotClaudeJson);
      if (config) return config;
    }

    // Check standard config files
    for (const configFile of CONFIG_FILES) {
      const configPath = path.join(basePath, configFile);
      if (isFile(configPath)) {
        const config = readJsonFile<ClaudeCodeConfig>(configPath);
        if (config) return config;
      }
    }

    // Check for Claude desktop config location
    const desktopConfig = path.join(basePath, 'claude_desktop_config.json');
    if (isFile(desktopConfig)) {
      const config = readJsonFile<ClaudeCodeConfig>(desktopConfig);
      if (config) return config;
    }
  }

  // macOS Claude desktop location
  if (process.platform === 'darwin') {
    const appSupportPath = path.join(
      home,
      'Library',
      'Application Support',
      'Claude',
      'claude_desktop_config.json'
    );
    if (isFile(appSupportPath)) {
      const config = readJsonFile<ClaudeCodeConfig>(appSupportPath);
      if (config) return config;
    }
  }

  return null;
}

// Get all MCP server configurations from Claude Code
export function getMcpServerConfigs(): Record<string, {
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
}> {
  const config = getClaudeCodeConfig();
  if (!config?.mcpServers) {
    return {};
  }
  return config.mcpServers;
}

// Get allowed/denied tools configuration
export function getToolPermissions(): {
  allowed: string[];
  denied: string[];
} {
  const config = getClaudeCodeConfig();
  const result = {
    allowed: [] as string[],
    denied: [] as string[],
  };

  if (config?.allowedTools) {
    result.allowed = config.allowedTools;
  }

  if (config?.disallowedTools) {
    result.denied = config.disallowedTools;
  }

  if (config?.permissions?.allow) {
    result.allowed.push(...config.permissions.allow);
  }

  if (config?.permissions?.deny) {
    result.denied.push(...config.permissions.deny);
  }

  return result;
}

// Check if Claude Code has unrestricted file access
export function hasUnrestrictedFileAccess(): boolean {
  const permissions = getToolPermissions();

  // If nothing is explicitly denied, assume broad access
  if (permissions.denied.length === 0) {
    return true;
  }

  return false;
}

// Get list of config files that were scanned with educational content
export function getScannedConfigFiles(): ConfigFileInfo[] {
  const configFiles: ConfigFileInfo[] = [];
  const home = getHomeDir();
  const configPaths = getClaudeConfigPaths();

  // Helper to get education for a file
  const getEducation = (filename: string) => {
    const edu = CONFIG_FILE_EDUCATION[filename];
    if (edu) {
      return {
        purpose: edu.purpose,
        whatItControls: edu.whatItControls,
        risk: edu.risk,
      };
    }
    return {
      purpose: 'Configuration file',
      whatItControls: ['Claude Code settings'],
      risk: 'May contain configuration affecting agent capabilities',
    };
  };

  // Check main config directory (~/.claude)
  const claudeDir = path.join(home, '.claude');
  const claudeDirEdu = getEducation('.claude');
  configFiles.push({
    path: '~/.claude',
    exists: pathExists(claudeDir),
    ...claudeDirEdu,
  });

  // Check settings.json in ~/.claude
  const settingsPath = path.join(claudeDir, 'settings.json');
  const settingsEdu = getEducation('settings.json');
  configFiles.push({
    path: '~/.claude/settings.json',
    exists: isFile(settingsPath),
    ...settingsEdu,
  });

  // Check settings.local.json
  const localSettingsPath = path.join(claudeDir, 'settings.local.json');
  const localSettingsEdu = getEducation('settings.local.json');
  configFiles.push({
    path: '~/.claude/settings.local.json',
    exists: isFile(localSettingsPath),
    ...localSettingsEdu,
  });

  // Check projects.json
  const projectsPath = path.join(claudeDir, 'projects.json');
  const projectsEdu = getEducation('projects.json');
  configFiles.push({
    path: '~/.claude/projects.json',
    exists: isFile(projectsPath),
    ...projectsEdu,
  });

  // Check .claude.json in home
  const dotClaudeJson = path.join(home, '.claude.json');
  const dotClaudeEdu = getEducation('.claude.json');
  configFiles.push({
    path: '~/.claude.json',
    exists: isFile(dotClaudeJson),
    ...dotClaudeEdu,
  });

  // Check XDG config location
  const xdgConfig = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
  const xdgClaudeDir = path.join(xdgConfig, 'claude');
  const xdgSettingsPath = path.join(xdgClaudeDir, 'settings.json');
  configFiles.push({
    path: '~/.config/claude/settings.json',
    exists: isFile(xdgSettingsPath),
    purpose: 'XDG config location (Linux)',
    whatItControls: ['Same as ~/.claude/settings.json', 'Alternative location on Linux systems'],
    risk: 'May be used instead of ~/.claude on some systems',
  });

  // Check macOS Application Support
  if (process.platform === 'darwin') {
    const appSupportPath = path.join(
      home,
      'Library',
      'Application Support',
      'Claude',
      'claude_desktop_config.json'
    );
    const desktopEdu = getEducation('claude_desktop_config.json');
    configFiles.push({
      path: '~/Library/Application Support/Claude/claude_desktop_config.json',
      exists: isFile(appSupportPath),
      ...desktopEdu,
    });
  }

  // Check Windows AppData
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA;
    if (appData) {
      const windowsConfigPath = path.join(appData, 'Claude', 'claude_desktop_config.json');
      const desktopEdu = getEducation('claude_desktop_config.json');
      configFiles.push({
        path: '%APPDATA%\\Claude\\claude_desktop_config.json',
        exists: isFile(windowsConfigPath),
        ...desktopEdu,
      });
    }
  }

  return configFiles;
}
