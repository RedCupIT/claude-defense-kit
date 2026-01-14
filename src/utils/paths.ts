import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

// Get user's home directory cross-platform
export function getHomeDir(): string {
  return os.homedir();
}

// Expand ~ to home directory
export function expandPath(p: string): string {
  if (p.startsWith('~/') || p === '~') {
    return path.join(getHomeDir(), p.slice(2));
  }
  return p;
}

// Normalize path for display (replace home dir with ~)
export function displayPath(p: string): string {
  const home = getHomeDir();
  if (p.startsWith(home)) {
    return '~' + p.slice(home.length);
  }
  return p;
}

// Check if a path exists
export function pathExists(p: string): boolean {
  try {
    fs.accessSync(expandPath(p));
    return true;
  } catch {
    return false;
  }
}

// Check if path is a directory
export function isDirectory(p: string): boolean {
  try {
    return fs.statSync(expandPath(p)).isDirectory();
  } catch {
    return false;
  }
}

// Check if path is a file
export function isFile(p: string): boolean {
  try {
    return fs.statSync(expandPath(p)).isFile();
  } catch {
    return false;
  }
}

// Read JSON file safely
export function readJsonFile<T>(p: string): T | null {
  try {
    const content = fs.readFileSync(expandPath(p), 'utf-8');
    return JSON.parse(content) as T;
  } catch {
    return null;
  }
}

// List files in directory
export function listDir(p: string): string[] {
  try {
    return fs.readdirSync(expandPath(p));
  } catch {
    return [];
  }
}

// Get common config directories for Claude Code
export function getClaudeConfigPaths(): string[] {
  const home = getHomeDir();
  const paths: string[] = [];

  // Primary Claude config location
  paths.push(path.join(home, '.claude'));

  // XDG config on Linux/macOS
  const xdgConfig = process.env.XDG_CONFIG_HOME ||
    path.join(home, '.config');
  paths.push(path.join(xdgConfig, 'claude'));

  // macOS Application Support
  if (process.platform === 'darwin') {
    paths.push(path.join(home, 'Library', 'Application Support', 'Claude'));
  }

  // Windows AppData
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA;
    if (appData) {
      paths.push(path.join(appData, 'Claude'));
    }
  }

  return paths;
}

// Get potential sensitive directories
export function getSensitiveDirectories(): string[] {
  const home = getHomeDir();
  return [
    path.join(home, '.ssh'),
    path.join(home, '.aws'),
    path.join(home, '.config', 'gcloud'),
    path.join(home, '.azure'),
    path.join(home, '.gnupg'),
    path.join(home, '.kube'),
    path.join(home, '.docker'),
  ];
}
