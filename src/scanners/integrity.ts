import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { getHomeDir } from '../utils/paths.js';
import type { McpServer, McpIntegrityResult, ClaudeInstallationIntegrity } from '../types/index.js';

const SCRIPT_INTERPRETERS = [
  'node', 'python', 'python3', 'ruby', 'perl',
  'bash', 'sh', 'deno', 'bun'
];

const BASELINE_PATH = path.join(
  getHomeDir(),
  '.claude',
  'security-audit',
  'hashes.json'
);

interface HashBaseline {
  version: 1;
  servers: Record<string, {
    targetPath: string;
    hash: string;
    recordedAt: string;
  }>;
  claudeCode?: {
    hash: string;
    version: string | null;
    recordedAt: string;
  };
}

// Resolve what file to hash for an MCP server
function resolveHashTarget(server: McpServer): string | null {
  if (!server.command) return null;

  const cmd = path.basename(server.command);
  const args = server.args || [];

  // Check if it's a script interpreter
  if (SCRIPT_INTERPRETERS.includes(cmd)) {
    // First arg is the script
    const scriptArg = args[0];
    if (!scriptArg) return null;

    // Resolve relative to CWD (where scan runs)
    return path.isAbsolute(scriptArg)
      ? scriptArg
      : path.resolve(process.cwd(), scriptArg);
  }

  // npx/bunx/uvx - harder to resolve, skip for now
  if (cmd === 'npx' || cmd === 'bunx' || cmd === 'uvx') {
    return null; // TODO: resolve package entry point
  }

  // Direct executable - hash the command itself
  if (path.isAbsolute(server.command)) {
    return server.command;
  }

  return null;
}

// Compute SHA-256 of a file
function hashFile(filePath: string): string | null {
  try {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  } catch {
    return null;
  }
}

// Load baseline from disk
function loadBaseline(): HashBaseline {
  try {
    const content = fs.readFileSync(BASELINE_PATH, 'utf-8');
    return JSON.parse(content);
  } catch {
    return { version: 1, servers: {} };
  }
}

// Save baseline to disk
function saveBaseline(baseline: HashBaseline): void {
  const dir = path.dirname(BASELINE_PATH);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2));
}

// Main scanner function
export async function scanMcpIntegrity(
  servers: McpServer[]
): Promise<McpIntegrityResult[]> {
  const baseline = loadBaseline();
  const results: McpIntegrityResult[] = [];
  let baselineUpdated = false;

  for (const server of servers) {
    const targetPath = resolveHashTarget(server);

    if (!targetPath) {
      results.push({
        serverName: server.name,
        targetPath: null,
        currentHash: null,
        baselineHash: null,
        status: 'unhashable',
        recordedAt: null,
      });
      continue;
    }

    const currentHash = hashFile(targetPath);
    const baselineEntry = baseline.servers[server.name];

    if (!currentHash) {
      results.push({
        serverName: server.name,
        targetPath,
        currentHash: null,
        baselineHash: baselineEntry?.hash || null,
        status: 'missing',
        recordedAt: baselineEntry?.recordedAt || null,
      });
      continue;
    }

    if (!baselineEntry) {
      // New server - record baseline
      baseline.servers[server.name] = {
        targetPath,
        hash: currentHash,
        recordedAt: new Date().toISOString(),
      };
      baselineUpdated = true;

      results.push({
        serverName: server.name,
        targetPath,
        currentHash,
        baselineHash: null,
        status: 'new',
        recordedAt: baseline.servers[server.name].recordedAt,
      });
    } else if (baselineEntry.hash === currentHash) {
      results.push({
        serverName: server.name,
        targetPath,
        currentHash,
        baselineHash: baselineEntry.hash,
        status: 'unchanged',
        recordedAt: baselineEntry.recordedAt,
      });
    } else {
      results.push({
        serverName: server.name,
        targetPath,
        currentHash,
        baselineHash: baselineEntry.hash,
        status: 'changed',
        recordedAt: baselineEntry.recordedAt,
      });
    }
  }

  if (baselineUpdated) {
    saveBaseline(baseline);
  }

  return results;
}

// Reset baseline (for "accept current state" action)
export function resetBaseline(serverName?: string): void {
  if (serverName) {
    const baseline = loadBaseline();
    delete baseline.servers[serverName];
    saveBaseline(baseline);
  } else {
    saveBaseline({ version: 1, servers: {} });
  }
}

// Accept current hash as new baseline
export function acceptCurrentHash(
  serverName: string,
  targetPath: string,
  hash: string
): void {
  const baseline = loadBaseline();
  baseline.servers[serverName] = {
    targetPath,
    hash,
    recordedAt: new Date().toISOString(),
  };
  saveBaseline(baseline);
}

// Get the baseline file path for display
export function getBaselinePath(): string {
  return BASELINE_PATH;
}

// Find Claude Code installation path and version
function findClaudeInstallation(): { path: string | null; version: string | null } {
  try {
    // Get path from 'which claude'
    const claudePath = execSync('which claude', { encoding: 'utf-8' }).trim();
    if (!claudePath) {
      return { path: null, version: null };
    }

    // Resolve symlink to get actual file
    const resolved = fs.realpathSync(claudePath);
    const pkgDir = path.dirname(resolved);

    // Read version from package.json
    let version: string | null = null;
    try {
      const pkgJsonPath = path.join(pkgDir, 'package.json');
      const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      version = pkgJson.version || null;
    } catch {
      // package.json not found or unreadable
    }

    return { path: resolved, version };
  } catch {
    return { path: null, version: null };
  }
}

// Scan Claude Code installation for integrity
export async function scanClaudeInstallation(): Promise<ClaudeInstallationIntegrity> {
  const installation = findClaudeInstallation();

  if (!installation.path) {
    return {
      installPath: null,
      version: null,
      cliHash: null,
      baselineHash: null,
      status: 'not-found',
      recordedAt: null,
    };
  }

  const currentHash = hashFile(installation.path);
  const baseline = loadBaseline();
  const baselineEntry = baseline.claudeCode;

  let status: 'new' | 'unchanged' | 'changed';
  let recordedAt: string | null = null;

  if (!baselineEntry) {
    // Record new baseline
    baseline.claudeCode = {
      hash: currentHash!,
      version: installation.version,
      recordedAt: new Date().toISOString(),
    };
    saveBaseline(baseline);
    status = 'new';
    recordedAt = baseline.claudeCode.recordedAt;
  } else if (baselineEntry.hash === currentHash) {
    status = 'unchanged';
    recordedAt = baselineEntry.recordedAt;
  } else {
    status = 'changed';
    recordedAt = baselineEntry.recordedAt;
  }

  return {
    installPath: installation.path,
    version: installation.version,
    cliHash: currentHash,
    baselineHash: baselineEntry?.hash || null,
    status,
    recordedAt,
  };
}

// Accept current Claude installation hash as new baseline
export function acceptClaudeInstallationHash(hash: string, version: string | null): void {
  const baseline = loadBaseline();
  baseline.claudeCode = {
    hash,
    version,
    recordedAt: new Date().toISOString(),
  };
  saveBaseline(baseline);
}
