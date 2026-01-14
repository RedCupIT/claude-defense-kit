import type {
  ScanResults,
  SecurityIssue,
  McpServer,
  SensitiveFile,
  RiskLevel,
  SimpleRisk,
  SeverityProgress,
  ClaudeCodeConfig,
} from '../types/index.js';
import { readClaudeConfig } from '../config/writer.js';

// Map 4-tier risk to 3-tier
function mapRisk(risk: RiskLevel): SimpleRisk {
  if (risk === 'critical' || risk === 'high') {
    return 'high';
  }
  return risk as SimpleRisk;
}

// Check if a path pattern is already denied in the config
function isPathAlreadyDenied(pattern: string, config: ClaudeCodeConfig): boolean {
  if (!config.permissions?.deny) return false;

  const denyPattern = `Read(${pattern})`;
  return config.permissions.deny.some(entry => {
    // Exact match
    if (entry === denyPattern) return true;
    // Check if an existing deny pattern covers this one
    // e.g., Read(~/.aws/*) covers ~/.aws/credentials
    const entryPath = entry.match(/^Read\((.+)\)$/)?.[1];
    if (!entryPath) return false;
    // Wildcard match: ~/.aws/* covers ~/.aws/credentials
    if (entryPath.endsWith('/*')) {
      const base = entryPath.slice(0, -2);
      return pattern.startsWith(base);
    }
    return false;
  });
}

// Check if an MCP server has been disabled (removed from config)
// Note: If the server isn't in mcpServers, it's been disabled
function isMcpServerDisabled(serverName: string, config: ClaudeCodeConfig): boolean {
  // Servers are detected from the config, so if it's in the scan results
  // it exists. We check if it's been removed since the scan.
  // For now, just return false since we can't easily detect this at scan time.
  return false;
}

// Severity order for sorting (high first)
const SEVERITY_ORDER: Record<SimpleRisk, number> = {
  high: 0,
  medium: 1,
  low: 2,
};

function getDenyPattern(filePath: string): string {
  // For files in sensitive directories, deny the whole directory
  const sensitiveRoots = [
    '~/.ssh',
    '~/.aws',
    '~/.gnupg',
    '~/.kube',
    '~/.docker',
    '~/.config/gcloud',
    '~/.azure',
  ];

  for (const root of sensitiveRoots) {
    if (filePath.startsWith(root)) {
      return root + '/*';
    }
  }

  return filePath;
}

function hashPath(path: string): string {
  // Simple hash for creating unique IDs
  let hash = 0;
  for (let i = 0; i < path.length; i++) {
    const char = path.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(36);
}

function getServerCommand(server: McpServer): string | undefined {
  if (server.command) {
    const args = server.args?.join(' ') || '';
    return args ? `${server.command} ${args}` : server.command;
  }
  if (server.url) {
    return server.url;
  }
  return undefined;
}

export function generateSecurityIssues(results: ScanResults): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  const seenDenyPatterns = new Set<string>();

  // Read current config to check what's already fixed
  const config = readClaudeConfig();

  // From MCP servers (these are already filtered by the scanner - if they're
  // in results, they exist in the config)
  for (const server of results.mcpServers) {
    issues.push({
      id: `mcp-${server.name.replace(/[^a-zA-Z0-9]/g, '-')}`,
      category: 'mcp-servers',
      type: 'mcp-server',
      title: server.name,
      description: server.riskReason || `MCP server with ${server.risk} risk`,
      target: server.name,
      command: getServerCommand(server),
      risk: mapRisk(server.risk),
      action: {
        type: 'disable-mcp',
        target: server.name,
      },
    });
  }

  // From sensitive files (deduplicate by deny pattern)
  for (const file of results.filesystem.sensitiveFiles) {
    const denyPattern = getDenyPattern(file.path);

    // Skip if we already have an issue for this deny pattern
    if (seenDenyPatterns.has(denyPattern)) {
      continue;
    }

    // Skip if this path is already denied in the config
    if (isPathAlreadyDenied(denyPattern, config)) {
      continue;
    }

    seenDenyPatterns.add(denyPattern);

    issues.push({
      id: `file-${hashPath(file.path)}`,
      category: 'credentials',
      type: 'sensitive-file',
      title: file.type,
      description: file.description || `Access to ${denyPattern}`,
      target: denyPattern,
      risk: mapRisk(file.risk),
      action: {
        type: 'deny-path',
        target: denyPattern,
      },
    });
  }

  // Sort by severity (high first), then alphabetically by title
  return issues.sort((a, b) => {
    const severityDiff = SEVERITY_ORDER[a.risk] - SEVERITY_ORDER[b.risk];
    if (severityDiff !== 0) return severityDiff;
    return a.title.localeCompare(b.title);
  });
}

// Calculate severity progress from issues and fixed IDs
export function calculateProgress(
  issues: SecurityIssue[],
  fixedIds: Set<string>
): SeverityProgress {
  const progress: SeverityProgress = {
    high: { total: 0, fixed: 0 },
    medium: { total: 0, fixed: 0 },
    low: { total: 0, fixed: 0 },
  };

  for (const issue of issues) {
    progress[issue.risk].total++;
    if (fixedIds.has(issue.id)) {
      progress[issue.risk].fixed++;
    }
  }

  return progress;
}

// Get issues by category
export function getIssuesByCategory(
  issues: SecurityIssue[]
): Record<string, SecurityIssue[]> {
  const byCategory: Record<string, SecurityIssue[]> = {
    credentials: [],
    'mcp-servers': [],
  };

  for (const issue of issues) {
    byCategory[issue.category].push(issue);
  }

  return byCategory;
}
