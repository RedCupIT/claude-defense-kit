import type {
  AgentInfo,
  McpServer,
  FilesystemAccess,
  Capabilities,
  BlastRadiusItem,
  AttackChainResult,
  RiskLevel,
  ClaudeCodeConfig,
  SensitiveFile,
} from '../types/index.js';
import { getDangerousCapabilities } from '../scanners/capabilities.js';
import { ATTACK_CHAINS } from '../data/educational.js';
import { readClaudeConfig } from '../config/writer.js';

// Check if a path is already denied in the config
function isPathDenied(filePath: string, config: ClaudeCodeConfig): boolean {
  if (!config.permissions?.deny) return false;

  return config.permissions.deny.some(entry => {
    const entryPath = entry.match(/^Read\((.+)\)$/)?.[1];
    if (!entryPath) return false;
    // Wildcard match: ~/.aws/* covers ~/.aws/credentials
    if (entryPath.endsWith('/*')) {
      const base = entryPath.slice(0, -2);
      // Handle both ~/path and full path
      const normalizedFilePath = filePath.replace(/^~/, '');
      const normalizedBase = base.replace(/^~/, '');
      return normalizedFilePath.startsWith(normalizedBase);
    }
    return filePath === entryPath || filePath.replace(/^~/, '') === entryPath.replace(/^~/, '');
  });
}

// Filter sensitive files to exclude those already denied
function filterAlreadyDeniedFiles(
  files: SensitiveFile[],
  config: ClaudeCodeConfig
): SensitiveFile[] {
  return files.filter(file => !isPathDenied(file.path, config));
}

interface BlastRadiusInput {
  agent: AgentInfo;
  mcpServers: McpServer[];
  filesystem: FilesystemAccess;
  capabilities: Capabilities;
}

export function analyzeBlastRadius(input: BlastRadiusInput): BlastRadiusItem[] {
  const items: BlastRadiusItem[] = [];

  // Read current config to filter out already-denied paths
  const config = readClaudeConfig();

  // Filter filesystem sensitive files to exclude already-denied paths
  const filteredFilesystem: FilesystemAccess = {
    ...input.filesystem,
    sensitiveFiles: filterAlreadyDeniedFiles(input.filesystem.sensitiveFiles, config),
  };

  // Analyze credential exposure (only for files not already denied)
  const credentialItems = analyzeCredentialExposure(filteredFilesystem);
  items.push(...credentialItems);

  // Analyze MCP capabilities
  const mcpItems = analyzeMcpCapabilities(input.mcpServers);
  items.push(...mcpItems);

  // Analyze general capabilities
  const capabilityItems = analyzeCapabilityImpact(input.capabilities);
  items.push(...capabilityItems);

  // Analyze file system access
  const fsItems = analyzeFilesystemImpact(filteredFilesystem);
  items.push(...fsItems);

  // Sort by risk level (critical first)
  items.sort((a, b) => {
    const riskOrder: Record<RiskLevel, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
    };
    return riskOrder[a.risk] - riskOrder[b.risk];
  });

  return items;
}

function analyzeCredentialExposure(
  filesystem: FilesystemAccess
): BlastRadiusItem[] {
  const items: BlastRadiusItem[] = [];
  const credentialTypes = new Set<string>();

  for (const file of filesystem.sensitiveFiles) {
    // Group by type to avoid repetition
    if (credentialTypes.has(file.type)) continue;
    credentialTypes.add(file.type);

    // Determine the impact description
    let description = '';
    const typeLower = file.type.toLowerCase();

    if (typeLower.includes('ssh')) {
      description = 'Exfiltrate SSH keys and access remote servers';
    } else if (typeLower.includes('aws')) {
      description = 'Access AWS resources and potentially incur costs';
    } else if (typeLower.includes('gcp') || typeLower.includes('google')) {
      description = 'Access Google Cloud resources';
    } else if (typeLower.includes('azure')) {
      description = 'Access Azure resources';
    } else if (typeLower.includes('kube')) {
      description = 'Access Kubernetes clusters and deploy containers';
    } else if (typeLower.includes('docker')) {
      description = 'Access Docker registries and containers';
    } else if (typeLower.includes('gpg') || typeLower.includes('gnupg')) {
      description = 'Decrypt GPG-encrypted data and sign as you';
    } else if (typeLower.includes('git')) {
      description = 'Push code to repositories as you';
    } else if (typeLower.includes('env')) {
      description = 'Extract API keys and secrets from environment files';
    } else if (typeLower.includes('npm') || typeLower.includes('pypi')) {
      description = 'Publish packages to registries as you';
    } else if (typeLower.includes('password') || typeLower.includes('secret')) {
      description = 'Access stored passwords and secrets';
    } else {
      description = `Access ${file.type}`;
    }

    items.push({
      category: 'Credential Access',
      description,
      risk: file.risk,
    });
  }

  return items;
}

function analyzeMcpCapabilities(servers: McpServer[]): BlastRadiusItem[] {
  const items: BlastRadiusItem[] = [];

  for (const server of servers) {
    if (server.risk === 'low') continue;

    let description = server.riskReason || '';
    const nameLower = server.name.toLowerCase();

    if (nameLower.includes('shell') || nameLower.includes('bash')) {
      description = 'Execute arbitrary system commands';
    } else if (nameLower.includes('postgres') || nameLower.includes('mysql') ||
               nameLower.includes('sql')) {
      description = 'Read, modify, or delete database contents';
    } else if (nameLower.includes('filesystem') || nameLower.includes('file')) {
      description = 'Read and modify files on the system';
    }

    items.push({
      category: 'MCP Server',
      description: `${server.name}: ${description}`,
      risk: server.risk,
    });
  }

  return items;
}

function analyzeCapabilityImpact(capabilities: Capabilities): BlastRadiusItem[] {
  const items: BlastRadiusItem[] = [];
  const dangerous = getDangerousCapabilities(capabilities);

  for (const capability of dangerous) {
    let risk: RiskLevel = 'medium';
    let category = 'Capability';

    if (capability.includes('shell')) {
      risk = 'critical';
      category = 'Code Execution';
    } else if (capability.includes('database')) {
      risk = 'high';
      category = 'Data Access';
    } else if (capability.includes('Install')) {
      risk = 'high';
      category = 'System Modification';
    } else if (capability.includes('network')) {
      risk = 'medium';
      category = 'Network';
    }

    items.push({
      category,
      description: capability,
      risk,
    });
  }

  return items;
}

function analyzeFilesystemImpact(
  filesystem: FilesystemAccess
): BlastRadiusItem[] {
  const items: BlastRadiusItem[] = [];

  // Check for broad read access
  const hasBroadRead = filesystem.readPaths.some(
    p => p.includes('~/*') || p.includes('$HOME/*')
  );
  if (hasBroadRead) {
    items.push({
      category: 'File Access',
      description: 'Read any file in your home directory',
      risk: 'high',
    });
  }

  // Check for broad write access
  const hasBroadWrite = filesystem.writePaths.some(
    p => p.includes('~/*') || p.includes('$HOME/*')
  );
  if (hasBroadWrite) {
    items.push({
      category: 'File Access',
      description: 'Modify any file in your home directory',
      risk: 'critical',
    });
  }

  return items;
}

// Generate a summary of what could happen if compromised
export function generateImpactSummary(items: BlastRadiusItem[]): string[] {
  const summary: string[] = [];
  const seen = new Set<string>();

  for (const item of items) {
    // Deduplicate similar impacts
    const key = item.description.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);

    summary.push(item.description);
  }

  return summary.slice(0, 6); // Limit to top 6 impacts
}

// Generate attack chains based on current capabilities and credentials
export function generateAttackChains(input: BlastRadiusInput): AttackChainResult[] {
  const results: AttackChainResult[] = [];

  // Read current config to filter out already-denied paths
  const config = readClaudeConfig();

  // Get the list of available capabilities and credential types
  const availableCapabilities = new Set<string>();
  const availableCredentials = new Set<string>();

  // Map capabilities
  if (input.capabilities.shellExecution) availableCapabilities.add('shellExecution');
  if (input.capabilities.networkAccess) availableCapabilities.add('networkAccess');
  if (input.capabilities.packageInstallation) availableCapabilities.add('packageInstallation');
  if (input.capabilities.databaseAccess) availableCapabilities.add('databaseAccess');
  if (input.capabilities.fileSystemAccess) availableCapabilities.add('fileSystemAccess');

  // Map credential types from sensitive files (only those not already denied)
  const accessibleFiles = filterAlreadyDeniedFiles(input.filesystem.sensitiveFiles, config);
  for (const file of accessibleFiles) {
    availableCredentials.add(file.type);
  }

  // Check each attack chain template
  for (const chain of ATTACK_CHAINS) {
    let meetsRequirements = true;

    for (const req of chain.requirements) {
      // Check if requirement is a capability or credential type
      const isCapability = availableCapabilities.has(req);
      const isCredential = [...availableCredentials].some(
        cred => cred.toLowerCase().includes(req.toLowerCase()) ||
                req.toLowerCase().includes(cred.toLowerCase())
      );

      if (!isCapability && !isCredential) {
        meetsRequirements = false;
        break;
      }
    }

    if (meetsRequirements) {
      results.push({
        name: chain.name,
        scenario: chain.scenario,
        impact: chain.impact,
      });
    }
  }

  // Limit to top 4 most relevant attack chains
  return results.slice(0, 4);
}
