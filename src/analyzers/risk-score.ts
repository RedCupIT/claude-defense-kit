import type {
  AgentInfo,
  McpServer,
  FilesystemAccess,
  Capabilities,
  RiskLevel,
} from '../types/index.js';

interface RiskInput {
  agent: AgentInfo;
  mcpServers: McpServer[];
  filesystem: FilesystemAccess;
  capabilities: Capabilities;
}

// Risk weights for different factors
const WEIGHTS = {
  // MCP server risks
  mcpServerCritical: 25,
  mcpServerHigh: 15,
  mcpServerMedium: 8,
  mcpServerLow: 3,

  // Sensitive file risks
  sensitiveFileCritical: 15,
  sensitiveFileHigh: 10,
  sensitiveFileMedium: 5,
  sensitiveFileLow: 2,

  // Capability risks
  shellExecution: 20,
  databaseAccess: 12,
  networkAccess: 8,
  packageInstallation: 10,
  backgroundProcesses: 6,
  fileSystemAccess: 5,

  // Base risks
  agentDetected: 5,
  broadFileAccess: 10,
};

export function calculateRiskScore(input: RiskInput): number {
  let score = 0;

  // Base score for having an AI agent detected
  if (input.agent.detected) {
    score += WEIGHTS.agentDetected;
  }

  // MCP server risks
  for (const server of input.mcpServers) {
    score += getMcpServerRiskScore(server.risk);
  }

  // Sensitive file risks
  for (const file of input.filesystem.sensitiveFiles) {
    score += getSensitiveFileRiskScore(file.risk);
  }

  // Capability risks
  if (input.capabilities.shellExecution) {
    score += WEIGHTS.shellExecution;
  }
  if (input.capabilities.databaseAccess) {
    score += WEIGHTS.databaseAccess;
  }
  if (input.capabilities.networkAccess) {
    score += WEIGHTS.networkAccess;
  }
  if (input.capabilities.packageInstallation) {
    score += WEIGHTS.packageInstallation;
  }
  if (input.capabilities.backgroundProcesses) {
    score += WEIGHTS.backgroundProcesses;
  }
  if (input.capabilities.fileSystemAccess) {
    score += WEIGHTS.fileSystemAccess;
  }

  // Broad file access (home directory access)
  const hasBroadAccess = input.filesystem.readPaths.some(
    p => p.includes('~/*') || p.includes('$HOME/*') || p === '/'
  );
  if (hasBroadAccess) {
    score += WEIGHTS.broadFileAccess;
  }

  // Cap at 100
  return Math.min(100, score);
}

function getMcpServerRiskScore(risk: RiskLevel): number {
  switch (risk) {
    case 'critical':
      return WEIGHTS.mcpServerCritical;
    case 'high':
      return WEIGHTS.mcpServerHigh;
    case 'medium':
      return WEIGHTS.mcpServerMedium;
    case 'low':
      return WEIGHTS.mcpServerLow;
    default:
      return 0;
  }
}

function getSensitiveFileRiskScore(risk: RiskLevel): number {
  switch (risk) {
    case 'critical':
      return WEIGHTS.sensitiveFileCritical;
    case 'high':
      return WEIGHTS.sensitiveFileHigh;
    case 'medium':
      return WEIGHTS.sensitiveFileMedium;
    case 'low':
      return WEIGHTS.sensitiveFileLow;
    default:
      return 0;
  }
}

// Get the risk level category from a numeric score
export function getRiskLevel(score: number): RiskLevel {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

// Get a human-readable risk description
export function getRiskDescription(score: number): string {
  if (score >= 75) {
    return 'CRITICAL - Immediate action recommended';
  }
  if (score >= 50) {
    return 'HIGH - Significant exposure detected';
  }
  if (score >= 25) {
    return 'MEDIUM - Some concerns identified';
  }
  return 'LOW - Minimal exposure detected';
}
