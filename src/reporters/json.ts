import type { ScanResults } from '../types/index.js';

export function generateJsonReport(results: ScanResults): string {
  // Create a clean JSON output without internal implementation details
  const report = {
    meta: {
      tool: 'what-can-my-ai-do',
      version: '0.1.0',
      timestamp: results.timestamp,
    },
    agent: {
      name: results.agent.name,
      detected: results.agent.detected,
      version: results.agent.version || null,
      configPath: results.agent.configPath || null,
    },
    riskScore: {
      score: results.riskScore,
      level: getRiskLevel(results.riskScore),
      description: getRiskDescription(results.riskScore),
    },
    mcpServers: results.mcpServers.map(server => ({
      name: server.name,
      type: server.type,
      tools: server.tools.map(t => t.name),
      risk: server.risk,
      riskReason: server.riskReason || null,
    })),
    filesystem: {
      readPaths: results.filesystem.readPaths,
      writePaths: results.filesystem.writePaths,
      sensitiveFileCount: results.filesystem.sensitiveFiles.length,
      sensitiveFiles: results.filesystem.sensitiveFiles.map(f => ({
        path: f.path,
        type: f.type,
        risk: f.risk,
      })),
    },
    capabilities: {
      shellExecution: results.capabilities.shellExecution,
      networkAccess: results.capabilities.networkAccess,
      packageInstallation: results.capabilities.packageInstallation,
      databaseAccess: results.capabilities.databaseAccess,
      backgroundProcesses: results.capabilities.backgroundProcesses,
      fileSystemAccess: results.capabilities.fileSystemAccess,
    },
    blastRadius: results.blastRadius.map(item => ({
      category: item.category,
      description: item.description,
      risk: item.risk,
    })),
    recommendations: results.recommendations.map(rec => ({
      priority: rec.priority,
      title: rec.title,
      description: rec.description,
      risk: rec.risk,
    })),
  };

  return JSON.stringify(report, null, 2);
}

function getRiskLevel(score: number): string {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

function getRiskDescription(score: number): string {
  if (score >= 75) return 'Critical - Immediate action recommended';
  if (score >= 50) return 'High - Significant exposure detected';
  if (score >= 25) return 'Medium - Some concerns identified';
  return 'Low - Minimal exposure detected';
}
