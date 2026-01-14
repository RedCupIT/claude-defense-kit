import type {
  AgentInfo,
  McpServer,
  FilesystemAccess,
  Capabilities,
  Recommendation,
  RiskLevel,
} from '../types/index.js';

interface RecommendationInput {
  agent: AgentInfo;
  mcpServers: McpServer[];
  filesystem: FilesystemAccess;
  capabilities: Capabilities;
  riskScore: number;
}

export function generateRecommendations(
  input: RecommendationInput
): Recommendation[] {
  const recommendations: Recommendation[] = [];

  // Check for shell execution capability
  if (input.capabilities.shellExecution) {
    const shellServer = input.mcpServers.find(
      s => s.name.toLowerCase().includes('shell') ||
           s.name.toLowerCase().includes('bash') ||
           s.name.toLowerCase().includes('terminal')
    );

    recommendations.push({
      priority: 1,
      title: 'Restrict shell access',
      description: shellServer
        ? `Remove or restrict the "${shellServer.name}" MCP server. ` +
          'Consider using an allowlist of specific commands instead of ' +
          'unrestricted shell access.'
        : 'Restrict shell execution capabilities to specific allowed commands.',
      risk: 'critical',
      howToFix: [
        'Remove the shell MCP server from your Claude configuration',
        'Or create a custom MCP server that only allows specific commands',
        'Consider using the built-in Bash tool with explicit approval per command',
        'Add shell-related tools to your disallowedTools list in settings',
      ],
      protectsAgainst: 'Arbitrary code execution, malware installation, data exfiltration, system modification',
    });
  }

  // Check for sensitive credential files
  const criticalCreds = input.filesystem.sensitiveFiles.filter(
    f => f.risk === 'critical'
  );

  if (criticalCreds.length > 0) {
    const types = [...new Set(criticalCreds.map(f => f.type))];
    recommendations.push({
      priority: 2,
      title: 'Secure sensitive credentials',
      description:
        `Found ${criticalCreds.length} critical credential files ` +
        `(${types.slice(0, 3).join(', ')}). ` +
        'Move credentials to a secure vault or use environment-specific credential injection.',
      risk: 'critical',
      howToFix: [
        'Move long-lived credentials to a secrets manager (1Password, HashiCorp Vault, AWS Secrets Manager)',
        'Use IAM roles or workload identity instead of static credentials',
        'Set short expiration times on any tokens or API keys',
        'Configure Claude Code to exclude sensitive directories from file access',
      ],
      protectsAgainst: 'Credential theft, cloud account takeover, lateral movement to other systems',
    });
  }

  // Check for broad file access
  const hasBroadAccess = input.filesystem.readPaths.some(
    p => p.includes('~/*')
  );
  if (hasBroadAccess) {
    recommendations.push({
      priority: 3,
      title: 'Scope filesystem access',
      description:
        'AI agent has access to your entire home directory. ' +
        'Configure filesystem access to only include project directories.',
      risk: 'high',
      howToFix: [
        'Configure Claude Code to only access specific project directories',
        'Use .claude/settings.json to define allowed paths',
        'Move sensitive files outside of accessible directories',
        'Create a dedicated workspace directory for AI-assisted projects',
      ],
      protectsAgainst: 'Reading sensitive files, credential theft, source code exfiltration',
    });
  }

  // Check for database access
  if (input.capabilities.databaseAccess) {
    const dbServer = input.mcpServers.find(
      s => s.name.toLowerCase().includes('postgres') ||
           s.name.toLowerCase().includes('mysql') ||
           s.name.toLowerCase().includes('sql') ||
           s.name.toLowerCase().includes('database')
    );

    if (dbServer) {
      recommendations.push({
        priority: 4,
        title: 'Limit database access',
        description:
          `The "${dbServer.name}" MCP server provides database access. ` +
          'Use a read-only database user or restrict to specific tables.',
        risk: 'high',
        howToFix: [
          'Create a dedicated read-only database user for the AI agent',
          'Use database views to limit accessible data',
          'Exclude tables with PII or sensitive data',
          'Enable database query logging to audit AI agent queries',
        ],
        protectsAgainst: 'Data theft, PII exposure, unauthorized data modification',
      });
    }
  }

  // Check for environment files
  const envFiles = input.filesystem.sensitiveFiles.filter(
    f => f.type.toLowerCase().includes('env')
  );
  if (envFiles.length > 0) {
    recommendations.push({
      priority: 5,
      title: 'Protect environment files',
      description:
        `Found ${envFiles.length} environment files that may contain secrets. ` +
        'Use a secrets manager instead of .env files.',
      risk: 'high',
      howToFix: [
        'Migrate secrets from .env files to a secrets manager',
        'Use environment variable injection at runtime instead of files',
        'Add .env patterns to your .gitignore and Claude exclusion list',
        'Rotate any secrets that may have been exposed',
      ],
      protectsAgainst: 'API key theft, third-party service compromise, database access',
    });
  }

  // Check for git credentials
  const gitCreds = input.filesystem.sensitiveFiles.filter(
    f => f.type.toLowerCase().includes('git')
  );
  if (gitCreds.length > 0) {
    recommendations.push({
      priority: 6,
      title: 'Secure Git credentials',
      description:
        'Git credential files are accessible. Use SSH keys with passphrases.',
      risk: 'medium',
      howToFix: [
        'Use SSH keys with passphrases instead of HTTPS tokens',
        'Configure Git credential helper with short-lived tokens',
        'Enable 2FA on your Git hosting provider',
        'Use signed commits to detect tampering',
      ],
      protectsAgainst: 'Malicious code injection, repository tampering, impersonation',
    });
  }

  // Check for cloud credentials
  const cloudTypes = ['aws', 'gcp', 'azure', 'google'];
  const cloudCreds = input.filesystem.sensitiveFiles.filter(
    f => cloudTypes.some(t => f.type.toLowerCase().includes(t))
  );
  if (cloudCreds.length > 0) {
    recommendations.push({
      priority: 7,
      title: 'Use short-lived cloud credentials',
      description:
        'Found cloud provider credentials that could access infrastructure.',
      risk: 'critical',
      howToFix: [
        'Use IAM roles instead of long-lived access keys',
        'Configure temporary credentials via AWS SSO, GCP Workload Identity, or Azure Managed Identity',
        'Set up CloudTrail/Cloud Audit Logs to monitor credential usage',
        'Implement least-privilege IAM policies',
      ],
      protectsAgainst: 'Cloud account takeover, resource abuse, data breach',
    });
  }

  // Check for network access without shell
  if (input.capabilities.networkAccess && !input.capabilities.shellExecution) {
    recommendations.push({
      priority: 8,
      title: 'Review network access',
      description:
        'AI agent can make network requests. Configure allowlists for destinations.',
      risk: 'medium',
      howToFix: [
        'Configure MCP servers to only allow requests to specific domains',
        'Use a network proxy to monitor outbound connections',
        'Review MCP server source code for network capabilities',
      ],
      protectsAgainst: 'Data exfiltration, command and control communication',
    });
  }

  // Check for package installation capability
  if (input.capabilities.packageInstallation) {
    recommendations.push({
      priority: 9,
      title: 'Restrict package installation',
      description:
        'AI agent can install packages, which could introduce malicious code.',
      risk: 'high',
      howToFix: [
        'Use lockfiles (package-lock.json, yarn.lock) to pin dependencies',
        'Enable npm audit or similar security scanning',
        'Review package changes before allowing installation',
        'Consider using a private package registry with approved packages',
      ],
      protectsAgainst: 'Supply chain attacks, malicious package installation',
    });
  }

  // General recommendation if score is high
  if (input.riskScore >= 50 && recommendations.length < 3) {
    recommendations.push({
      priority: 10,
      title: 'Review AI agent permissions',
      description:
        'Your AI agent has significant access to your system. Apply least privilege.',
      risk: 'medium',
      howToFix: [
        'Audit current MCP servers and remove any not actively used',
        'Review Claude Code settings for unnecessary permissions',
        'Consider running Claude Code in a container or VM for isolation',
        'Enable logging to audit AI agent actions',
      ],
      protectsAgainst: 'Broad attack surface, privilege escalation',
    });
  }

  // Sort by priority
  recommendations.sort((a, b) => a.priority - b.priority);

  // Return top recommendations
  return recommendations.slice(0, 5);
}

// Get a short action item for each recommendation
export function getActionItem(rec: Recommendation): string {
  return `[${rec.risk.toUpperCase()}] ${rec.title}`;
}
