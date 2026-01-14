import { getMcpServerConfigs } from '../detectors/claude-code.js';
import {
  matchPattern,
  HIGH_RISK_TOOL_PATTERNS,
  MEDIUM_RISK_TOOL_PATTERNS,
} from '../utils/patterns.js';
import { MCP_EDUCATION } from '../data/educational.js';
import type {
  AgentInfo,
  McpServer,
  McpTool,
  RiskLevel,
} from '../types/index.js';

// Get educational content for an MCP server based on its name
function getEducationalContent(name: string): {
  brief?: string;
  detail?: string;
  mitigation?: string;
} {
  const nameLower = name.toLowerCase();

  // Check exact matches first
  for (const [key, content] of Object.entries(MCP_EDUCATION)) {
    if (nameLower === key || nameLower.includes(key)) {
      return {
        brief: content.brief,
        detail: content.detail,
        mitigation: content.mitigation,
      };
    }
  }

  return {};
}

// Known MCP server patterns and their risks
const KNOWN_SERVERS: Record<string, {
  tools: string[];
  risk: RiskLevel;
  reason: string;
}> = {
  'filesystem': {
    tools: ['read_file', 'write_file', 'list_directory', 'create_directory'],
    risk: 'medium',
    reason: 'Can read and write files on the filesystem',
  },
  'shell': {
    tools: ['execute_command', 'run_command', 'bash'],
    risk: 'critical',
    reason: 'Unrestricted shell command execution',
  },
  'bash': {
    tools: ['execute', 'run'],
    risk: 'critical',
    reason: 'Unrestricted shell command execution',
  },
  'terminal': {
    tools: ['execute', 'run_command'],
    risk: 'critical',
    reason: 'Unrestricted terminal access',
  },
  'postgres': {
    tools: ['query', 'list_tables', 'describe_table'],
    risk: 'high',
    reason: 'Database read/write access',
  },
  'sqlite': {
    tools: ['query', 'execute'],
    risk: 'high',
    reason: 'Database read/write access',
  },
  'mysql': {
    tools: ['query', 'execute'],
    risk: 'high',
    reason: 'Database read/write access',
  },
  'git': {
    tools: ['clone', 'commit', 'push', 'status'],
    risk: 'medium',
    reason: 'Git repository access',
  },
  'github': {
    tools: ['create_issue', 'create_pr', 'search_repos'],
    risk: 'medium',
    reason: 'GitHub API access',
  },
  'browser': {
    tools: ['navigate', 'screenshot', 'click'],
    risk: 'medium',
    reason: 'Browser automation capabilities',
  },
  'puppeteer': {
    tools: ['navigate', 'screenshot', 'evaluate'],
    risk: 'high',
    reason: 'Full browser automation with script execution',
  },
  'fetch': {
    tools: ['fetch', 'get', 'post'],
    risk: 'medium',
    reason: 'Network request capabilities',
  },
  'http': {
    tools: ['request', 'get', 'post'],
    risk: 'medium',
    reason: 'HTTP request capabilities',
  },
};

export async function scanMcpServers(agent: AgentInfo): Promise<McpServer[]> {
  const servers: McpServer[] = [];

  if (!agent.detected) {
    return servers;
  }

  const mcpConfigs = getMcpServerConfigs();

  for (const [name, config] of Object.entries(mcpConfigs)) {
    const server = analyzeMcpServer(name, config);
    servers.push(server);
  }

  return servers;
}

function analyzeMcpServer(
  name: string,
  config: {
    command?: string;
    args?: string[];
    url?: string;
    env?: Record<string, string>;
  }
): McpServer {
  // Determine server type
  let type: 'stdio' | 'http' | 'sse' | 'unknown' = 'unknown';
  if (config.command) {
    type = 'stdio';
  } else if (config.url) {
    type = config.url.includes('sse') ? 'sse' : 'http';
  }

  // Get known tools or infer from name
  const { tools, risk, reason } = inferServerCapabilities(name, config);

  // Get educational content
  const education = getEducationalContent(name);

  return {
    name,
    type,
    command: config.command,
    args: config.args,
    url: config.url,
    tools,
    risk,
    riskReason: reason,
    securityBrief: education.brief,
    securityDetail: education.detail,
    mitigation: education.mitigation,
  };
}

function inferServerCapabilities(
  name: string,
  config: {
    command?: string;
    args?: string[];
    url?: string;
  }
): { tools: McpTool[]; risk: RiskLevel; reason: string } {
  const nameLower = name.toLowerCase();

  // Check if it matches a known server
  for (const [knownName, info] of Object.entries(KNOWN_SERVERS)) {
    if (nameLower.includes(knownName)) {
      return {
        tools: info.tools.map(t => ({ name: t })),
        risk: info.risk,
        reason: info.reason,
      };
    }
  }

  // Check command for hints
  const command = config.command?.toLowerCase() || '';
  const args = config.args?.join(' ').toLowerCase() || '';
  const combinedCmd = `${command} ${args}`;

  // Shell/command execution
  if (
    combinedCmd.includes('shell') ||
    combinedCmd.includes('bash') ||
    combinedCmd.includes('exec') ||
    combinedCmd.includes('terminal')
  ) {
    return {
      tools: [{ name: 'execute_command' }],
      risk: 'critical',
      reason: 'Likely has shell execution capabilities',
    };
  }

  // Database
  if (
    combinedCmd.includes('postgres') ||
    combinedCmd.includes('mysql') ||
    combinedCmd.includes('sqlite') ||
    combinedCmd.includes('database') ||
    combinedCmd.includes('sql')
  ) {
    return {
      tools: [{ name: 'query' }],
      risk: 'high',
      reason: 'Database access capabilities',
    };
  }

  // Filesystem
  if (
    combinedCmd.includes('filesystem') ||
    combinedCmd.includes('file') ||
    combinedCmd.includes('fs')
  ) {
    return {
      tools: [{ name: 'read_file' }, { name: 'write_file' }],
      risk: 'medium',
      reason: 'Filesystem access capabilities',
    };
  }

  // Network/HTTP
  if (
    combinedCmd.includes('http') ||
    combinedCmd.includes('fetch') ||
    combinedCmd.includes('api') ||
    config.url
  ) {
    return {
      tools: [{ name: 'request' }],
      risk: 'medium',
      reason: 'Network request capabilities',
    };
  }

  // Unknown - default to medium risk for caution
  return {
    tools: [{ name: 'unknown' }],
    risk: 'medium',
    reason: 'Unknown capabilities - unable to determine tools',
  };
}

// Calculate risk level based on tools
export function assessToolRisk(tools: McpTool[]): RiskLevel {
  let maxRisk: RiskLevel = 'low';

  for (const tool of tools) {
    const toolName = tool.name.toLowerCase();

    // Check high risk patterns
    for (const pattern of HIGH_RISK_TOOL_PATTERNS) {
      if (matchPattern(pattern, toolName)) {
        return 'critical'; // Short circuit - can't get worse
      }
    }

    // Check medium risk patterns
    for (const pattern of MEDIUM_RISK_TOOL_PATTERNS) {
      if (matchPattern(pattern, toolName)) {
        if (maxRisk === 'low') {
          maxRisk = 'medium';
        }
      }
    }
  }

  return maxRisk;
}
