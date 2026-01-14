import type { Capabilities, McpServer } from '../types/index.js';

// Keywords that indicate shell execution capability
const SHELL_KEYWORDS = [
  'shell', 'bash', 'exec', 'command', 'terminal', 'run',
  'subprocess', 'spawn', 'execute',
];

// Keywords that indicate network capability
const NETWORK_KEYWORDS = [
  'http', 'fetch', 'request', 'api', 'network', 'url',
  'get', 'post', 'put', 'delete', 'curl', 'wget',
];

// Keywords that indicate package installation capability
const PACKAGE_KEYWORDS = [
  'npm', 'pip', 'yarn', 'pnpm', 'cargo', 'gem', 'brew',
  'install', 'package',
];

// Keywords that indicate database access
const DATABASE_KEYWORDS = [
  'postgres', 'mysql', 'sqlite', 'database', 'sql', 'query',
  'mongo', 'redis', 'db',
];

// Keywords that indicate background process capability
const BACKGROUND_KEYWORDS = [
  'daemon', 'background', 'async', 'spawn', 'fork',
  'detach', 'nohup',
];

// Keywords that indicate file system access
const FILESYSTEM_KEYWORDS = [
  'file', 'filesystem', 'fs', 'read', 'write', 'directory',
  'path', 'folder',
];

export async function scanCapabilities(
  mcpServers: McpServer[]
): Promise<Capabilities> {
  const capabilities: Capabilities = {
    shellExecution: false,
    networkAccess: false,
    packageInstallation: false,
    backgroundProcesses: false,
    databaseAccess: false,
    fileSystemAccess: false,
  };

  for (const server of mcpServers) {
    // Check server name
    const nameLower = server.name.toLowerCase();

    // Check tools
    const toolNames = server.tools.map(t => t.name.toLowerCase());
    const allKeywords = [
      nameLower,
      ...toolNames,
      server.command?.toLowerCase() || '',
      ...(server.args?.map(a => a.toLowerCase()) || []),
    ].join(' ');

    // Check each capability
    if (matchesAny(allKeywords, SHELL_KEYWORDS)) {
      capabilities.shellExecution = true;
    }

    if (matchesAny(allKeywords, NETWORK_KEYWORDS)) {
      capabilities.networkAccess = true;
    }

    if (matchesAny(allKeywords, PACKAGE_KEYWORDS)) {
      capabilities.packageInstallation = true;
    }

    if (matchesAny(allKeywords, DATABASE_KEYWORDS)) {
      capabilities.databaseAccess = true;
    }

    if (matchesAny(allKeywords, BACKGROUND_KEYWORDS)) {
      capabilities.backgroundProcesses = true;
    }

    if (matchesAny(allKeywords, FILESYSTEM_KEYWORDS)) {
      capabilities.fileSystemAccess = true;
    }
  }

  // Shell execution implies many other capabilities
  if (capabilities.shellExecution) {
    capabilities.networkAccess = true;
    capabilities.packageInstallation = true;
    capabilities.backgroundProcesses = true;
    capabilities.fileSystemAccess = true;
  }

  return capabilities;
}

function matchesAny(text: string, keywords: string[]): boolean {
  return keywords.some(kw => text.includes(kw));
}

// Get a summary of dangerous capabilities
export function getDangerousCapabilities(
  capabilities: Capabilities
): string[] {
  const dangerous: string[] = [];

  if (capabilities.shellExecution) {
    dangerous.push('Execute arbitrary shell commands');
  }

  if (capabilities.networkAccess) {
    dangerous.push('Make outbound network requests');
  }

  if (capabilities.packageInstallation) {
    dangerous.push('Install software packages');
  }

  if (capabilities.databaseAccess) {
    dangerous.push('Access database contents');
  }

  if (capabilities.backgroundProcesses) {
    dangerous.push('Spawn background processes');
  }

  if (capabilities.fileSystemAccess) {
    dangerous.push('Read and write files');
  }

  return dangerous;
}
