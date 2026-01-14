import * as path from 'path';
import * as fs from 'fs';
import {
  getHomeDir,
  pathExists,
  listDir,
  displayPath,
} from '../utils/paths.js';
import { SENSITIVE_FILE_EDUCATION } from '../data/educational.js';
import type { SensitiveFile, RiskLevel } from '../types/index.js';

// Helper to add educational content to a sensitive file
function addEducationalContent(file: SensitiveFile): SensitiveFile {
  const education = SENSITIVE_FILE_EDUCATION[file.type];
  if (education) {
    return {
      ...file,
      whyItMatters: education.brief,
      attackScenario: education.detail,
      mitigation: education.mitigation,
    };
  }
  return file;
}

// File patterns that typically contain secrets
const SECRET_FILE_PATTERNS: Array<{
  pattern: RegExp;
  type: string;
  risk: RiskLevel;
  description: string;
}> = [
  {
    pattern: /^\.env$/i,
    type: 'Environment file',
    risk: 'high',
    description: 'Environment variables file',
  },
  {
    pattern: /^\.env\..+$/i,
    type: 'Environment file',
    risk: 'high',
    description: 'Environment-specific variables',
  },
  {
    pattern: /^\.envrc$/i,
    type: 'direnv config',
    risk: 'high',
    description: 'direnv environment file',
  },
  {
    pattern: /secrets?\.ya?ml$/i,
    type: 'Secrets file',
    risk: 'critical',
    description: 'Secrets configuration file',
  },
  {
    pattern: /secrets?\.json$/i,
    type: 'Secrets file',
    risk: 'critical',
    description: 'Secrets configuration file',
  },
  {
    pattern: /credentials?\.json$/i,
    type: 'Credentials file',
    risk: 'critical',
    description: 'Credentials configuration file',
  },
  {
    pattern: /service[_-]?account.*\.json$/i,
    type: 'Service account key',
    risk: 'critical',
    description: 'Cloud service account credentials',
  },
  {
    pattern: /.*[_-]?key\.pem$/i,
    type: 'Private key',
    risk: 'critical',
    description: 'PEM private key file',
  },
  {
    pattern: /.*[_-]?key\.json$/i,
    type: 'Key file',
    risk: 'high',
    description: 'JSON key file',
  },
  {
    pattern: /^\.?htpasswd$/i,
    type: 'htpasswd file',
    risk: 'high',
    description: 'Apache password file',
  },
  {
    pattern: /^\.?pgpass$/i,
    type: 'PostgreSQL password',
    risk: 'high',
    description: 'PostgreSQL password file',
  },
  {
    pattern: /^\.?my\.?cnf$/i,
    type: 'MySQL config',
    risk: 'high',
    description: 'MySQL configuration with credentials',
  },
  {
    pattern: /^terraform\.tfvars$/i,
    type: 'Terraform vars',
    risk: 'high',
    description: 'Terraform variables (may contain secrets)',
  },
  {
    pattern: /^.*\.tfstate$/i,
    type: 'Terraform state',
    risk: 'critical',
    description: 'Terraform state (contains sensitive data)',
  },
  {
    pattern: /^vault[_-]?token$/i,
    type: 'Vault token',
    risk: 'critical',
    description: 'HashiCorp Vault token',
  },
];

// Directories to scan for sensitive files
const SCAN_DIRECTORIES = [
  '~',
  '~/Projects',
  '~/code',
  '~/dev',
  '~/work',
  '~/Documents',
];

// Maximum depth for directory traversal
const MAX_DEPTH = 3;

export async function scanCredentials(): Promise<SensitiveFile[]> {
  const sensitiveFiles: SensitiveFile[] = [];
  const home = getHomeDir();
  const scanned = new Set<string>();

  for (const dir of SCAN_DIRECTORIES) {
    const fullPath = dir.replace('~', home);
    if (pathExists(fullPath)) {
      await scanDirectory(fullPath, sensitiveFiles, scanned, 0);
    }
  }

  return sensitiveFiles;
}

async function scanDirectory(
  directory: string,
  results: SensitiveFile[],
  scanned: Set<string>,
  depth: number
): Promise<void> {
  // Prevent infinite loops and limit depth
  if (depth > MAX_DEPTH || scanned.has(directory)) {
    return;
  }
  scanned.add(directory);

  let entries: string[];
  try {
    entries = listDir(directory);
  } catch {
    return; // Permission denied or other error
  }

  for (const entry of entries) {
    // Skip hidden directories (except specific ones we want to scan)
    if (entry.startsWith('.') && !entry.startsWith('.env')) {
      continue;
    }

    // Skip common large directories
    if (entry === 'node_modules' || entry === '.git' ||
        entry === 'vendor' || entry === '__pycache__' ||
        entry === 'venv' || entry === '.venv') {
      continue;
    }

    const fullPath = path.join(directory, entry);

    // Check if entry matches a sensitive pattern
    const sensitiveFile = checkSensitiveFile(fullPath, entry);
    if (sensitiveFile) {
      results.push(sensitiveFile);
    }

    // Recursively scan subdirectories
    try {
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        await scanDirectory(fullPath, results, scanned, depth + 1);
      }
    } catch {
      // Ignore permission errors
    }
  }
}

function checkSensitiveFile(
  fullPath: string,
  filename: string
): SensitiveFile | null {
  for (const pattern of SECRET_FILE_PATTERNS) {
    if (pattern.pattern.test(filename)) {
      return addEducationalContent({
        path: displayPath(fullPath),
        type: pattern.type,
        risk: pattern.risk,
        description: pattern.description,
      });
    }
  }
  return null;
}

// Count total sensitive files by risk level
export function countByRisk(
  files: SensitiveFile[]
): Record<RiskLevel, number> {
  const counts: Record<RiskLevel, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  for (const file of files) {
    counts[file.risk]++;
  }

  return counts;
}
