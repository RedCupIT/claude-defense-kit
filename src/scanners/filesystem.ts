import * as path from 'path';
import {
  getHomeDir,
  pathExists,
  listDir,
  displayPath,
} from '../utils/paths.js';
import { SENSITIVE_FILE_EDUCATION } from '../data/educational.js';
import type { FilesystemAccess, SensitiveFile } from '../types/index.js';

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

// Default accessible paths for Claude Code
// These are typical defaults - actual access may vary by config
const DEFAULT_READ_PATHS = [
  '~/*', // Home directory
];

const DEFAULT_WRITE_PATHS = [
  '~/Projects/*',
  '~/code/*',
  '~/dev/*',
  '~/work/*',
  '~/Downloads/*',
  '~/Documents/*',
];

// Sensitive directories to check
const SENSITIVE_DIRS: Array<{
  path: string;
  type: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}> = [
  {
    path: '~/.ssh',
    type: 'SSH keys',
    risk: 'critical',
    description: 'SSH private keys and configuration',
  },
  {
    path: '~/.aws',
    type: 'AWS credentials',
    risk: 'critical',
    description: 'AWS access keys and configuration',
  },
  {
    path: '~/.config/gcloud',
    type: 'GCP credentials',
    risk: 'critical',
    description: 'Google Cloud credentials and configuration',
  },
  {
    path: '~/.azure',
    type: 'Azure credentials',
    risk: 'critical',
    description: 'Azure credentials and configuration',
  },
  {
    path: '~/.kube',
    type: 'Kubernetes config',
    risk: 'high',
    description: 'Kubernetes cluster access configuration',
  },
  {
    path: '~/.docker',
    type: 'Docker config',
    risk: 'high',
    description: 'Docker credentials and configuration',
  },
  {
    path: '~/.gnupg',
    type: 'GPG keys',
    risk: 'critical',
    description: 'GPG private keys and keyring',
  },
  {
    path: '~/.password-store',
    type: 'Password store',
    risk: 'critical',
    description: 'Pass password manager storage',
  },
  {
    path: '~/.1password',
    type: '1Password data',
    risk: 'critical',
    description: '1Password local data',
  },
];

// Sensitive files to check
const SENSITIVE_FILES: Array<{
  path: string;
  type: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}> = [
  {
    path: '~/.gitconfig',
    type: 'Git config',
    risk: 'low',
    description: 'Git configuration (may contain tokens)',
  },
  {
    path: '~/.git-credentials',
    type: 'Git credentials',
    risk: 'high',
    description: 'Stored Git credentials',
  },
  {
    path: '~/.netrc',
    type: 'Netrc credentials',
    risk: 'high',
    description: 'Network authentication credentials',
  },
  {
    path: '~/.npmrc',
    type: 'npm config',
    risk: 'medium',
    description: 'npm configuration (may contain auth tokens)',
  },
  {
    path: '~/.pypirc',
    type: 'PyPI config',
    risk: 'medium',
    description: 'PyPI configuration (may contain auth tokens)',
  },
  {
    path: '~/.m2/settings.xml',
    type: 'Maven config',
    risk: 'medium',
    description: 'Maven settings (may contain credentials)',
  },
  {
    path: '~/.gradle/gradle.properties',
    type: 'Gradle config',
    risk: 'medium',
    description: 'Gradle properties (may contain credentials)',
  },
  {
    path: '~/.composer/auth.json',
    type: 'Composer auth',
    risk: 'medium',
    description: 'Composer authentication tokens',
  },
  {
    path: '~/.cargo/credentials',
    type: 'Cargo credentials',
    risk: 'medium',
    description: 'Rust cargo registry credentials',
  },
  {
    path: '~/.gem/credentials',
    type: 'RubyGems credentials',
    risk: 'medium',
    description: 'RubyGems API credentials',
  },
  {
    path: '~/.nuget/NuGet.Config',
    type: 'NuGet config',
    risk: 'medium',
    description: 'NuGet configuration (may contain API keys)',
  },
];

export async function scanFilesystem(): Promise<FilesystemAccess> {
  const sensitiveFiles: SensitiveFile[] = [];
  const home = getHomeDir();

  // Check sensitive directories
  for (const dir of SENSITIVE_DIRS) {
    const fullPath = dir.path.replace('~', home);
    if (pathExists(fullPath)) {
      sensitiveFiles.push(addEducationalContent({
        path: displayPath(fullPath),
        type: dir.type,
        risk: dir.risk,
        description: dir.description,
      }));

      // Scan for specific sensitive files within directories
      const files = listDir(fullPath);
      for (const file of files) {
        const filePath = path.join(fullPath, file);
        const sensitiveFile = identifySensitiveFile(filePath, file, dir.type);
        if (sensitiveFile) {
          sensitiveFiles.push(addEducationalContent(sensitiveFile));
        }
      }
    }
  }

  // Check individual sensitive files
  for (const fileInfo of SENSITIVE_FILES) {
    const fullPath = fileInfo.path.replace('~', home);
    if (pathExists(fullPath)) {
      sensitiveFiles.push(addEducationalContent({
        path: displayPath(fullPath),
        type: fileInfo.type,
        risk: fileInfo.risk,
        description: fileInfo.description,
      }));
    }
  }

  return {
    readPaths: DEFAULT_READ_PATHS,
    writePaths: DEFAULT_WRITE_PATHS,
    sensitiveFiles,
  };
}

function identifySensitiveFile(
  fullPath: string,
  filename: string,
  parentType: string
): SensitiveFile | null {
  const nameLower = filename.toLowerCase();

  // SSH key identification
  if (parentType === 'SSH keys') {
    if (nameLower === 'id_rsa' || nameLower === 'id_ed25519' ||
        nameLower === 'id_ecdsa' || nameLower === 'id_dsa') {
      return {
        path: displayPath(fullPath),
        type: 'SSH private key',
        risk: 'critical',
        description: `Private key file: ${filename}`,
      };
    }
  }

  // AWS credential files
  if (parentType === 'AWS credentials') {
    if (nameLower === 'credentials') {
      return {
        path: displayPath(fullPath),
        type: 'AWS credentials file',
        risk: 'critical',
        description: 'AWS access key credentials',
      };
    }
  }

  // GCP service account keys
  if (parentType === 'GCP credentials') {
    if (nameLower.endsWith('.json')) {
      return {
        path: displayPath(fullPath),
        type: 'GCP service account',
        risk: 'critical',
        description: 'Google Cloud service account key',
      };
    }
  }

  // Kubernetes config
  if (parentType === 'Kubernetes config') {
    if (nameLower === 'config') {
      return {
        path: displayPath(fullPath),
        type: 'Kubeconfig',
        risk: 'high',
        description: 'Kubernetes cluster configuration',
      };
    }
  }

  return null;
}

// Scan a specific directory for .env files
export async function scanForEnvFiles(directory: string): Promise<SensitiveFile[]> {
  const envFiles: SensitiveFile[] = [];
  const home = getHomeDir();
  const fullPath = directory.replace('~', home);

  if (!pathExists(fullPath)) {
    return envFiles;
  }

  const files = listDir(fullPath);
  for (const file of files) {
    const nameLower = file.toLowerCase();
    if (nameLower === '.env' || nameLower.startsWith('.env.')) {
      envFiles.push(addEducationalContent({
        path: displayPath(path.join(fullPath, file)),
        type: 'Environment file',
        risk: 'high',
        description: 'Environment variables (may contain secrets)',
      }));
    }
  }

  return envFiles;
}
