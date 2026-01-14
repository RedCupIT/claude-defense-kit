import * as fs from 'fs';
import * as path from 'path';
import { getHomeDir } from '../utils/paths.js';
import { getMcpServerConfigs } from '../detectors/claude-code.js';
import type { ExposedEnvVar, IdentityExposure, IdentityScanResult, ClaudeJsonIdentity } from '../types/index.js';

// Sensitive env var patterns
const SENSITIVE_ENV_PATTERNS = [
  /.*_(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)$/i,
  /^(DATABASE|REDIS|MONGO|MYSQL|POSTGRES)_URL$/i,
  /^(AWS|AZURE|GCP|GOOGLE)_/i,
  /^(OPENAI|ANTHROPIC|COHERE)_/i,
  /^(GITHUB|GITLAB|BITBUCKET)_/i,
  /^(STRIPE|TWILIO|SENDGRID)_/i,
];

// Known API key prefixes
const API_KEY_PREFIXES = [
  'sk-',      // OpenAI
  'ghp_',     // GitHub PAT
  'gho_',     // GitHub OAuth
  'xoxb-',    // Slack bot
  'xoxp-',    // Slack user
  'AKIA',     // AWS access key
  'sk_live_', // Stripe live
  'sk_test_', // Stripe test
  'SG.',      // SendGrid
];

function detectSensitiveEnvVar(name: string, value: string): boolean {
  // Check name patterns
  for (const pattern of SENSITIVE_ENV_PATTERNS) {
    if (pattern.test(name)) return true;
  }
  // Check value prefixes (actual secrets)
  for (const prefix of API_KEY_PREFIXES) {
    if (value.startsWith(prefix)) return true;
  }
  return false;
}

function maskValue(value: string): string {
  if (value.length <= 4) return '****';
  return value.slice(0, 4) + '...';
}

// Scan ~/.claude.json for user identity information
function scanClaudeJson(home: string): ClaudeJsonIdentity {
  const claudeJsonPath = path.join(home, '.claude.json');
  try {
    const content = fs.readFileSync(claudeJsonPath, 'utf-8');
    const data = JSON.parse(content);
    return {
      email: data.oauthAccount?.emailAddress || null,
      displayName: data.oauthAccount?.displayName || null,
      organizationName: data.oauthAccount?.organizationName || null,
      accountUuid: data.oauthAccount?.accountUuid || null,
      organizationUuid: data.oauthAccount?.organizationUuid || null,
      userID: data.userID || null,
      firstStartTime: data.firstStartTime || null,
      numStartups: data.numStartups || 0,
    };
  } catch {
    return {
      email: null,
      displayName: null,
      organizationName: null,
      accountUuid: null,
      organizationUuid: null,
      userID: null,
      firstStartTime: null,
      numStartups: 0,
    };
  }
}

export async function scanIdentityExposure(): Promise<IdentityScanResult> {
  const home = getHomeDir();
  const claudeDir = path.join(home, '.claude');

  // Scan MCP server env vars
  const exposedEnvVars: ExposedEnvVar[] = [];
  const mcpConfigs = getMcpServerConfigs();

  for (const [serverName, config] of Object.entries(mcpConfigs)) {
    if (config.env) {
      for (const [varName, value] of Object.entries(config.env)) {
        if (detectSensitiveEnvVar(varName, value)) {
          // Determine risk level
          const isHighRisk = varName.toLowerCase().includes('key') ||
                            varName.toLowerCase().includes('secret') ||
                            varName.toLowerCase().includes('password') ||
                            API_KEY_PREFIXES.some(p => value.startsWith(p));

          exposedEnvVars.push({
            serverName,
            varName,
            valuePreview: maskValue(value),
            risk: isHighRisk ? 'high' : 'medium',
          });
        }
      }
    }
  }

  // Extract username from home path
  const username = home.match(/\/Users\/([^/]+)/)?.[1]
                || home.match(/\/home\/([^/]+)/)?.[1]
                || home.match(/C:\\Users\\([^\\]+)/)?.[1]
                || null;

  // Count projects
  const projectsDir = path.join(claudeDir, 'projects');
  let projectCount = 0;
  try {
    const entries = fs.readdirSync(projectsDir);
    projectCount = entries.length;
  } catch {
    // Directory doesn't exist or not readable
  }

  // Check history
  const historyExists = fs.existsSync(path.join(claudeDir, 'history.jsonl'));

  // Count sessions
  const sessionDir = path.join(claudeDir, 'session-env');
  let sessionCount = 0;
  try {
    const entries = fs.readdirSync(sessionDir);
    sessionCount = entries.length;
  } catch {
    // Directory doesn't exist or not readable
  }

  // Check for custom API key
  let hasCustomApiKey = false;
  try {
    const configPath = path.join(claudeDir, 'config.json');
    const configContent = fs.readFileSync(configPath, 'utf-8');
    const config = JSON.parse(configContent);
    hasCustomApiKey = !!(
      config.customApiKeyResponses?.approved &&
      config.customApiKeyResponses.approved.length > 0
    );
  } catch {
    // Config doesn't exist or not readable
  }

  // Check keys directory
  const hasKeysDirectory = fs.existsSync(path.join(claudeDir, 'keys'));

  // Scan ~/.claude.json for identity info
  const claudeJson = scanClaudeJson(home);

  const identity: IdentityExposure = {
    username,
    homeDir: '~',
    projectCount,
    historyExists,
    sessionCount,
    hasCustomApiKey,
    hasKeysDirectory,
    claudeJson,
  };

  return {
    exposedEnvVars,
    identity,
  };
}
