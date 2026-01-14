// Simple glob-like pattern matching
export function matchPattern(pattern: string, value: string): boolean {
  // Convert glob pattern to regex
  const regexPattern = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&") // Escape special regex chars
    .replace(/\*\*/g, "<<<GLOBSTAR>>>") // Temporarily replace **
    .replace(/\*/g, "[^/]*") // * matches anything except /
    .replace(/<<<GLOBSTAR>>>/g, ".*") // ** matches anything including /
    .replace(/\?/g, "."); // ? matches single char

  const regex = new RegExp(`^${regexPattern}$`, "i");
  return regex.test(value);
}

// Normalize path for comparison (expand ~ to home dir, remove trailing slashes)
export function normalizePath(filepath: string): string {
  let normalized = filepath;

  // Expand ~ to home directory
  if (normalized.startsWith("~/")) {
    const home = process.env.HOME || "/home/user";
    normalized = home + normalized.slice(1);
  } else if (normalized === "~") {
    normalized = process.env.HOME || "/home/user";
  }

  // Remove trailing slashes
  normalized = normalized.replace(/\/+$/, "");

  return normalized;
}

// Check if a file path is covered by a deny rule pattern
// Pattern format: "Read(~/.ssh/**)" or just "~/.ssh/**"
export function isPathCoveredByDenyRule(
  filePath: string,
  denyRules: string[]
): string | null {
  const normalizedPath = normalizePath(filePath);

  for (const rule of denyRules) {
    // Extract pattern from rule like "Read(~/.ssh/**)"
    const match = rule.match(/^(?:Read|Write|Edit)\((.+)\)$/);
    const pattern = match ? match[1] : rule;

    // Normalize the pattern
    const normalizedPattern = normalizePath(pattern);

    // Check if the path matches the pattern
    if (matchPattern(normalizedPattern, normalizedPath)) {
      return rule; // Return the rule that covers this path
    }
  }

  return null; // Not covered by any rule
}

// Get all deny rules that would cover a given path
export function getCoveringDenyRules(
  filePath: string,
  denyRules: string[]
): string[] {
  const normalizedPath = normalizePath(filePath);
  const coveringRules: string[] = [];

  for (const rule of denyRules) {
    const match = rule.match(/^(?:Read|Write|Edit)\((.+)\)$/);
    const pattern = match ? match[1] : rule;
    const normalizedPattern = normalizePath(pattern);

    if (matchPattern(normalizedPattern, normalizedPath)) {
      coveringRules.push(rule);
    }
  }

  return coveringRules;
}

// Suggest directory-level rules for a file path
export function suggestDirectoryRules(filePath: string): string[] {
  const suggestions: string[] = [];
  const normalizedPath = normalizePath(filePath);

  // Get the directory containing the file
  const lastSlash = normalizedPath.lastIndexOf("/");
  if (lastSlash > 0) {
    const directory = normalizedPath.slice(0, lastSlash);

    // Suggest blocking the immediate directory
    suggestions.push(`Read(${directory}/**)`);

    // If it's a hidden directory (like .ssh), suggest blocking it from anywhere
    const dirName = directory.split("/").pop();
    if (dirName && dirName.startsWith(".")) {
      suggestions.push(`Read(**/${dirName}/**)`);
    }
  }

  // Suggest blocking the specific file
  suggestions.push(`Read(${normalizedPath})`);

  return suggestions;
}

// Check if filename matches any of the patterns
export function matchesAny(filename: string, patterns: string[]): boolean {
  return patterns.some((p) => matchPattern(p, filename));
}

// Extract filename from path
export function getFilename(filepath: string): string {
  const parts = filepath.split(/[/\\]/);
  return parts[parts.length - 1] || "";
}

// Common secret file patterns
export const SECRET_FILE_PATTERNS = [
  // SSH
  "id_rsa",
  "id_rsa.pub",
  "id_ed25519",
  "id_ed25519.pub",
  "id_dsa",
  "id_ecdsa",
  "known_hosts",
  "authorized_keys",

  // Environment files
  ".env",
  ".env.*",
  "*.env",
  ".envrc",

  // Credentials
  "credentials",
  "credentials.json",
  "credentials.yaml",
  "credentials.yml",

  // AWS
  "aws_credentials",
  "config", // in .aws directory

  // GCP
  "application_default_credentials.json",
  "*.json", // service account keys

  // Azure
  "azure.json",
  "azureProfile.json",

  // Git
  ".git-credentials",
  ".gitconfig",
  ".netrc",

  // Package managers
  ".npmrc",
  ".pypirc",
  ".gemrc",
  ".nuget",

  // Kubernetes
  "kubeconfig",
  "config", // in .kube directory

  // Docker
  "config.json", // in .docker directory

  // Database
  ".pgpass",
  ".my.cnf",
  ".mongorc.js",

  // GPG
  "secring.gpg",
  "trustdb.gpg",

  // Tokens/API keys
  "*token*",
  "*secret*",
  "*apikey*",
  "*api_key*",
  "*password*",
];

// Patterns for MCP tools that indicate high risk
export const HIGH_RISK_TOOL_PATTERNS = [
  "*shell*",
  "*exec*",
  "*command*",
  "*bash*",
  "*terminal*",
  "*run*",
  "*database*",
  "*sql*",
  "*query*",
];

// Patterns for MCP tools that indicate medium risk
export const MEDIUM_RISK_TOOL_PATTERNS = [
  "*write*",
  "*create*",
  "*delete*",
  "*modify*",
  "*update*",
  "*remove*",
  "*file*",
  "*network*",
  "*http*",
  "*fetch*",
  "*request*",
];
