// Risk levels for categorizing threats
export type RiskLevel = "low" | "medium" | "high" | "critical";

// Output format options
export type OutputFormat = "terminal" | "json" | "html";

// Config scope - global or project-specific
export type ConfigScope =
  | { type: "global" }
  | { type: "project"; projectPath: string };

// CLI options parsed from command line
export interface CliOptions {
  format: OutputFormat;
  output?: string;
  color: boolean;
  verbose: boolean;
  openBrowser: boolean;
  scope: ConfigScope;
}

// Detected AI agent information
export interface AgentInfo {
  name: string;
  version?: string;
  configPath?: string;
  detected: boolean;
  permissions?: ToolPermissions;
  configFiles?: ConfigFileInfo[];
}

// Tool permission configuration
export interface ToolPermissions {
  allowed: string[];
  denied: string[];
  hasExplicitConfig: boolean;
}

// Config file that was scanned
export interface ConfigFileInfo {
  path: string;
  exists: boolean;
  purpose: string;
  whatItControls: string[];
  risk?: string;
}

// MCP server tool definition
export interface McpTool {
  name: string;
  description?: string;
}

// MCP server configuration
export interface McpServer {
  name: string;
  type: "stdio" | "http" | "sse" | "unknown";
  command?: string;
  args?: string[];
  url?: string;
  tools: McpTool[];
  risk: RiskLevel;
  riskReason?: string;
  // Educational content
  securityBrief?: string;
  securityDetail?: string;
  mitigation?: string;
}

// Sensitive file found during scan
export interface SensitiveFile {
  path: string;
  type: string;
  risk: RiskLevel;
  description: string;
  // Educational content
  whyItMatters?: string;
  attackScenario?: string;
  mitigation?: string;
}

// Filesystem access scope
export interface FilesystemAccess {
  readPaths: string[];
  writePaths: string[];
  sensitiveFiles: SensitiveFile[];
}

// Detected capabilities
export interface Capabilities {
  shellExecution: boolean;
  networkAccess: boolean;
  packageInstallation: boolean;
  backgroundProcesses: boolean;
  databaseAccess: boolean;
  fileSystemAccess: boolean;
}

// Recommendation for improving security
export interface Recommendation {
  priority: number;
  title: string;
  description: string;
  risk: RiskLevel;
  // Educational content
  howToFix?: string[];
  protectsAgainst?: string;
}

// Blast radius impact item
export interface BlastRadiusItem {
  category: string;
  description: string;
  risk: RiskLevel;
}

// Attack chain scenario
export interface AttackChainResult {
  name: string;
  scenario: string;
  impact: string;
}

// Complete scan results
export interface ScanResults {
  timestamp: string;
  agent: AgentInfo;
  mcpServers: McpServer[];
  filesystem: FilesystemAccess;
  capabilities: Capabilities;
  riskScore: number;
  blastRadius: BlastRadiusItem[];
  attackChains: AttackChainResult[];
  recommendations: Recommendation[];
  integrity: McpIntegrityResult[];
  identityExposure: IdentityScanResult;
  claudeInstallation: ClaudeInstallationIntegrity;
  configInventory?: ConfigInventory;
  effectiveConfig?: EffectiveConfig;
}

// Partial scan results for aggregation
export interface PartialScanResults {
  agent?: AgentInfo;
  mcpServers?: McpServer[];
  filesystem?: FilesystemAccess;
  capabilities?: Capabilities;
}

// Scanner interface for extensibility
export interface Scanner<T> {
  name: string;
  scan(): Promise<T>;
}

// Analyzer interface
export interface Analyzer<T, R> {
  analyze(data: T): R;
}

// Reporter interface
export interface Reporter {
  generate(results: ScanResults): string;
}

// Sandbox network configuration
export interface SandboxNetworkConfig {
  allowUnixSockets?: string[];
  allowLocalBinding?: boolean;
  httpProxyPort?: number;
  socksProxyPort?: number;
}

// Sandbox configuration for bash isolation
export interface SandboxConfig {
  enabled?: boolean;
  autoAllowBashIfSandboxed?: boolean;
  excludedCommands?: string[];
  allowUnsandboxedCommands?: boolean;
  network?: SandboxNetworkConfig;
  enableWeakerNestedSandbox?: boolean;
}

// MCP config from Claude Code settings
export interface ClaudeCodeConfig {
  mcpServers?: Record<string, McpServerConfig>;
  allowedTools?: string[];
  disallowedTools?: string[];
  permissions?: {
    allow?: string[];
    deny?: string[];
  };
  sandbox?: SandboxConfig;
}

export interface McpServerConfig {
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
}

// Pattern for detecting risky MCP servers
export interface McpRiskPattern {
  namePattern: string;
  toolPatterns: string[];
  risk: RiskLevel;
  reason: string;
}

// MCP integrity scan result
export type IntegrityStatus =
  | "new"
  | "unchanged"
  | "changed"
  | "missing"
  | "unhashable";

export interface McpIntegrityResult {
  serverName: string;
  targetPath: string | null;
  currentHash: string | null;
  baselineHash: string | null;
  status: IntegrityStatus;
  recordedAt: string | null;
}

// Claude Code installation integrity
export type ClaudeInstallationStatus =
  | "new"
  | "unchanged"
  | "changed"
  | "not-found";

export interface ClaudeInstallationIntegrity {
  installPath: string | null;
  version: string | null;
  cliHash: string | null;
  baselineHash: string | null;
  status: ClaudeInstallationStatus;
  recordedAt: string | null;
}

// Sensitive path pattern
export interface SensitivePathPattern {
  pattern: string;
  type: string;
  risk: RiskLevel;
  description: string;
}

// Exposed environment variable in MCP config
export interface ExposedEnvVar {
  serverName: string;
  varName: string;
  valuePreview: string;
  risk: "high" | "medium";
}

// ~/.claude.json identity information
export interface ClaudeJsonIdentity {
  email: string | null;
  displayName: string | null;
  organizationName: string | null;
  accountUuid: string | null;
  organizationUuid: string | null;
  userID: string | null;
  firstStartTime: string | null;
  numStartups: number;
}

// User identity exposure information
export interface IdentityExposure {
  username: string | null;
  homeDir: string;
  projectCount: number;
  historyExists: boolean;
  sessionCount: number;
  hasCustomApiKey: boolean;
  hasKeysDirectory: boolean;
  claudeJson: ClaudeJsonIdentity;
}

// Identity scan result
export interface IdentityScanResult {
  exposedEnvVars: ExposedEnvVar[];
  identity: IdentityExposure;
}

// Issue categories for grouping
export type IssueCategory = "credentials" | "mcp-servers";

// Simplified risk levels for UI (3-tier)
export type SimpleRisk = "high" | "medium" | "low";

// Security issue for remediation UI
export interface SecurityIssue {
  id: string;
  category: IssueCategory;
  type: "mcp-server" | "sensitive-file";
  title: string;
  description: string;
  target: string; // Path pattern or server name
  command?: string; // For MCP servers, the command
  risk: SimpleRisk;
  action: {
    type: "disable-mcp" | "deny-path";
    target: string;
  };
}

// Progress tracking by severity
export interface SeverityProgress {
  high: { total: number; fixed: number };
  medium: { total: number; fixed: number };
  low: { total: number; fixed: number };
}

// Extended scan results with issues
export interface ScanResultsWithIssues extends ScanResults {
  issues: SecurityIssue[];
}

// ============================================
// Configuration Inventory Types
// ============================================

// Platform types
export type Platform = "darwin" | "linux" | "win32";

// Configuration scope hierarchy (highest to lowest precedence)
export type ConfigScopeType = "managed" | "local" | "project" | "user";

// Managed settings (IT-deployed, highest precedence)
export interface ManagedSettings {
  // Permission overrides that can't be bypassed
  permissions?: {
    allow?: string[];
    deny?: string[];
    disableBypassPermissionsMode?: "disable";
  };
  // Sandbox enforcement
  sandbox?: SandboxConfig;
  // MCP server restrictions
  allowedMcpServers?: Array<{ serverName: string }>;
  deniedMcpServers?: Array<{ serverName: string }>;
  // Plugin marketplace restrictions
  strictKnownMarketplaces?: Array<{
    source: string;
    repo?: string;
    url?: string;
    package?: string;
    path?: string;
  }>;
  // Hook restrictions
  allowManagedHooksOnly?: boolean;
  disableAllHooks?: boolean;
  // Other managed settings
  forceLoginMethod?: "claudeai" | "console";
  forceLoginOrgUUID?: string;
  companyAnnouncements?: string[];
}

// Managed MCP configuration
export interface ManagedMcpConfig {
  mcpServers?: Record<string, McpServerConfig>;
}

// User settings (~/.claude/settings.json)
export interface UserSettings extends ClaudeCodeConfig {
  // Additional user-specific settings
  env?: Record<string, string>;
  hooks?: Record<string, unknown>;
  model?: string;
  language?: string;
  autoUpdatesChannel?: "stable" | "latest";
  cleanupPeriodDays?: number;
}

// Project settings (.claude/settings.json or .claude/settings.local.json)
export interface ProjectSettings extends ClaudeCodeConfig {
  env?: Record<string, string>;
  hooks?: Record<string, unknown>;
}

// User MCP config (~/.claude.json)
export interface UserMcpConfig {
  mcpServers?: Record<string, McpServerConfig>;
  // Per-project MCP servers
  projects?: Record<
    string,
    {
      mcpServers?: Record<string, McpServerConfig>;
      allowedTools?: string[];
    }
  >;
  // User preferences
  theme?: string;
  notificationSettings?: unknown;
  editorMode?: string;
}

// Project MCP config (.mcp.json)
export interface ProjectMcpConfig {
  mcpServers?: Record<string, McpServerConfig>;
}

// Managed configuration scope
export interface ManagedConfigScope {
  detected: boolean;
  path: string;
  settings: ManagedSettings | null;
  mcpConfig: ManagedMcpConfig | null;
  // What this managed config enforces
  enforces: {
    sandboxing: boolean;
    permissionRestrictions: boolean;
    mcpRestrictions: boolean;
    pluginRestrictions: boolean;
    hookRestrictions: boolean;
  };
}

// User configuration scope
export interface UserConfigScope {
  settingsPath: string;
  settings: UserSettings | null;
  mcpPath: string;
  mcpConfig: UserMcpConfig | null;
  agentsPath: string;
  agentCount: number;
  claudeMdPath: string;
  hasClaudeMd: boolean;
}

// Project configuration
export interface ProjectConfigInfo {
  path: string;
  name: string; // Directory name
  settings: {
    shared: ProjectSettings | null; // .claude/settings.json
    local: ProjectSettings | null; // .claude/settings.local.json
  };
  mcpConfig: ProjectMcpConfig | null; // .mcp.json
  hasClaudeMd: boolean; // CLAUDE.md or .claude/CLAUDE.md
  hasLocalClaudeMd: boolean; // CLAUDE.local.md
  // Timestamps for freshness
  lastModified: string | null;
}

// Complete configuration inventory
export interface ConfigInventory {
  // Scan metadata
  scannedAt: string;
  scanDurationMs: number;

  // Platform info
  platform: Platform;
  claudeCodeVersion: string | null;
  claudeCodeInstallPath: string | null;

  // IT-managed scope (highest precedence)
  managed: ManagedConfigScope;

  // User scope
  user: UserConfigScope;

  // Discovered projects
  projects: ProjectConfigInfo[];

  // Summary flags
  isITManaged: boolean; // True if managed config exists
  projectCount: number;
  hasUserConfig: boolean;
}

// Effective configuration for a specific context
// (computed by merging scopes according to precedence)
export interface EffectiveConfig {
  // Which project this is for (null = global/user level)
  projectPath: string | null;

  // Merged permissions
  permissions: {
    allow: string[];
    deny: string[];
    // Track where each rule came from
    sources: Array<{
      rule: string;
      scope: ConfigScopeType;
      type: "allow" | "deny";
    }>;
  };

  // Merged tool restrictions
  tools: {
    allowed: string[];
    disallowed: string[];
    sources: Array<{
      tool: string;
      scope: ConfigScopeType;
      type: "allowed" | "disallowed";
    }>;
  };

  // Merged MCP server restrictions (allowlist/denylist)
  mcpRestrictions: {
    allowed: string[];
    denied: string[];
    sources: Array<{
      server: string;
      scope: ConfigScopeType;
      type: "allowed" | "denied";
    }>;
  };

  // Merged sandbox config
  sandbox: SandboxConfig | null;
  sandboxSource: ConfigScopeType | null;

  // Merged MCP servers
  mcpServers: Record<string, McpServerConfig & { source: ConfigScopeType }>;

  // Hook restrictions
  hooks: {
    allowManagedHooksOnly: boolean;
    disableAllHooks: boolean;
    source: ConfigScopeType | null;
  };

  // Bypass mode
  bypassMode: {
    disabled: boolean;
    source: ConfigScopeType | null;
  };

  // What's shadowed (set at lower level but overridden by higher)
  shadowedRules: Array<{
    rule: string;
    setAt: ConfigScopeType;
    overriddenBy: ConfigScopeType;
    type: "allow" | "deny" | "mcp" | "sandbox" | "tool";
  }>;
}
