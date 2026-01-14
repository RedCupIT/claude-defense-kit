// Educational content for the security audit report
// Provides context about why findings matter and how to fix them

export interface EducationalContent {
  brief: string;
  detail: string;
  mitigation?: string;
}

// Sensitive file type education
export const SENSITIVE_FILE_EDUCATION: Record<string, EducationalContent> = {
  'SSH keys': {
    brief: 'Remote server access credentials',
    detail: `SSH private keys grant direct access to remote servers. An attacker could:
• Connect to any server you have SSH access to
• Pivot through internal networks and jump hosts
• Push malicious code to Git repositories
• Impersonate you in version control commits
• Access production systems and databases`,
    mitigation: 'Use SSH keys with strong passphrases. Consider using hardware security keys (YubiKey) or SSH certificates with short lifetimes.',
  },
  'SSH private key': {
    brief: 'Direct server access',
    detail: `This private key file grants authentication to remote servers without passwords. If compromised, an attacker gains persistent access to every system this key is authorized for.`,
    mitigation: 'Protect with a strong passphrase. Rotate keys periodically. Use ssh-agent with confirmation.',
  },
  'AWS credentials': {
    brief: 'Cloud infrastructure access',
    detail: `AWS access keys can control your entire cloud infrastructure. An attacker could:
• Spin up EC2 instances for crypto mining (you pay the bill)
• Access S3 buckets containing sensitive data
• Read secrets from Parameter Store and Secrets Manager
• Modify or delete production resources
• Pivot to other AWS accounts via cross-account roles
• Exfiltrate data through AWS services`,
    mitigation: 'Use IAM roles instead of long-lived keys. Enable MFA. Use AWS Organizations SCPs to limit blast radius.',
  },
  'AWS credentials file': {
    brief: 'AWS API access keys',
    detail: `Contains AWS access key ID and secret key pairs. These credentials often have broad permissions and don't expire unless rotated.`,
    mitigation: 'Rotate keys regularly. Use temporary credentials via AWS SSO or IAM roles. Set up CloudTrail alerts.',
  },
  'GCP credentials': {
    brief: 'Google Cloud access',
    detail: `Google Cloud credentials can access your GCP projects. An attacker could:
• Access Cloud Storage buckets
• Query BigQuery datasets
• Deploy malicious Cloud Functions
• Access Kubernetes Engine clusters
• Read secrets from Secret Manager`,
    mitigation: 'Use Workload Identity instead of service account keys. Enable audit logging. Use VPC Service Controls.',
  },
  'GCP service account': {
    brief: 'GCP service account key',
    detail: `Service account JSON keys provide programmatic access to Google Cloud APIs. These keys don't expire and are a common attack vector.`,
    mitigation: 'Prefer Workload Identity Federation. If keys are needed, rotate them regularly and use IAM Conditions.',
  },
  'Azure credentials': {
    brief: 'Azure cloud access',
    detail: `Azure credentials can access your Azure subscriptions. An attacker could:
• Access Azure Storage accounts
• Query Azure SQL databases
• Deploy to Azure App Services
• Access Key Vault secrets
• Modify Azure AD settings`,
    mitigation: 'Use Managed Identities. Enable Azure AD Conditional Access. Monitor with Azure Sentinel.',
  },
  'Kubernetes config': {
    brief: 'Cluster admin access',
    detail: `Kubeconfig files often contain cluster admin credentials. An attacker could:
• Deploy malicious containers
• Access secrets stored in the cluster
• Modify running deployments
• Pivot to other namespaces and clusters
• Exfiltrate data through pod networking`,
    mitigation: 'Use OIDC authentication instead of static tokens. Implement RBAC with least privilege. Enable audit logging.',
  },
  'Kubeconfig': {
    brief: 'Kubernetes cluster credentials',
    detail: `Contains authentication tokens or certificates for Kubernetes clusters. Often grants admin-level access across multiple clusters.`,
    mitigation: 'Remove clusters you no longer need. Use context-specific authentication. Enable cluster audit logs.',
  },
  'Docker config': {
    brief: 'Container registry access',
    detail: `Docker config contains credentials for container registries. An attacker could:
• Pull private images containing proprietary code
• Push malicious images to your registries
• Conduct supply chain attacks via image poisoning`,
    mitigation: 'Use credential helpers instead of storing passwords. Enable registry vulnerability scanning.',
  },
  'GPG keys': {
    brief: 'Encryption and signing keys',
    detail: `GPG private keys can decrypt your encrypted files and sign data as you. An attacker could:
• Decrypt any GPG-encrypted files or emails
• Sign malicious code or documents as you
• Forge signed Git commits`,
    mitigation: 'Use subkeys for daily operations. Store master key offline. Enable key expiration.',
  },
  'Git config': {
    brief: 'Git identity and settings',
    detail: `Git configuration may contain credential helpers, tokens, or identity information used for repository access.`,
    mitigation: 'Use credential managers with short-lived tokens. Enable Git signing.',
  },
  'Git credentials': {
    brief: 'Repository access tokens',
    detail: `Git credential files store passwords or tokens for repository access. An attacker could:
• Push malicious code to your repositories
• Access private repositories
• Modify repository settings
• Delete branches or releases`,
    mitigation: 'Use SSH keys or short-lived tokens. Enable 2FA on your Git hosting provider.',
  },
  'Environment file': {
    brief: 'Application secrets',
    detail: `Environment files typically contain sensitive configuration:
• Database connection strings with passwords
• API keys for third-party services
• OAuth client secrets
• Encryption keys
• Internal service credentials
These secrets often grant access to production systems.`,
    mitigation: 'Use a secrets manager (Vault, AWS Secrets Manager). Never commit .env files. Use different secrets per environment.',
  },
  'npm config': {
    brief: 'Package registry access',
    detail: `npm configuration may contain authentication tokens for package registries. An attacker could:
• Publish malicious versions of your packages
• Access private packages
• Conduct supply chain attacks`,
    mitigation: 'Use npm token with minimal scopes. Enable 2FA for publishing. Use npm audit.',
  },
  'PyPI config': {
    brief: 'Python package registry access',
    detail: `PyPI configuration contains credentials for uploading Python packages. An attacker could publish malicious package versions.`,
    mitigation: 'Use API tokens with minimal scope. Enable 2FA. Use trusted publishing with GitHub Actions.',
  },
  'Password store': {
    brief: 'Password manager vault',
    detail: `The password store contains GPG-encrypted passwords. If the GPG key is also accessible, all passwords are compromised.`,
    mitigation: 'Use a strong GPG passphrase. Consider hardware key storage.',
  },
  'Netrc credentials': {
    brief: 'Network service credentials',
    detail: `.netrc files contain plaintext credentials for FTP, HTTP, and other services. Often used by build tools and scripts.`,
    mitigation: 'Use service-specific credential mechanisms instead. Restrict file permissions.',
  },
  'Terraform state': {
    brief: 'Infrastructure state with secrets',
    detail: `Terraform state files contain the current state of your infrastructure, including sensitive values like passwords and API keys in plaintext.`,
    mitigation: 'Use remote state with encryption. Enable state locking. Never commit state files.',
  },
  'Terraform vars': {
    brief: 'Infrastructure variables',
    detail: `Terraform variable files may contain sensitive values used to provision infrastructure.`,
    mitigation: 'Use environment variables or a secrets manager for sensitive values.',
  },
  'Secrets file': {
    brief: 'Application secrets',
    detail: `Files named "secrets" typically contain sensitive credentials in YAML, JSON, or other formats.`,
    mitigation: 'Use a proper secrets management solution. Never commit these files.',
  },
  'Credentials file': {
    brief: 'Authentication credentials',
    detail: `Generic credentials files often contain multiple sets of authentication data for various services.`,
    mitigation: 'Audit what credentials are stored. Migrate to a secrets manager.',
  },
  'Private key': {
    brief: 'Cryptographic private key',
    detail: `PEM private key files are used for TLS/SSL, code signing, and authentication. Compromise allows impersonation and decryption.`,
    mitigation: 'Protect with strong passphrases. Use hardware security modules for critical keys.',
  },
};

// MCP server type education
export const MCP_EDUCATION: Record<string, EducationalContent> = {
  shell: {
    brief: 'Grants unrestricted command execution',
    detail: `Shell access is the highest-risk MCP capability. A compromised agent could:
• Execute any command your user can run
• Install backdoors, malware, or crypto miners
• Exfiltrate files to external servers
• Modify system configurations and cron jobs
• Read any file your user has access to
• Establish persistent access via SSH keys or services
• Pivot to other systems on your network`,
    mitigation: 'Remove shell MCP if not essential. If needed, use an allowlist of specific commands.',
  },
  bash: {
    brief: 'Full bash shell access',
    detail: `Bash execution provides complete shell access with all its features including pipes, redirects, and scripting capabilities.`,
    mitigation: 'Replace with a restricted command runner that only allows specific operations.',
  },
  terminal: {
    brief: 'Interactive terminal access',
    detail: `Terminal access enables interactive command execution, potentially with TTY features that could bypass some security controls.`,
    mitigation: 'Prefer non-interactive command execution with explicit allowlists.',
  },
  filesystem: {
    brief: 'Read and write files on your system',
    detail: `Filesystem access allows reading, writing, and modifying files. An attacker could:
• Read sensitive configuration files and credentials
• Modify source code to inject backdoors
• Alter build scripts for supply chain attacks
• Access personal documents and data
• Plant malicious files for later execution`,
    mitigation: 'Scope filesystem access to specific project directories only.',
  },
  postgres: {
    brief: 'PostgreSQL database access',
    detail: `Database access enables querying and modifying data. An attacker could:
• Exfiltrate sensitive user data and PII
• Modify or delete records
• Access password hashes for offline cracking
• Pivot to other databases via db_link
• Execute functions with elevated privileges`,
    mitigation: 'Use a read-only database user. Restrict to specific tables/schemas.',
  },
  mysql: {
    brief: 'MySQL database access',
    detail: `MySQL access enables database queries and modifications. Risk includes data theft, modification, and potential command execution via UDFs.`,
    mitigation: 'Use least-privilege database credentials. Enable query logging.',
  },
  sqlite: {
    brief: 'SQLite database access',
    detail: `SQLite access allows reading and modifying local database files, which may contain application data, credentials, or browser history.`,
    mitigation: 'Restrict to specific database files. Use read-only mode when possible.',
  },
  git: {
    brief: 'Git repository operations',
    detail: `Git access allows repository operations including commits and pushes. Could be used to inject malicious code or steal source code.`,
    mitigation: 'Use read-only Git access when possible. Review all changes before pushing.',
  },
  github: {
    brief: 'GitHub API access',
    detail: `GitHub API access can interact with repositories, issues, PRs, and potentially organization settings depending on token scope.`,
    mitigation: 'Use fine-grained personal access tokens with minimal permissions.',
  },
  browser: {
    brief: 'Web browser automation',
    detail: `Browser automation can navigate to pages, click elements, and read page content. Could be used for credential theft or unauthorized actions.`,
    mitigation: 'Limit to specific domains. Avoid automating authenticated sessions.',
  },
  puppeteer: {
    brief: 'Full browser control with JS execution',
    detail: `Puppeteer enables complete browser automation including JavaScript execution, which can access browser storage, cookies, and perform authenticated actions.`,
    mitigation: 'Use isolated browser profiles. Clear sessions after use.',
  },
  fetch: {
    brief: 'HTTP request capabilities',
    detail: `Network fetch allows making HTTP requests. Could be used for:
• Exfiltrating data to external servers
• Accessing internal services
• Command and control communication`,
    mitigation: 'Restrict to specific domains. Monitor outbound traffic.',
  },
  http: {
    brief: 'HTTP client for network requests',
    detail: `HTTP access enables web requests that could exfiltrate data or communicate with attacker infrastructure.`,
    mitigation: 'Use domain allowlists. Log all outbound requests.',
  },
};

// Capability education
export const CAPABILITY_EDUCATION: Record<string, EducationalContent> = {
  shellExecution: {
    brief: 'Can run any system command',
    detail: `Shell execution is the most dangerous capability. It effectively gives the AI agent the same access as your user account. This includes:
• Running arbitrary programs
• Accessing the network
• Reading/writing any accessible file
• Installing software
• Modifying system configuration
All other capabilities become redundant when shell access is available.`,
    mitigation: 'Remove shell MCP servers. If shell access is required, use a restricted command runner with an explicit allowlist.',
  },
  networkAccess: {
    brief: 'Can make outbound connections',
    detail: `Network access enables the agent to communicate with external servers. Risks include:
• Data exfiltration to attacker-controlled servers
• Command and control communication
• Accessing internal network services
• Downloading and executing payloads`,
    mitigation: 'Use network allowlists. Monitor outbound connections. Consider a proxy.',
  },
  packageInstallation: {
    brief: 'Can install software packages',
    detail: `Package installation allows adding new dependencies. This is a supply chain attack vector:
• Installing malicious packages with similar names (typosquatting)
• Packages with post-install scripts that execute code
• Backdoored versions of legitimate packages`,
    mitigation: 'Use lockfiles. Review new dependencies. Consider using a package proxy.',
  },
  databaseAccess: {
    brief: 'Can query and modify databases',
    detail: `Database access exposes your data layer. Depending on permissions:
• Read sensitive data (PII, credentials, financial data)
• Modify or delete records
• Access audit logs
• Potentially escalate via database features`,
    mitigation: 'Use read-only credentials. Restrict to non-sensitive tables. Enable query logging.',
  },
  backgroundProcesses: {
    brief: 'Can spawn persistent processes',
    detail: `Background process capability allows starting processes that continue after the session ends. Could be used for:
• Establishing persistence
• Running crypto miners
• Maintaining backdoor access`,
    mitigation: 'Audit running processes. Use process monitoring. Restrict process spawning.',
  },
  fileSystemAccess: {
    brief: 'Can read and write files',
    detail: `Filesystem access allows reading sensitive files and writing malicious content:
• Reading credentials and configuration
• Modifying source code
• Planting malware
• Accessing personal documents`,
    mitigation: 'Restrict to specific directories. Use read-only access where possible.',
  },
};

// Attack chain templates for combining risks
export interface AttackChain {
  name: string;
  requirements: string[];
  scenario: string;
  impact: string;
}

export const ATTACK_CHAINS: AttackChain[] = [
  {
    name: 'Cloud Account Takeover',
    requirements: ['shellExecution', 'AWS credentials'],
    scenario: 'Exfiltrate AWS credentials via shell → Use keys to access S3 buckets → Download database backups → Pivot to other AWS services',
    impact: 'Full access to cloud infrastructure, potential data breach, financial impact from resource abuse',
  },
  {
    name: 'Supply Chain Attack',
    requirements: ['packageInstallation', 'Git credentials'],
    scenario: 'Install malicious dev dependency → Modify build scripts → Push backdoored code → Compromise downstream users',
    impact: 'Malicious code distributed to users of your packages, reputation damage',
  },
  {
    name: 'Lateral Movement',
    requirements: ['shellExecution', 'SSH keys'],
    scenario: 'Read SSH private keys → Connect to other servers → Establish persistence → Pivot through internal network',
    impact: 'Compromise of multiple systems, access to internal services',
  },
  {
    name: 'Data Exfiltration',
    requirements: ['databaseAccess', 'networkAccess'],
    scenario: 'Query database for sensitive data → Exfiltrate via HTTP to external server → Sell or leak data',
    impact: 'Data breach, regulatory penalties, customer trust loss',
  },
  {
    name: 'Cryptomining',
    requirements: ['shellExecution', 'AWS credentials'],
    scenario: 'Use AWS credentials to spin up GPU instances → Install crypto miners → Run until detected',
    impact: 'Unexpected cloud bills potentially in thousands of dollars',
  },
  {
    name: 'Source Code Theft',
    requirements: ['fileSystemAccess', 'networkAccess'],
    scenario: 'Read source code from accessible directories → Archive and compress → Exfiltrate via HTTP',
    impact: 'Intellectual property theft, competitive disadvantage',
  },
  {
    name: 'Credential Harvesting',
    requirements: ['fileSystemAccess', 'Environment file'],
    scenario: 'Read .env files across projects → Extract API keys and passwords → Use for further access',
    impact: 'Access to third-party services, potential account takeovers',
  },
  {
    name: 'Kubernetes Cluster Compromise',
    requirements: ['shellExecution', 'Kubernetes config'],
    scenario: 'Read kubeconfig → Deploy privileged container → Escape to node → Access cluster secrets',
    impact: 'Full cluster compromise, access to all deployed applications',
  },
];

// Config file education
export interface ConfigFileEducation {
  purpose: string;
  whatItControls: string[];
  risk: string;
}

export const CONFIG_FILE_EDUCATION: Record<string, ConfigFileEducation> = {
  'settings.json': {
    purpose: 'Main Claude Code configuration file',
    whatItControls: [
      'MCP server definitions (what tools Claude can use)',
      'Allowed and denied tool lists',
      'Default behaviors and preferences',
    ],
    risk: 'Defines what capabilities Claude Code has access to. If modified, could grant additional permissions.',
  },
  'settings.local.json': {
    purpose: 'Local Claude Code settings override',
    whatItControls: [
      'Machine-specific configuration overrides',
      'Local MCP server additions',
    ],
    risk: 'Can override security settings from the main config file.',
  },
  'claude_desktop_config.json': {
    purpose: 'Claude Desktop application settings',
    whatItControls: [
      'MCP servers for Claude Desktop app',
      'Desktop-specific preferences',
    ],
    risk: 'Controls MCP access for the desktop application. Separate from CLI config.',
  },
  'projects.json': {
    purpose: 'Per-project configuration registry',
    whatItControls: [
      'Project-specific settings paths',
      'Project directory associations',
    ],
    risk: 'Tracks which projects have custom configurations.',
  },
  '.claude.json': {
    purpose: 'Legacy/simple configuration file',
    whatItControls: [
      'Basic Claude settings',
      'Can contain MCP server definitions',
    ],
    risk: 'Alternative config location that may be overlooked during security audits.',
  },
  '.claude': {
    purpose: 'Claude Code configuration directory',
    whatItControls: [
      'Contains all Claude Code config files',
      'Project settings and caches',
    ],
    risk: 'Main directory for all Claude Code configuration.',
  },
  'config.json': {
    purpose: 'Alternative configuration file',
    whatItControls: [
      'Same as settings.json',
      'Used in some installations',
    ],
    risk: 'May contain MCP servers and permissions.',
  },
};

// Claude Code permission explanation
export const CLAUDE_CODE_PERMISSIONS_EXPLANATION = `
## How Claude Code Permissions Work

Claude Code operates within a permission system that controls what the AI agent can do:

### Tool Permissions
- **Allowed Tools**: Explicitly permitted tools that Claude Code can use
- **Denied Tools**: Tools that are blocked from use
- If no explicit permissions are set, Claude Code may have broad access

### MCP Servers
MCP (Model Context Protocol) servers extend Claude Code's capabilities by providing additional tools.
Each MCP server can expose multiple tools with varying levels of risk.

### File Access
Claude Code can typically access files within your project directory and home directory,
unless explicitly restricted.

### Best Practices
1. Review MCP servers regularly - remove any you don't actively use
2. Deny high-risk tools like shell/bash when not needed
3. Scope file access to specific project directories
4. Use read-only modes where possible
`;
