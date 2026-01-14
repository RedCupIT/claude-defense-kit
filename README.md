# Claude Defense Kit

Secure your Claude Code installation against prompt injection attacks.

This tool scans your Claude Code configuration and shows what could be accessed
if Claude Code is prompt-injected, with one-click remediation to lock it down.

## Quick Start

```bash
npx claude-defense-kit
```

This starts an interactive web app at http://localhost:3847 that:

- Scans your Claude Code configuration for security issues
- Shows severity-based findings (High/Medium/Low)
- Enables one-click remediation of each issue

## Installation

```bash
# Run directly (no install required)
npx claude-defense-kit

# Or install globally
npm install -g claude-defense-kit
```

## Usage

```bash
# Interactive mode (default) - starts web server with live remediation
claude-defense-kit

# Terminal output (static, no server)
claude-defense-kit --no-open

# JSON output to stdout
claude-defense-kit --format json

# Save static HTML report to file
claude-defense-kit --format html -o report.html

# Verbose mode
claude-defense-kit --verbose
```

### Options

```
-f, --format <type>  Output format: terminal, json, html (default: terminal)
-o, --output <file>  Write output to file instead of stdout
--no-open            Don't open browser (by default opens HTML report in browser)
--no-color           Disable colored output
--verbose            Show detailed scan progress
--help               Display help
--version            Display version
```

## What It Scans

### Claude Code Detection

- Detects Claude Code installation and version
- Parses configuration files from `~/.claude/`
- Tracks installation integrity via file hashing

### MCP Server Analysis

- Enumerates configured MCP servers
- Identifies tools/capabilities each server exposes
- Categorizes risk level (critical/high/medium/low)
- Detects changes to MCP server scripts

### Credential Exposure

- Scans for sensitive files Claude Code can access:
  - SSH keys (`~/.ssh/`)
  - Cloud credentials (`~/.aws/`, `~/.config/gcloud/`, `~/.azure/`)
  - Environment files (`.env`, `.env.local`, etc.)
  - Git credentials (`~/.gitconfig`, `.git-credentials`, `.netrc`)
  - Package manager tokens (`~/.npmrc`, `~/.pypirc`)

### Capability Analysis

- Shell command execution (Bash tool)
- Network request capabilities (WebFetch)
- File read/write permissions
- Package installation permissions

## Remediation

The tool modifies `~/.claude/settings.json` to:

- Deny access to sensitive file paths
- Disable risky MCP servers
- Block dangerous bash commands (curl, wget, nc, ssh, scp)
- Configure sandbox settings
- Disable specific tools (Bash, Write, Edit, WebFetch)

All changes can be undone with the "Undo" button.

## Output

The tool generates a risk score (0-100) and categorizes findings:

- **Critical** (75-100): Immediate action recommended
- **High** (50-74): Significant exposure detected
- **Medium** (25-49): Some concerns identified
- **Low** (0-24): Minimal exposure

## Privacy

This tool runs entirely locally. No data is uploaded or sent anywhere.

## Supported Platforms

- macOS
- Linux
- Windows

## Development

```bash
npm install
npm run build
npm start        # Opens http://localhost:3847

# Or run without building
npm run dev
```

Requires Node.js 18+.

## License

MIT
