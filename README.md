# Claude Defense Kit

> **Claude Code is powerful—but with great power comes great attack surface.** If Claude gets prompt-injected, what can an attacker access? Your SSH keys? AWS credentials? Database connections? Claude Defense Kit scans your installation, shows you the blast radius, and lets you lock it down with one click.

## Quick Start

Until we publish to npm, run locally:

```bash
git clone https://github.com/gobeyondidentity/claude-defense-kit.git
cd claude-defense-kit
npm install
npm run build
npm start
```

This starts an interactive web app at http://localhost:3847 that:

- Scans your Claude Code configuration for security issues
- Shows severity-based findings (High/Medium/Low)
- Enables one-click remediation of each issue

## Installation

Once published to npm, you'll be able to run:

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

# Scan a specific project's configuration
claude-defense-kit -p /path/to/project

```

### Options

```
-p, --project <path>  Target a specific project directory (edits project-level config)
--help                Display help
--version             Display version
```

## Configuration Scopes

Claude Code supports two configuration levels, and Claude Defense Kit can scan and remediate both:

### Global Configuration (Default)

By default, Claude Defense Kit scans and modifies your global configuration at:

```
~/.claude/settings.json
```

This affects Claude Code's behavior across all projects.

### Project Configuration

To scan and harden a specific project's configuration, use the `-p` flag:

```bash
claude-defense-kit -p /path/to/your/project
```

This targets the project-level configuration at:

```
<project>/.claude/settings.json
```

Project-level settings override global settings, allowing you to have stricter security for sensitive projects while keeping a more permissive global config for general use.

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

The tool modifies your Claude Code settings to:

- Deny access to sensitive file paths
- Disable risky MCP servers
- Block dangerous bash commands (curl, wget, nc, ssh, scp)
- Configure sandbox settings
- Disable specific tools (Bash, Write, Edit, WebFetch)

All changes can be undone with the "Undo" button.

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
