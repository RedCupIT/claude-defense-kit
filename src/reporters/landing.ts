// Landing page for Claude Defense Kit

export function generateLandingPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Claude Defense Kit | Secure Your Claude Code Installation</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .gradient-text {
      background: linear-gradient(135deg, #58a6ff 0%, #f0883e 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .code-block {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
    }
    .feature-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      transition: border-color 0.2s ease;
    }
    .feature-card:hover {
      border-color: #58a6ff;
    }
  </style>
</head>
<body class="bg-[#0d1117] text-[#c9d1d9] min-h-screen font-sans">

  <!-- Hero Section -->
  <header class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16 text-center">
      <h1 class="text-4xl md:text-5xl font-bold mb-6">
        <span class="gradient-text">Claude Defense Kit</span>
      </h1>
      <p class="text-xl text-[#8b949e] mb-10 max-w-2xl mx-auto">
        Secure your Claude Code installation against prompt injection attacks.
        See what's at risk and lock it down with one click.
      </p>

      <!-- CTA Section -->
      <div class="code-block p-6 md:p-8 max-w-2xl mx-auto text-left">
        <div class="text-lg font-semibold mb-6 text-center">Get Started</div>

        <!-- Step 1 -->
        <div class="mb-6">
          <div class="flex items-center gap-3 mb-2">
            <span class="w-6 h-6 rounded-full bg-[#58a6ff] text-white text-sm flex items-center justify-center font-bold">1</span>
            <span class="font-semibold">Run the scanner</span>
          </div>
          <div class="ml-9">
            <div class="bg-[#0d1117] border border-[#30363d] rounded px-4 py-2 font-mono text-sm flex items-center justify-between">
              <span><span class="text-[#8b949e]">$</span> npx claude-defense-kit</span>
              <button onclick="navigator.clipboard.writeText('npx claude-defense-kit')"
                class="text-[#8b949e] hover:text-[#58a6ff] transition text-xs">Copy</button>
            </div>
          </div>
        </div>

        <!-- Step 2 -->
        <div class="mb-6">
          <div class="flex items-center gap-3 mb-2">
            <span class="w-6 h-6 rounded-full bg-[#58a6ff] text-white text-sm flex items-center justify-center font-bold">2</span>
            <span class="font-semibold">Opens an interactive report in your browser</span>
          </div>
          <div class="ml-9 text-sm text-[#8b949e]">
            <div class="flex items-start gap-2 mb-1">
              <span class="text-[#3fb950]">&#8226;</span>
              <span>See what MCP servers, tools, and files are exposed</span>
            </div>
            <div class="flex items-start gap-2">
              <span class="text-[#3fb950]">&#8226;</span>
              <span>View attack scenarios specific to your config</span>
            </div>
          </div>
        </div>

        <!-- Step 3 -->
        <div class="mb-6">
          <div class="flex items-center gap-3 mb-2">
            <span class="w-6 h-6 rounded-full bg-[#58a6ff] text-white text-sm flex items-center justify-center font-bold">3</span>
            <span class="font-semibold">Fix issues with one click</span>
          </div>
          <div class="ml-9 text-sm text-[#8b949e]">
            <div class="flex items-start gap-2 mb-1">
              <span class="text-[#3fb950]">&#8226;</span>
              <span>Disable risky MCP servers</span>
            </div>
            <div class="flex items-start gap-2 mb-1">
              <span class="text-[#3fb950]">&#8226;</span>
              <span>Block sensitive file paths</span>
            </div>
            <div class="flex items-start gap-2">
              <span class="text-[#3fb950]">&#8226;</span>
              <span>Restrict dangerous bash commands</span>
            </div>
          </div>
        </div>

        <!-- Privacy note -->
        <div class="text-center text-sm text-[#8b949e] border-t border-[#30363d] pt-5">
          All analysis runs locally. No data leaves your machine.
        </div>

        <!-- Badges -->
        <div class="flex flex-wrap justify-center gap-4 mt-4 text-xs">
          <span class="px-3 py-1 bg-[#21262d] rounded-full text-[#8b949e]">Runs in 10 seconds</span>
          <span class="px-3 py-1 bg-[#21262d] rounded-full text-[#8b949e]">No installation required</span>
          <span class="px-3 py-1 bg-[#21262d] rounded-full text-[#8b949e]">One-click fixes</span>
        </div>

        <!-- Buttons -->
        <div class="flex flex-col sm:flex-row gap-3 justify-center mt-6">
          <a href="https://github.com/gobeyondidentity/claude-defense-kit" target="_blank"
            class="px-5 py-2.5 bg-[#21262d] text-[#c9d1d9] border border-[#30363d] rounded-lg font-semibold hover:bg-[#30363d] transition text-center text-sm">
            View on GitHub
          </a>
        </div>
      </div>
    </div>
  </header>

  <!-- The Problem Section -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-2">We've Seen This Before</h2>
      <p class="text-[#8b949e] mb-8">
        The agent architecture is structurally identical to command-and-control
        malware. The difference is intent, not design.
      </p>

      <div class="grid md:grid-cols-2 gap-8 mb-8">
        <!-- C2 Architecture -->
        <div class="code-block p-4">
          <div class="text-xs font-semibold text-[#f85149] uppercase mb-3">Traditional Botnet</div>
          <pre class="text-sm text-[#8b949e] whitespace-pre-wrap">Command source: C2 server
Executor:       Bot/malware
Instructions:   Encoded commands
System access:  Shell, APIs, files
Exfiltration:   Back to C2
Persistence:    Registry, cron</pre>
        </div>

        <!-- Agent Architecture -->
        <div class="code-block p-4">
          <div class="text-xs font-semibold text-[#58a6ff] uppercase mb-3">Claude Code</div>
          <pre class="text-sm text-[#8b949e] whitespace-pre-wrap">Command source: LLM (via context)
Executor:       Agent program
Instructions:   Natural language
System access:  Tools (bash, HTTP)
Exfiltration:   Tool results, context
Persistence:    MCP server, plugin</pre>
        </div>
      </div>

      <p class="text-sm text-[#8b949e]">
        Same pattern. Different runtime.
      </p>
    </div>
  </section>

  <!-- Classic Vulnerabilities Reborn -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-6">Classic Vulnerabilities, Reborn</h2>

      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-[#30363d]">
              <th class="text-left py-3 px-4 text-[#8b949e] font-semibold">Classic</th>
              <th class="text-left py-3 px-4 text-[#8b949e] font-semibold">Agentic</th>
            </tr>
          </thead>
          <tbody>
            <tr class="border-b border-[#21262d]">
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">SQL Injection</span>
                <div class="text-xs text-[#8b949e] mt-1">Untrusted input in SQL query</div>
              </td>
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Prompt Injection</span>
                <div class="text-xs text-[#8b949e] mt-1">Untrusted data in LLM context</div>
              </td>
            </tr>
            <tr class="border-b border-[#21262d]">
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Confused Deputy</span>
                <div class="text-xs text-[#8b949e] mt-1">Service tricked into misusing permissions</div>
              </td>
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Agent as Deputy</span>
                <div class="text-xs text-[#8b949e] mt-1">Claude Code uses your creds for attacker's requests</div>
              </td>
            </tr>
            <tr class="border-b border-[#21262d]">
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Supply Chain</span>
                <div class="text-xs text-[#8b949e] mt-1">Malicious npm package</div>
              </td>
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">MCP Supply Chain</span>
                <div class="text-xs text-[#8b949e] mt-1">Malicious MCP server or plugin</div>
              </td>
            </tr>
            <tr>
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Data Exfiltration</span>
                <div class="text-xs text-[#8b949e] mt-1">SQL dump, XSS cookie theft</div>
              </td>
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Context Leakage</span>
                <div class="text-xs text-[#8b949e] mt-1">Tool call sends data to external endpoint</div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- What We Scan -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-6">What We Scan</h2>

      <div class="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">MCP Servers</div>
          <p class="text-sm text-[#8b949e]">Tool inventory, exposed environment variables, command access</p>
        </div>
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">Filesystem Access</div>
          <p class="text-sm text-[#8b949e]">Read/write paths, sensitive files in accessible directories</p>
        </div>
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">Credentials</div>
          <p class="text-sm text-[#8b949e]">API keys, tokens, SSH keys that Claude Code can read</p>
        </div>
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">Bash Access</div>
          <p class="text-sm text-[#8b949e]">Shell command capabilities, dangerous command patterns</p>
        </div>
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">Network</div>
          <p class="text-sm text-[#8b949e]">HTTP/curl/fetch tools that enable data exfiltration</p>
        </div>
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">Integrity</div>
          <p class="text-sm text-[#8b949e]">Hash tracking for MCP scripts and Claude installation</p>
        </div>
      </div>
    </div>
  </section>

  <!-- Attack Scenarios -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-6">Attack Scenarios</h2>

      <div class="space-y-6">
        <div class="code-block p-5">
          <div class="flex items-center gap-2 mb-3">
            <span class="text-[#f85149] text-lg">1</span>
            <span class="font-semibold">Credential Theft</span>
          </div>
          <p class="text-sm text-[#8b949e]">
            A malicious MCP server or prompt injection reads API keys from accessible
            config files (~/.aws/credentials, .env files) and exfiltrates them via
            an HTTP tool call.
          </p>
        </div>

        <div class="code-block p-5">
          <div class="flex items-center gap-2 mb-3">
            <span class="text-[#f85149] text-lg">2</span>
            <span class="font-semibold">Data Exfiltration</span>
          </div>
          <p class="text-sm text-[#8b949e]">
            Claude Code with file read + network access can read sensitive documents,
            source code, or database exports and send them anywhere. The agent
            faithfully executes what the LLM requests.
          </p>
        </div>

        <div class="code-block p-5">
          <div class="flex items-center gap-2 mb-3">
            <span class="text-[#f85149] text-lg">3</span>
            <span class="font-semibold">Persistence via Context</span>
          </div>
          <p class="text-sm text-[#8b949e]">
            Injected instructions survive context compaction, persisting across
            sessions. Security-critical context gets dropped while malicious
            instructions remain.
          </p>
        </div>
      </div>
    </div>
  </section>

  <!-- How It Works -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-6">How It Works</h2>

      <div class="code-block p-5 mb-8">
        <div class="text-[#8b949e] text-sm mb-2">$ npx claude-defense-kit</div>
        <div class="text-[#3fb950]">Starting Claude Defense Kit...</div>
      </div>

      <div class="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <div class="text-center">
          <div class="w-10 h-10 rounded-full bg-[#21262d] border border-[#30363d] flex items-center justify-center mx-auto mb-3 text-[#58a6ff] font-bold">1</div>
          <p class="text-sm text-[#8b949e]">Scans your Claude Code configuration</p>
        </div>
        <div class="text-center">
          <div class="w-10 h-10 rounded-full bg-[#21262d] border border-[#30363d] flex items-center justify-center mx-auto mb-3 text-[#58a6ff] font-bold">2</div>
          <p class="text-sm text-[#8b949e]">Identifies MCP servers, tools, file access</p>
        </div>
        <div class="text-center">
          <div class="w-10 h-10 rounded-full bg-[#21262d] border border-[#30363d] flex items-center justify-center mx-auto mb-3 text-[#58a6ff] font-bold">3</div>
          <p class="text-sm text-[#8b949e]">Calculates blast radius and attack chains</p>
        </div>
        <div class="text-center">
          <div class="w-10 h-10 rounded-full bg-[#21262d] border border-[#30363d] flex items-center justify-center mx-auto mb-3 text-[#58a6ff] font-bold">4</div>
          <p class="text-sm text-[#8b949e]">Shows one-click remediation options</p>
        </div>
      </div>
    </div>
  </section>

  <!-- Features -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-6">Features</h2>

      <div class="grid sm:grid-cols-2 gap-6">
        <div class="flex gap-4">
          <div class="text-[#3fb950] text-xl">&#10003;</div>
          <div>
            <div class="font-semibold mb-1">Local-Only</div>
            <p class="text-sm text-[#8b949e]">No data leaves your machine. All analysis happens locally.</p>
          </div>
        </div>
        <div class="flex gap-4">
          <div class="text-[#3fb950] text-xl">&#10003;</div>
          <div>
            <div class="font-semibold mb-1">One-Click Remediation</div>
            <p class="text-sm text-[#8b949e]">Fix issues directly from the report with config changes.</p>
          </div>
        </div>
        <div class="flex gap-4">
          <div class="text-[#3fb950] text-xl">&#10003;</div>
          <div>
            <div class="font-semibold mb-1">Integrity Monitoring</div>
            <p class="text-sm text-[#8b949e]">Track changes to MCP server scripts over time.</p>
          </div>
        </div>
        <div class="flex gap-4">
          <div class="text-[#3fb950] text-xl">&#10003;</div>
          <div>
            <div class="font-semibold mb-1">Configurable Restrictions</div>
            <p class="text-sm text-[#8b949e]">Restrict tools, paths, and bash commands from the UI.</p>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Enterprise -->
  <section class="border-b border-[#30363d] bg-[#161b22]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-2">Managing Claude Code Across Your Organization?</h2>
      <p class="text-[#8b949e] mb-6">
        Beyond Identity provides enterprise-grade security controls for Claude Code deployments.
      </p>

      <div class="flex flex-wrap gap-x-6 gap-y-2 mb-8 text-sm">
        <span class="flex items-center gap-2">
          <span class="text-[#3fb950]">&#10003;</span>
          <span class="text-[#c9d1d9]">Fleet-wide policy enforcement</span>
        </span>
        <span class="flex items-center gap-2">
          <span class="text-[#3fb950]">&#10003;</span>
          <span class="text-[#c9d1d9]">Centralized audit logs</span>
        </span>
        <span class="flex items-center gap-2">
          <span class="text-[#3fb950]">&#10003;</span>
          <span class="text-[#c9d1d9]">Compliance reporting</span>
        </span>
      </div>

      <a href="https://beyondidentity.ai" target="_blank"
        class="inline-block px-6 py-3 bg-[#58a6ff] text-white rounded-lg font-semibold hover:brightness-110 transition">
        Learn More
      </a>
    </div>
  </section>

  <!-- Footer -->
  <footer class="py-12">
    <div class="max-w-5xl mx-auto px-6 text-center">
      <p class="text-[#8b949e] mb-4">
        <a href="https://github.com/gobeyondidentity/claude-defense-kit" target="_blank" class="text-[#58a6ff] hover:underline">GitHub</a>
        <span class="mx-2">·</span>
        <span>MIT License</span>
        <span class="mx-2">·</span>
        <a href="/" class="text-[#58a6ff] hover:underline">Run Audit</a>
      </p>
      <p class="text-sm text-[#8b949e]">
        No data leaves your machine. All analysis happens locally.
      </p>
    </div>
  </footer>

</body>
</html>`;
}
