import type {
  ScanResultsWithIssues,
  SecurityIssue,
  BlastRadiusItem,
  McpIntegrityResult,
  IntegrityStatus,
  ClaudeCodeConfig,
} from "../types/index.js";
import {
  readClaudeConfig,
  SECURITY_PROFILES,
  getConfigPath,
  getConfigScope,
} from "../config/writer.js";

// Tool restriction definitions
const TOOL_RESTRICTIONS = [
  {
    name: "Bash",
    description: "Shell command execution",
    risk: "high",
    detail: "Prevents running arbitrary system commands",
  },
  {
    name: "Write",
    description: "File creation/overwrite",
    risk: "medium",
    detail: "Prevents creating new files or overwriting existing ones",
  },
  {
    name: "Edit",
    description: "File modification",
    risk: "medium",
    detail: "Prevents modifying existing files",
  },
  {
    name: "WebFetch",
    description: "HTTP requests",
    risk: "medium",
    detail: "Prevents fetching content from URLs",
  },
];

// Bash command restriction definitions
const BASH_COMMAND_RESTRICTIONS = [
  {
    command: "curl",
    pattern: "Bash(curl:*)",
    risk: "high",
    description: "Prevents HTTP requests and data exfiltration via curl",
  },
  {
    command: "wget",
    pattern: "Bash(wget:*)",
    risk: "high",
    description: "Prevents downloading files via wget",
  },
  {
    command: "nc",
    pattern: "Bash(nc:*)",
    risk: "high",
    description: "Prevents netcat connections for reverse shells",
  },
  {
    command: "ssh",
    pattern: "Bash(ssh:*)",
    risk: "high",
    description: "Prevents SSH connections to remote servers",
  },
  {
    command: "scp",
    pattern: "Bash(scp:*)",
    risk: "high",
    description: "Prevents secure copy to remote servers",
  },
];

// Sandbox setting definitions
const SANDBOX_SETTINGS = [
  {
    path: "enabled",
    name: "Enable Sandbox",
    configKey: "sandbox.enabled",
    description:
      "Isolates bash commands from filesystem and network (macOS/Linux)",
    enableValue: true,
    disableValue: false,
    defaultValue: false,
  },
  {
    path: "autoAllowBashIfSandboxed",
    name: "Auto-Approve Bash When Sandboxed",
    configKey: "sandbox.autoAllowBashIfSandboxed",
    description:
      "Skip confirmation prompts for bash commands when sandbox is enabled",
    enableValue: true,
    disableValue: false,
    defaultValue: true,
  },
  {
    path: "allowUnsandboxedCommands",
    name: "Block Unsafe Commands",
    configKey: "sandbox.allowUnsandboxedCommands",
    description: "Prevent escape hatch that allows bypassing the sandbox",
    enableValue: false,
    disableValue: true,
    defaultValue: true,
    invertDisplay: true,
  },
  {
    path: "network.allowLocalBinding",
    name: "Allow Localhost Binding",
    configKey: "sandbox.network.allowLocalBinding",
    description:
      "Allow sandboxed commands to bind to localhost ports (macOS only)",
    enableValue: true,
    disableValue: false,
    defaultValue: false,
  },
];

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Deduplicate blast radius items by description (case-insensitive)
function deduplicateBlastRadius(items: BlastRadiusItem[]): BlastRadiusItem[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = item.description.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// Generate a section card with consistent styling (glass-morphism)
function generateSection(
  title: string,
  content: string,
  titleColor?: string,
  id?: string
): string {
  const colorClass = titleColor || "text-[rgba(255,255,255,0.6)]";
  const idAttr = id ? ` id="${id}"` : "";
  return `
    <section${idAttr} class="glass-card rounded-xl mb-4 overflow-hidden">
      <div class="px-5 py-3 border-b border-[rgba(255,255,255,0.1)]">
        <h2 class="text-sm font-semibold uppercase tracking-wide ${colorClass}">${title}</h2>
      </div>
      <div class="px-5 py-4">
        ${content}
      </div>
    </section>`;
}

// Generate a finding card
function generateFindingCard(issue: SecurityIssue): string {
  const actionLabel = issue.type === "mcp-server" ? "Disable" : "Fix";
  const commandHtml = issue.command
    ? `<code class="block mt-2 text-xs text-[rgba(255,255,255,0.5)] bg-[rgba(0,0,0,0.3)] px-2 py-1 rounded overflow-x-auto">${escapeHtml(
        issue.command
      )}</code>`
    : "";

  return `
    <div class="finding-card glass-card rounded-lg p-4 mb-3 last:mb-0"
         id="issue-${escapeHtml(issue.id)}" data-risk="${issue.risk}">
      <div class="flex justify-between items-start gap-4">
        <div class="flex-1 min-w-0">
          <h3 class="font-semibold text-white">${escapeHtml(issue.title)}</h3>
          <code class="text-sm text-[rgba(255,255,255,0.6)] break-all">${escapeHtml(
            issue.target
          )}</code>
        </div>
        <button class="btn-fix btn-gradient shrink-0 px-3 py-1.5 rounded text-sm"
          onclick="fixIssue('${escapeHtml(issue.id)}', '${
    issue.action.type
  }', '${escapeHtml(issue.action.target)}')">
          ${actionLabel}
        </button>
        <button class="btn-undo hidden btn-secondary shrink-0 px-3 py-1.5 rounded text-sm"
          onclick="undoIssue('${escapeHtml(issue.id)}')">
          Undo
        </button>
      </div>
      <p class="text-sm text-[rgba(255,255,255,0.6)] mt-2">${escapeHtml(
        issue.description
      )}</p>
      ${commandHtml}
      <div class="fixed-badge hidden mt-2 text-sm text-[#10b981]">&#10003; Fixed</div>
    </div>`;
}

// Generate a tool restriction card
function generateToolRestrictionCard(
  tool: (typeof TOOL_RESTRICTIONS)[0],
  isDisabled: boolean
): string {
  const statusBadge = isDisabled
    ? '<span class="px-2 py-0.5 rounded text-xs font-medium bg-[#f85149] text-white">BLOCKED</span>'
    : '<span class="px-2 py-0.5 rounded text-xs font-medium bg-[#238636] text-white">ALLOWED</span>';

  const buttonLabel = isDisabled ? "Enable" : "Disable";
  const buttonAction = isDisabled
    ? `enableTool('${escapeHtml(tool.name)}')`
    : `disableTool('${escapeHtml(tool.name)}')`;
  const buttonClass = isDisabled
    ? "bg-[#238636] text-white"
    : "bg-[#f85149] text-white";

  return `
    <div class="glass-card rounded-lg p-4 mb-3 last:mb-0"
         id="tool-${escapeHtml(tool.name)}" data-risk="${tool.risk}">
      <div class="flex justify-between items-start gap-4">
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-1">
            <h3 class="font-semibold text-white">${escapeHtml(tool.name)}</h3>
            ${statusBadge}
          </div>
          <span class="text-sm text-[rgba(255,255,255,0.6)]">${escapeHtml(
            tool.description
          )}</span>
        </div>
        <button class="shrink-0 px-3 py-1.5 ${buttonClass} rounded text-sm font-medium hover:brightness-110 transition"
          onclick="${buttonAction}">
          ${buttonLabel}
        </button>
      </div>
      <p class="text-sm text-[rgba(255,255,255,0.6)] mt-2">${escapeHtml(
        tool.detail
      )}</p>
    </div>`;
}

// Generate a bash command restriction card
function generateBashRestrictionCard(
  cmd: (typeof BASH_COMMAND_RESTRICTIONS)[0],
  isBlocked: boolean
): string {
  const cardClass = isBlocked ? "finding-card fixed" : "finding-card";

  return `
    <div class="${cardClass} bg-[#21262d] border border-[#30363d] rounded-lg p-4 mb-3 last:mb-0"
         id="bash-${escapeHtml(cmd.command)}" data-risk="${cmd.risk}">
      <div class="flex justify-between items-start gap-4">
        <div class="flex-1 min-w-0">
          <h3 class="font-semibold text-[#c9d1d9]">${escapeHtml(
            cmd.command
          )}</h3>
          <code class="text-sm text-[#8b949e] break-all">${escapeHtml(
            cmd.pattern
          )}</code>
        </div>
        <button class="btn-fix shrink-0 px-3 py-1.5 bg-[#58a6ff] text-white rounded text-sm font-medium hover:brightness-110 transition"
          onclick="blockBashCommand('${escapeHtml(cmd.command)}', '${escapeHtml(
    cmd.pattern
  )}')">
          Block
        </button>
        <button class="btn-undo hidden shrink-0 px-3 py-1.5 bg-[#21262d] text-[#c9d1d9] border border-[#30363d] rounded text-sm font-medium hover:bg-[#30363d] transition"
          onclick="undoRestriction('bash-${escapeHtml(cmd.command)}')">
          Undo
        </button>
      </div>
      <p class="text-sm text-[#8b949e] mt-2">${escapeHtml(cmd.description)}</p>
      <div class="fixed-badge hidden mt-2 text-sm text-[#3fb950]">&#10003; Blocked</div>
    </div>`;
}

// Generate a sandbox setting card
function generateSandboxCard(
  setting: (typeof SANDBOX_SETTINGS)[0],
  currentValue: boolean | undefined
): string {
  const value = currentValue ?? setting.defaultValue;
  const isEnabled = setting.invertDisplay ? !value : value;
  const buttonLabel = isEnabled ? "Disable" : "Enable";
  const newValue = isEnabled ? setting.disableValue : setting.enableValue;
  const cardId = `sandbox-${setting.path.replace(".", "-")}`;

  return `
    <div class="bg-[#21262d] border border-[#30363d] rounded-lg p-4 mb-3 last:mb-0"
         id="${escapeHtml(cardId)}">
      <div class="flex justify-between items-start gap-4">
        <div class="flex-1 min-w-0">
          <h3 class="font-semibold text-[#c9d1d9]">${escapeHtml(
            setting.name
          )}</h3>
          <code class="text-sm text-[#8b949e]">${escapeHtml(
            setting.configKey
          )}</code>
        </div>
        <span class="shrink-0 px-2 py-0.5 rounded text-xs font-medium ${
          isEnabled ? "bg-[#238636] text-white" : "bg-[#30363d] text-[#8b949e]"
        }">
          ${isEnabled ? "ON" : "OFF"}
        </span>
        <button class="shrink-0 px-3 py-1.5 bg-[#58a6ff] text-white rounded text-sm font-medium hover:brightness-110 transition"
          onclick="updateSandbox('${escapeHtml(
            setting.path
          )}', ${JSON.stringify(newValue)}, '${escapeHtml(setting.name)}')">
          ${buttonLabel}
        </button>
      </div>
      <p class="text-sm text-[#8b949e] mt-2">${escapeHtml(
        setting.description
      )}</p>
    </div>`;
}

// Get integrity status styling
function getIntegrityStatusStyle(status: IntegrityStatus): {
  label: string;
  bgClass: string;
  textClass: string;
} {
  switch (status) {
    case "new":
      return { label: "NEW", bgClass: "bg-[#d29922]", textClass: "text-white" };
    case "unchanged":
      return { label: "OK", bgClass: "bg-[#238636]", textClass: "text-white" };
    case "changed":
      return {
        label: "CHANGED",
        bgClass: "bg-[#f85149]",
        textClass: "text-white",
      };
    case "missing":
      return {
        label: "MISSING",
        bgClass: "bg-[#f85149]",
        textClass: "text-white",
      };
    case "unhashable":
      return {
        label: "SKIP",
        bgClass: "bg-[#30363d]",
        textClass: "text-[#8b949e]",
      };
  }
}

// Generate an integrity status card
function generateIntegrityCard(item: McpIntegrityResult): string {
  const { label, bgClass, textClass } = getIntegrityStatusStyle(item.status);
  const date = item.recordedAt
    ? new Date(item.recordedAt).toLocaleDateString()
    : null;

  let details = "";
  if (item.status === "new") {
    details = '<span class="text-[#8b949e]">Baseline recorded</span>';
  } else if (item.status === "unchanged" && date) {
    details = `<span class="text-[#8b949e]">Unchanged since ${date}</span>`;
  } else if (item.status === "changed") {
    details = `
      <div class="text-xs text-[#8b949e] mt-1">
        <div>Was: <code class="text-[#f0883e]">${item.baselineHash?.slice(
          0,
          24
        )}...</code></div>
        <div>Now: <code class="text-[#f0883e]">${item.currentHash?.slice(
          0,
          24
        )}...</code></div>
      </div>`;
  } else if (item.status === "missing") {
    details = `<span class="text-[#f85149] text-xs">File not found: ${escapeHtml(
      item.targetPath || "unknown"
    )}</span>`;
  } else if (item.status === "unhashable") {
    details =
      '<span class="text-[#8b949e]">Cannot determine file to hash</span>';
  }

  const acceptButton =
    item.status === "changed" && item.currentHash && item.targetPath
      ? `<button class="shrink-0 px-3 py-1.5 bg-[#58a6ff] text-white rounded text-sm font-medium hover:brightness-110 transition"
         onclick="acceptHash('${escapeHtml(item.serverName)}', '${escapeHtml(
          item.targetPath
        )}', '${escapeHtml(item.currentHash)}')">
         Accept
       </button>`
      : "";

  return `
    <div class="bg-[#21262d] border border-[#30363d] rounded-lg p-4 mb-3 last:mb-0"
         id="integrity-${escapeHtml(
           item.serverName.replace(/[^a-zA-Z0-9]/g, "-")
         )}">
      <div class="flex justify-between items-start gap-4">
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-1">
            <span class="px-2 py-0.5 rounded text-xs font-medium ${bgClass} ${textClass}">${label}</span>
            <h3 class="font-semibold text-[#c9d1d9]">${escapeHtml(
              item.serverName
            )}</h3>
          </div>
          ${
            item.targetPath
              ? `<code class="text-xs text-[#8b949e] break-all">${escapeHtml(
                  item.targetPath
                )}</code>`
              : ""
          }
          <div class="mt-1">${details}</div>
        </div>
        ${acceptButton}
      </div>
    </div>`;
}

// Generate directory access controls content
function generateDirectoryAccessContent(config: ClaudeCodeConfig): string {
  const allowRules = config.permissions?.allow || [];
  const denyRules = config.permissions?.deny || [];

  // Filter to just directory rules (contain ** or end with /)
  const allowDirs = allowRules.filter(
    (r) => r.includes("**") || r.endsWith("/")
  );
  const denyDirs = denyRules.filter((r) => r.includes("**") || r.endsWith("/"));

  const allowHtml =
    allowDirs.length > 0
      ? allowDirs
          .map(
            (rule) => `
        <div class="flex items-center justify-between bg-[#0d1117] border border-[#30363d] rounded-lg p-3 mb-2">
          <code class="text-sm text-[#3fb950]">${escapeHtml(rule)}</code>
          <button class="px-2 py-1 text-xs bg-[#21262d] text-[#8b949e] border border-[#30363d] rounded hover:bg-[#30363d] transition"
            onclick="removePermission('${escapeHtml(rule)}', 'allow')">
            Remove
          </button>
        </div>
      `
          )
          .join("")
      : '<p class="text-sm text-[#8b949e] italic">No directory allow rules configured.</p>';

  const denyHtml =
    denyDirs.length > 0
      ? denyDirs
          .map(
            (rule) => `
        <div class="flex items-center justify-between bg-[#0d1117] border border-[#30363d] rounded-lg p-3 mb-2">
          <code class="text-sm text-[#f85149]">${escapeHtml(rule)}</code>
          <button class="px-2 py-1 text-xs bg-[#21262d] text-[#8b949e] border border-[#30363d] rounded hover:bg-[#30363d] transition"
            onclick="removePermission('${escapeHtml(rule)}', 'deny')">
            Remove
          </button>
        </div>
      `
          )
          .join("")
      : '<p class="text-sm text-[#8b949e] italic">No directory deny rules configured.</p>';

  return `
    <p class="text-sm text-[#8b949e] mb-4">
      Control which directories Claude Code can access. Use <code class="text-[#58a6ff]">**</code> to match all files recursively.
    </p>

    <!-- Add Directory Form -->
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mb-4">
      <div class="flex gap-2 mb-3">
        <input type="text" id="new-directory-path" placeholder="e.g., ~/.ssh or /path/to/secrets"
          class="flex-1 px-3 py-2 bg-[#21262d] border border-[#30363d] rounded text-sm text-[#c9d1d9] placeholder-[#8b949e] focus:border-[#58a6ff] focus:outline-none">
        <button onclick="addDenyDirectory()" class="px-4 py-2 bg-[#f85149] text-white rounded text-sm font-medium hover:brightness-110 transition">
          Block Directory
        </button>
        <button onclick="addAllowDirectory()" class="px-4 py-2 bg-[#238636] text-white rounded text-sm font-medium hover:brightness-110 transition">
          Allow Directory
        </button>
      </div>
      <p class="text-xs text-[#8b949e]">
        Common sensitive directories: <code class="cursor-pointer hover:text-[#58a6ff]" onclick="setDirectoryPath('~/.ssh')">~/.ssh</code>,
        <code class="cursor-pointer hover:text-[#58a6ff]" onclick="setDirectoryPath('~/.aws')">~/.aws</code>,
        <code class="cursor-pointer hover:text-[#58a6ff]" onclick="setDirectoryPath('~/.gnupg')">~/.gnupg</code>,
        <code class="cursor-pointer hover:text-[#58a6ff]" onclick="setDirectoryPath('~/.config')">~/.config</code>
      </p>
    </div>

    <!-- Current Rules -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <h4 class="text-sm font-semibold text-[#3fb950] mb-2">Allowed Directories</h4>
        ${allowHtml}
      </div>
      <div>
        <h4 class="text-sm font-semibold text-[#f85149] mb-2">Blocked Directories</h4>
        ${denyHtml}
      </div>
    </div>
  `;
}

// Generate security profiles content
function generateSecurityProfilesContent(): string {
  const profiles = Object.entries(SECURITY_PROFILES).map(([id, profile]) => {
    const denyRules = profile.permissions?.deny || [];
    return `
      <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mb-3">
        <div class="flex justify-between items-start gap-4">
          <div class="flex-1">
            <h4 class="font-semibold text-[#c9d1d9] mb-1">${escapeHtml(
              profile.name
            )}</h4>
            <p class="text-sm text-[#8b949e] mb-2">${escapeHtml(
              profile.description
            )}</p>
            <div class="text-xs text-[#8b949e]">
              ${
                denyRules.length > 0
                  ? `<span class="text-[#f85149]">Blocks:</span> ${denyRules
                      .slice(0, 3)
                      .map((d: string) => `<code>${escapeHtml(d)}</code>`)
                      .join(", ")}${denyRules.length > 3 ? "..." : ""}`
                  : ""
              }
            </div>
          </div>
          <button class="shrink-0 px-4 py-2 bg-[#58a6ff] text-white rounded text-sm font-medium hover:brightness-110 transition"
            onclick="applyProfile('${escapeHtml(id)}')">
            Apply
          </button>
        </div>
      </div>
    `;
  });

  return `
    <p class="text-sm text-[#8b949e] mb-4">
      Apply pre-configured security profiles to quickly lock down your Claude Code installation.
      Profiles add deny rules without removing existing configuration.
    </p>
    ${profiles.join("")}
    <p class="text-xs text-[#8b949e] mt-2">
      ⚠️ Applying a profile will add new deny rules. Use "Undo" to revert if needed.
    </p>
  `;
}

// Generate a severity section (always shown, even if empty)
function generateSeveritySection(
  risk: "high" | "medium" | "low",
  issues: SecurityIssue[]
): string {
  const colors = {
    high: "text-[#f85149]",
    medium: "text-[#d29922]",
    low: "text-[#3fb950]",
  };

  const label = risk.toUpperCase() + " RISK";
  const count = issues.length;
  const titleWithCount = `${label} (${count} ${
    count === 1 ? "finding" : "findings"
  })`;

  const content =
    issues.length > 0
      ? issues.map(generateFindingCard).join("")
      : `<p class="text-sm text-[#8b949e] italic">No ${risk}-risk findings.</p>`;

  return generateSection(titleWithCount, content, colors[risk], `${risk}-risk`);
}

export function generateHtmlReport(results: ScanResultsWithIssues): string {
  const {
    agent,
    issues,
    blastRadius,
    attackChains,
    integrity,
    identityExposure,
    claudeInstallation,
  } = results;

  // Group issues by severity
  const highIssues = issues.filter((i) => i.risk === "high");
  const mediumIssues = issues.filter((i) => i.risk === "medium");
  const lowIssues = issues.filter((i) => i.risk === "low");

  const totalIssues = issues.length;

  // Deduplicate blast radius
  const uniqueBlastRadius = deduplicateBlastRadius(blastRadius);
  const hasRisks = uniqueBlastRadius.length > 0;

  // Agent info
  const version = agent.version || "unknown";

  // Get the actual config path from the writer (respects --project flag)
  const actualConfigPath = getConfigPath().replace(process.env.HOME || "", "~");
  const scope = getConfigScope();
  const isProjectScope = scope.type === "project";
  const scopeLabel = isProjectScope ? "PROJECT" : "GLOBAL";
  const scopeDescription = isProjectScope
    ? `Project-level settings for <strong>${scope.projectPath?.replace(
        process.env.HOME || "",
        "~"
      )}</strong>`
    : "Global settings that apply to <strong>all projects</strong>";

  // Generate blast radius list
  const blastRadiusHtml = uniqueBlastRadius
    .slice(0, 8)
    .map(
      (item) =>
        `<li class="text-sm text-[#c9d1d9] py-1">${escapeHtml(
          item.description
        )}</li>`
    )
    .join("");

  // Generate attack scenarios
  const attackScenariosHtml =
    attackChains.length > 0
      ? attackChains
          .slice(0, 4)
          .map(
            (chain) => `
        <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mb-3 last:mb-0">
          <div class="font-semibold text-[#c9d1d9] mb-1">${escapeHtml(
            chain.name
          )}</div>
          <div class="text-sm text-[#8b949e] mb-2">${escapeHtml(
            chain.scenario
          )}</div>
          <div class="text-sm text-[#f85149]"><span class="font-semibold">Impact:</span> ${escapeHtml(
            chain.impact
          )}</div>
        </div>
      `
          )
          .join("")
      : "";

  // Build identity info for "What We Scanned"
  const cj = identityExposure?.identity?.claudeJson;
  const identityLine =
    cj?.email || cj?.organizationName
      ? `<div class="text-sm text-[#8b949e] mb-2">
        ${
          cj.email
            ? `<span class="text-[#f0883e]">${escapeHtml(cj.email)}</span>`
            : ""
        }
        ${cj.email && cj.organizationName ? " · " : ""}
        ${
          cj.organizationName
            ? `<span>${escapeHtml(cj.organizationName)}</span>`
            : ""
        }
       </div>`
      : "";

  // Build installation integrity badge
  const instStatus = claudeInstallation?.status;
  const instBadge = instStatus
    ? instStatus === "unchanged"
      ? '<span class="px-2 py-0.5 rounded text-xs font-medium bg-[#238636] text-white ml-2">OK</span>'
      : instStatus === "new"
      ? '<span class="px-2 py-0.5 rounded text-xs font-medium bg-[#d29922] text-white ml-2">NEW</span>'
      : instStatus === "changed"
      ? '<span class="px-2 py-0.5 rounded text-xs font-medium bg-[#f85149] text-white ml-2">CHANGED</span>'
      : ""
    : "";

  // Build issue breakdown by severity
  const issueBreakdown = `
    <div class="flex flex-wrap gap-4 text-sm">
      <span class="flex items-center gap-1.5">
        <span class="w-2.5 h-2.5 rounded-full bg-[#f85149]"></span>
        <span class="text-[#c9d1d9]">${highIssues.length} High</span>
      </span>
      <span class="flex items-center gap-1.5">
        <span class="w-2.5 h-2.5 rounded-full bg-[#d29922]"></span>
        <span class="text-[#c9d1d9]">${mediumIssues.length} Medium</span>
      </span>
      <span class="flex items-center gap-1.5">
        <span class="w-2.5 h-2.5 rounded-full bg-[#3fb950]"></span>
        <span class="text-[#c9d1d9]">${lowIssues.length} Low</span>
      </span>
    </div>`;

  // Build installation status explanation
  const instStatusExplanation =
    instStatus === "changed"
      ? '<span class="text-xs text-[#f85149] ml-2">Installation modified since last scan</span>'
      : instStatus === "new"
      ? '<span class="text-xs text-[#d29922] ml-2">First scan - baseline recorded</span>'
      : "";

  // Build sections
  const whatWeScannedContent = `
    <!-- Identity Section -->
    ${
      identityLine
        ? `
    <div class="mb-4 pb-4 border-b border-[#30363d]">
      <div class="text-xs uppercase tracking-wide text-[#8b949e] mb-2">Your Identity</div>
      ${identityLine}
      <p class="text-xs text-[#8b949e] mt-1">↳ This is the account Claude Code uses. If compromised, attackers could act as you.</p>
    </div>
    `
        : ""
    }

    <!-- Claude Code Installation -->
    <div class="mb-4 pb-4 border-b border-[#30363d]">
      <div class="text-xs uppercase tracking-wide text-[#8b949e] mb-2">Claude Code Installation</div>
      <div class="flex items-center gap-2 mb-1">
        <span class="text-[#c9d1d9] font-medium">Claude Code</span>
        <span class="text-[#8b949e]">v${escapeHtml(version)}</span>
        ${instBadge}
        ${instStatusExplanation}
      </div>
      <p class="text-xs text-[#8b949e]">↳ We track installation integrity to detect tampering or unexpected changes.</p>
    </div>

    <!-- Configuration Scope -->
    <div class="mb-4 pb-4 border-b border-[#30363d]">
      <div class="text-xs uppercase tracking-wide text-[#8b949e] mb-2">Configuration Scope</div>
      <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4">
        <div class="flex items-start gap-3 mb-3">
          <span class="px-2 py-1 ${
            isProjectScope ? "bg-[#238636]" : "bg-[#58a6ff]"
          } text-white text-xs font-semibold rounded shrink-0">${scopeLabel}</span>
          <div>
            <div class="text-sm text-[#c9d1d9] font-medium">Currently Scanning: ${
              isProjectScope ? "Project" : "Global"
            } Settings</div>
            <a href="/api/config/view" target="_blank" class="text-[#58a6ff] hover:underline font-mono text-xs">${escapeHtml(
              actualConfigPath
            )}</a>
          </div>
        </div>
        <p class="text-xs text-[#8b949e] mb-3">
          ${scopeDescription}. 
          Click "Fix" on issues below to modify it.
        </p>
        <div class="border-t border-[#30363d] pt-3 mt-3">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-xs text-[#8b949e] mb-1">📁 Want to scan a specific project instead?</div>
              <code class="text-xs text-[#58a6ff] bg-[rgba(0,0,0,0.3)] px-2 py-1 rounded">npx claude-defense-kit --project ~/path</code>
            </div>
            <button onclick="showConfigHierarchyModal()" class="text-xs text-[#58a6ff] hover:underline flex items-center gap-1">
              <span>ℹ️</span> Learn about config hierarchy
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Scan Results Summary -->
    <div class="mb-4">
      <div class="text-xs uppercase tracking-wide text-[#8b949e] mb-2">Scan Results</div>
      <p class="text-sm text-[#c9d1d9] mb-3">
        Found <strong>${totalIssues}</strong> security ${
    totalIssues === 1 ? "issue" : "issues"
  }:
      </p>
      ${issueBreakdown}
    </div>

    <!-- Why This Matters Callout -->
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mt-4">
      <div class="flex items-start gap-3">
        <span class="text-[#d29922] text-lg">💡</span>
        <div>
          <div class="text-sm font-medium text-[#c9d1d9] mb-1">Why This Matters</div>
          <p class="text-xs text-[#8b949e]">
            If Claude Code is compromised via prompt injection, an attacker could access everything shown below.
            This scan identifies what's at risk and helps you lock it down with one-click fixes.
          </p>
        </div>
      </div>
    </div>`;

  const whatsAtRiskContent = hasRisks
    ? `
    <p class="text-sm text-[#8b949e] mb-3">Claude Code currently has access to:</p>
    <ul class="list-disc list-inside mb-4 pl-2">
      ${blastRadiusHtml}
    </ul>
    ${
      attackChains.length > 0
        ? `
    <button onclick="toggleAttackScenarios()" id="attack-toggle"
      class="text-sm text-[#58a6ff] hover:underline flex items-center gap-1 mb-4">
      <span id="toggle-arrow">&#9656;</span> View Attack Scenarios
    </button>
    <div id="attack-scenarios" class="hidden">
      ${attackScenariosHtml}
    </div>
    `
        : ""
    }
  `
    : `<p class="text-sm text-[#3fb950]">No security risks detected. Your configuration looks secure.</p>`;

  const howToFixContent = `
    <p class="text-sm text-[#c9d1d9] mb-1">
      Click <strong>"Fix"</strong> or <strong>"Disable"</strong> next to each finding to add restrictions to your config.
    </p>
    <p class="text-sm text-[#8b949e]">
      Each fix modifies <code class="text-[#58a6ff]">${escapeHtml(
        actualConfigPath
      )}</code> to deny access.
    </p>`;

  const enterpriseContent = `
    <p class="text-[#c9d1d9] font-medium mb-2">Managing AI Agents Across Your Organization?</p>
    <p class="text-sm text-[#8b949e] mb-4">
      Beyond Identity provides enterprise-grade security controls for AI agent deployments,
      including centralized policy management, audit logging, and compliance reporting.
    </p>
    <div class="flex flex-wrap gap-x-4 gap-y-1 mb-4 text-sm text-[#8b949e]">
      <span class="flex items-center gap-1"><span class="text-[#3fb950]">&#10003;</span> Fleet-wide policy enforcement</span>
      <span class="flex items-center gap-1"><span class="text-[#3fb950]">&#10003;</span> Centralized audit logs</span>
      <span class="flex items-center gap-1"><span class="text-[#3fb950]">&#10003;</span> Compliance reporting</span>
    </div>
    <a href="https://beyondidentity.ai" target="_blank"
      class="inline-block px-4 py-2 bg-[#58a6ff] text-white rounded font-medium text-sm hover:brightness-110 transition">
      Learn More
    </a>`;

  // Read current config to check which restrictions are already applied
  const currentConfig = readClaudeConfig();
  const disabledTools = new Set(currentConfig.disallowedTools || []);
  const denyPatterns = new Set(currentConfig.permissions?.deny || []);

  // Generate tool restrictions section
  const toolRestrictionsCards = TOOL_RESTRICTIONS.map((tool) =>
    generateToolRestrictionCard(tool, disabledTools.has(tool.name))
  ).join("");

  const toolRestrictionsContent = `
    <p class="text-sm text-[#8b949e] mb-4">Disable Claude Code tools to reduce attack surface.</p>
    ${toolRestrictionsCards}`;

  // Generate bash command restrictions section
  const bashRestrictionsCards = BASH_COMMAND_RESTRICTIONS.map((cmd) =>
    generateBashRestrictionCard(cmd, denyPatterns.has(cmd.pattern))
  ).join("");

  const bashRestrictionsContent = `
    <p class="text-sm text-[#8b949e] mb-4">Block specific dangerous bash commands while keeping Bash enabled.</p>
    ${bashRestrictionsCards}`;

  // Generate sandbox configuration section
  const sandboxConfig = currentConfig.sandbox || {};
  const getSandboxValue = (path: string): boolean | undefined => {
    const parts = path.split(".");
    if (parts.length === 1) {
      return sandboxConfig[path as keyof typeof sandboxConfig] as
        | boolean
        | undefined;
    } else if (parts.length === 2 && parts[0] === "network") {
      return sandboxConfig.network?.[
        parts[1] as keyof typeof sandboxConfig.network
      ] as boolean | undefined;
    }
    return undefined;
  };

  const sandboxCards = SANDBOX_SETTINGS.map((setting) =>
    generateSandboxCard(setting, getSandboxValue(setting.path))
  ).join("");

  const sandboxContent = `
    <p class="text-sm text-[#8b949e] mb-4">Configure bash sandboxing to isolate Claude Code from your system.</p>
    ${sandboxCards}`;

  // Generate integrity section
  const hasIntegrityIssues =
    integrity &&
    integrity.some((i) => i.status === "changed" || i.status === "missing");
  const integrityCards =
    integrity && integrity.length > 0
      ? integrity.map(generateIntegrityCard).join("")
      : '<p class="text-sm text-[#8b949e] italic">No MCP servers with hashable files configured.</p>';

  const integrityContent = `
    <p class="text-sm text-[#8b949e] mb-4">
      Track changes to MCP server scripts. First scan establishes baseline; subsequent scans detect modifications.
    </p>
    ${integrityCards}`;

  // Beyond Identity logo SVG (white version)
  const biLogoSvg = `<svg width="140" height="17" viewBox="0 0 399 49" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M27.324 17.6425V28.6352C27.324 29.2483 27.0276 29.8231 26.5288 30.1791L0.576411 48.6781C0.334743 48.8504 0 48.6781 0 48.3809V37.3883C0 36.7751 0.29637 36.2003 0.795218 35.8444L26.7476 17.3453C26.9893 17.1731 27.324 17.3453 27.324 17.6425Z" fill="white"/>
<path d="M27.324 0.36571V11.3543C27.324 11.9674 27.0276 12.5422 26.5288 12.8982L12.8076 22.6775C10.9943 23.9692 8.56207 23.9692 6.74874 22.6775L0.795218 18.4345C0.29637 18.0785 0 17.5037 0 16.8906V5.90285C0 5.60648 0.334743 5.43339 0.576411 5.60566L8.17507 11.022C9.1344 11.7078 10.4219 11.7078 11.3813 11.022L26.7476 0.0685238C26.9893 -0.103746 27.324 0.0685238 27.324 0.36571Z" fill="white"/>
<path d="M49.1282 37.4536V3.79782H63.5247C69.7206 3.79782 73.8865 7.24672 73.8865 12.3822C73.8865 15.6543 72.1242 18.0984 69.16 19.1487C73.5785 20.0425 76.2295 23.0672 76.2295 27.42C76.2295 33.3331 71.3718 37.4586 64.4134 37.4586H49.1282V37.4536ZM63.5701 32.1363C67.6401 32.1363 69.8872 30.4094 69.8872 27.2786C69.8872 24.1478 67.6452 22.4158 63.5701 22.4158H55.2887V32.1414H63.5701V32.1363ZM62.5854 17.1945C65.7667 17.1945 67.5896 15.7149 67.5896 13.1295C67.5896 10.5441 65.7667 9.11003 62.5854 9.11003H55.2887V17.1945H62.5854Z" fill="white"/>
<path d="M91.3983 38.2007C83.425 38.2007 78.2693 32.6814 78.2693 24.1375C78.2693 15.5935 83.526 10.0742 91.3478 10.0742C99.1697 10.0742 104.103 15.134 104.103 22.9659V26.1169H84.551C84.9348 30.4192 87.6061 33.1712 91.4438 33.1712C94.4331 33.1712 96.7509 31.6008 97.6397 28.9649L97.7406 28.672H103.931L103.815 29.1972C102.614 34.6659 97.7407 38.2057 91.4034 38.2057L91.3983 38.2007ZM98.0285 21.3147C97.8568 17.472 95.3825 15.1037 91.4892 15.1037C87.5959 15.1037 85.263 17.3609 84.6318 21.3147H98.0335H98.0285Z" fill="white"/>
<path d="M108.839 46.8255L113.303 35.7567L103.946 10.8267H110.354L119.146 34.2721C119.615 35.5294 119.6 36.908 119.1 38.1502L115.606 46.8255H108.839Z" fill="white"/>
<path d="M118.853 28.8231L125.201 11.9624C125.458 11.2807 126.12 10.8212 126.847 10.8212H132.093L125.256 27.697C124.983 28.3787 124.327 28.8231 123.59 28.8231H118.858H118.853Z" fill="white"/>
<path d="M384.958 28.8232L391.306 11.9625C391.563 11.2808 392.225 10.8213 392.952 10.8213H398.199L391.361 27.6971C391.089 28.3788 390.432 28.8232 389.695 28.8232H384.964H384.958Z" fill="white"/>
<path d="M144.995 38.2007C137.007 38.2007 131.634 32.5501 131.634 24.1375C131.634 15.7248 137.002 10.0742 144.995 10.0742C152.989 10.0742 158.362 15.7248 158.362 24.1375C158.362 32.5501 152.989 38.2007 144.995 38.2007ZM144.995 15.1037C140.582 15.1037 137.84 18.5627 137.84 24.1375C137.84 29.7122 140.582 33.1712 144.995 33.1712C149.409 33.1712 152.156 29.7122 152.156 24.1375C152.156 18.5627 149.414 15.1037 144.995 15.1037Z" fill="white"/>
<path d="M178.919 37.4533V21.744C178.919 17.4013 177.267 15.1996 174.01 15.1996C172.571 15.1996 167.885 15.7399 167.885 22.6832V37.4533H161.962V10.8216H167.794V14.1998C169.582 11.5235 172.344 10.0692 175.697 10.0692C181.423 10.0692 184.842 14.2402 184.842 21.2289V37.4533H178.919Z" fill="white"/>
<path d="M200.627 38.2007C194.754 38.2007 188.437 33.7974 188.437 24.1375C188.437 14.4775 194.754 10.0743 200.627 10.0743C204.318 10.0743 207.464 11.7305 209.338 14.5785C209.333 14.2402 209.333 13.9069 209.333 13.5484V0.000244141H215.256V37.4533H209.383V34.8174C209.383 34.4034 209.383 34.0145 209.383 33.6257C207.52 36.5192 204.349 38.2007 200.627 38.2007ZM202.036 15.1037C197.547 15.1037 194.643 18.6485 194.643 24.1375C194.643 29.6264 197.547 33.1713 202.036 33.1713C206.525 33.1713 209.383 29.5406 209.383 24.1375C209.383 18.7344 206.429 15.1037 202.036 15.1037Z" fill="white"/>
<path d="M249.316 38.2007C243.443 38.2007 237.126 33.7974 237.126 24.1375C237.126 14.4775 243.443 10.0743 249.316 10.0743C253.007 10.0743 256.153 11.7305 258.026 14.5785C258.021 14.2402 258.021 13.9069 258.021 13.5484V0.000244141H263.944V37.4533H258.067V34.8174C258.067 34.4034 258.067 34.0145 258.067 33.6257C256.203 36.5192 253.032 38.2007 249.31 38.2007H249.316ZM250.724 15.1037C246.235 15.1037 243.332 18.6485 243.332 24.1375C243.332 29.6264 246.235 33.1713 250.724 33.1713C255.214 33.1713 258.067 29.6264 258.067 24.1375C258.067 18.6485 255.183 15.1037 250.724 15.1037Z" fill="white"/>
<path d="M280.668 38.2007C272.695 38.2007 267.539 32.6814 267.539 24.1375C267.539 15.5935 272.796 10.0742 280.623 10.0742C288.45 10.0742 293.373 15.134 293.373 22.9659V26.1169H273.821C274.205 30.4192 276.876 33.1712 280.714 33.1712C283.703 33.1712 286.021 31.6008 286.91 28.9649L287.011 28.672H293.202L293.085 29.1972C291.884 34.6659 287.011 38.2057 280.668 38.2057V38.2007ZM287.304 21.3147C287.132 17.472 284.658 15.1037 280.764 15.1037C276.871 15.1037 274.538 17.3609 273.907 21.3147H287.304Z" fill="white"/>
<path d="M313.839 37.4533V21.7439C313.839 17.4013 312.188 15.1996 308.926 15.1996C307.487 15.1996 302.801 15.7399 302.801 22.6832V37.4533H296.877V10.8216H302.705V14.2099C304.492 11.5285 307.254 10.0742 310.612 10.0742C316.339 10.0742 319.757 14.2452 319.757 21.2339V37.4584H313.834L313.839 37.4533Z" fill="white"/>
<path d="M333.957 37.4536C329.14 37.4536 326.589 34.9237 326.589 30.1316V15.9472H321.53V10.8219H326.589V3.79782H332.513V10.8269H340.521V15.9523H332.513V29.7176C332.513 31.5506 333.305 32.3282 335.174 32.3282H340.713V37.4586H333.957V37.4536Z" fill="white"/>
<path d="M349.662 1.35873H343.643V7.23145H349.662V1.35873Z" fill="white"/>
<path d="M349.611 10.8213H343.688V37.453H349.611V10.8213Z" fill="white"/>
<path d="M233.758 3.79797H227.744V14.5991H227.79V37.4537H233.713V14.5991H233.758V3.79797Z" fill="white"/>
<path d="M385.251 34.2723L376.46 10.8269H363.538V3.79782H357.615V10.8219H352.555V15.9422H357.615V30.1316C357.615 34.9187 360.16 37.4536 364.977 37.4536H371.733V32.3282H366.194C364.331 32.3282 363.533 31.5455 363.533 29.7125V15.9472H371.966L379.404 35.7569L374.935 46.8257H381.484H381.706L385.201 38.1504C385.701 36.9032 385.721 35.5297 385.246 34.2723H385.251Z" fill="white"/>
</svg>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Claude Defense Kit</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    /* Beyond Identity Theme - CSS Variables */
    :root {
      --primary: #a7e1e0;
      --primary-dark: #5fa8a7;
      --primary-light: #c5f0ef;
      --bg-primary: #0F2727;
      --bg-secondary: rgba(255, 255, 255, 0.08);
      --bg-card: rgba(255, 255, 255, 0.06);
      --text-primary: #ffffff;
      --text-secondary: rgba(255, 255, 255, 0.7);
      --border-color: rgba(255, 255, 255, 0.1);
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
    }
    
    /* Background with gradient */
    body {
      background: linear-gradient(135deg, #0F2727 0%, #0A1414 50%, #203A3A 100%);
    }
    
    /* Glass-morphism cards */
    .glass-card {
      background: rgba(255, 255, 255, 0.06);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      transition: all 0.3s ease;
    }
    .glass-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
    }
    
    /* Glass sidebar */
    .glass-sidebar {
      background: rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-right: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    /* Gradient buttons */
    .btn-gradient {
      background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
      color: #0a2020;
      font-weight: 600;
      box-shadow: 0 4px 12px rgba(167, 225, 224, 0.3);
      transition: all 0.2s ease;
    }
    .btn-gradient:hover {
      background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 100%);
      transform: scale(1.02);
      box-shadow: 0 6px 16px rgba(167, 225, 224, 0.4);
    }
    
    /* Secondary button */
    .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      color: rgba(255, 255, 255, 0.8);
      border: 1px solid rgba(255, 255, 255, 0.2);
      transition: all 0.2s ease;
    }
    .btn-secondary:hover {
      background: rgba(167, 225, 224, 0.15);
      border-color: rgba(167, 225, 224, 0.3);
      color: var(--primary);
    }
    
    .finding-card.fixed { 
      border-style: dashed; 
      border-color: rgba(16, 185, 129, 0.3);
      background: rgba(16, 185, 129, 0.08);
      position: relative;
      z-index: 1;
    }
    .finding-card:not(.fixed) {
      position: relative;
      z-index: 2;
    }
    .finding-card.fixed .btn-fix { display: none; }
    .finding-card.fixed .btn-undo { display: inline-flex; }
    .finding-card.fixed .fixed-badge { display: block; }
    .finding-card.fixed h3, .finding-card.fixed p, .finding-card.fixed code {
      opacity: 0.6;
    }
    
    /* Navigation sidebar */
    .nav-link {
      display: block;
      padding: 10px 14px;
      color: rgba(255, 255, 255, 0.7);
      text-decoration: none;
      border-radius: 10px;
      font-size: 13px;
      margin-bottom: 4px;
      transition: all 0.2s ease;
    }
    .nav-link:hover { 
      background: rgba(167, 225, 224, 0.1); 
      color: var(--primary-light); 
    }
    .nav-link.active { 
      background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
      color: #0a2020;
      font-weight: 600;
    }
    
    /* Progress bar gradient */
    .progress-fill {
      background: linear-gradient(90deg, var(--primary-dark) 0%, var(--primary) 100%);
    }
    
    /* Links */
    a { color: var(--primary); transition: color 0.2s ease; }
    a:hover { color: var(--primary-light); }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: rgba(255, 255, 255, 0.05); }
    ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.2); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.3); }
    
    /* Responsive: hide sidebar on small screens */
    @media (max-width: 1024px) {
      #sidebar { display: none; }
      .sidebar-offset { margin-left: 0 !important; }
    }
    
    /* Git-style diff highlighting */
    .diff-line { padding: 1px 4px; }
    .diff-added { 
      background: rgba(63, 185, 80, 0.2); 
      border-left: 3px solid #3fb950;
      padding: 1px 4px;
    }
    .diff-removed { 
      background: rgba(248, 81, 73, 0.2); 
      border-left: 3px solid #f85149;
      padding: 1px 4px;
    }
  </style>
</head>
<body class="text-white min-h-screen font-sans">
  <!-- Navigation Sidebar -->
  <nav id="sidebar" class="glass-sidebar fixed left-0 top-0 h-full w-56 pt-6 px-4 overflow-y-auto z-50">
    <!-- Logo -->
    <div class="flex flex-col items-center mb-6 pb-4 border-b border-[rgba(255,255,255,0.1)]">
      <div class="mb-2">${biLogoSvg}</div>
      <span class="text-sm font-semibold text-white tracking-tight">Claude Defense Kit</span>
    </div>
    
    <div class="text-xs font-semibold text-[rgba(255,255,255,0.5)] uppercase tracking-wider mb-3 px-2">Navigation</div>
    <a href="#what-we-scanned" class="nav-link">What We Scanned</a>
    <a href="#whats-at-risk" class="nav-link">What's at Risk</a>
    <a href="#how-to-fix" class="nav-link">How to Fix</a>
    <div class="border-t border-[rgba(255,255,255,0.2)] my-3 mx-2"></div>
    <a href="#high-risk" class="nav-link">High Risk (${highIssues.length})</a>
    <a href="#medium-risk" class="nav-link">Medium Risk (${
      mediumIssues.length
    })</a>
    <a href="#low-risk" class="nav-link">Low Risk (${lowIssues.length})</a>
    <div class="border-t border-[rgba(255,255,255,0.2)] my-3 mx-2"></div>
    <a href="#tool-restrictions" class="nav-link">Tool Restrictions</a>
    <a href="#bash-restrictions" class="nav-link">Bash Restrictions</a>
    <a href="#sandbox-config" class="nav-link">Sandbox Config</a>
    <a href="#directory-access" class="nav-link">Directory Access</a>
    <a href="#security-profiles" class="nav-link">Security Profiles</a>
    <a href="#mcp-integrity" class="nav-link">MCP Integrity</a>
    <div class="border-t border-[rgba(255,255,255,0.2)] my-3 mx-2"></div>
    <a href="#enterprise" class="nav-link">Enterprise</a>
  </nav>

  <!-- Main Content Wrapper (offset from sidebar) -->
  <div class="ml-56 min-h-screen relative z-10">
  
  <!-- Header -->
  <header class="bg-[rgba(255,255,255,0.04)] border-b border-[rgba(255,255,255,0.1)] px-6 py-6">
    <div class="max-w-4xl">
      <h1 class="text-2xl font-bold mb-2">Claude Defense Kit</h1>
      <p class="text-sm text-[rgba(255,255,255,0.6)] mb-1">
        Secure your Claude Code installation. This report shows what could be accessed
        if Claude Code is prompt-injected, with one-click fixes to lock it down.
      </p>
      <p class="text-xs text-[rgba(255,255,255,0.4)]">
        Scanned at ${new Date().toLocaleString()}
      </p>
    </div>
  </header>

  <!-- Main Content -->
  <main class="max-w-4xl px-6 py-6">
    <!-- What We Scanned -->
    ${generateSection(
      "WHAT WE SCANNED",
      whatWeScannedContent,
      undefined,
      "what-we-scanned"
    )}

    <!-- What's at Risk -->
    ${generateSection(
      "WHAT'S AT RISK",
      whatsAtRiskContent,
      undefined,
      "whats-at-risk"
    )}

    <!-- How to Fix -->
    ${generateSection("HOW TO FIX", howToFixContent, undefined, "how-to-fix")}
  </main>

  <!-- Sticky Progress Bar -->
  <div class="sticky top-0 z-40 bg-[rgba(15,39,39,0.95)] backdrop-blur-sm border-b border-[rgba(255,255,255,0.1)] py-3">
    <div class="max-w-4xl px-6">
      <div class="flex items-center gap-4">
        <span class="text-sm text-[#8b949e]">Progress:</span>
        <span class="text-sm text-[#c9d1d9]" id="progress-text">0/${totalIssues} fixed</span>
        <div class="flex-1 h-2 bg-[#21262d] rounded-full overflow-hidden">
          <div id="progress-bar" class="h-full bg-[#58a6ff] rounded-full transition-all duration-300" style="width: 0%"></div>
        </div>
        <button id="undo-btn" onclick="undoLast()" disabled
          class="px-3 py-1.5 bg-[#21262d] text-[#c9d1d9] border border-[#30363d] rounded text-sm font-medium hover:bg-[#30363d] transition disabled:opacity-50 disabled:cursor-not-allowed">
          Undo Last
        </button>
      </div>
    </div>
  </div>

  <!-- Severity Sections -->
  <div class="max-w-4xl px-6 py-6">
    ${generateSeveritySection("high", highIssues)}
    ${generateSeveritySection("medium", mediumIssues)}
    ${generateSeveritySection("low", lowIssues)}

    <!-- Tool Restrictions -->
    ${generateSection(
      "TOOL RESTRICTIONS",
      toolRestrictionsContent,
      undefined,
      "tool-restrictions"
    )}

    <!-- Bash Command Restrictions -->
    ${generateSection(
      "BASH COMMAND RESTRICTIONS",
      bashRestrictionsContent,
      undefined,
      "bash-restrictions"
    )}

    <!-- Sandbox Configuration -->
    ${generateSection(
      "SANDBOX CONFIGURATION",
      sandboxContent,
      undefined,
      "sandbox-config"
    )}

    <!-- Directory Access Controls -->
    ${generateSection(
      "DIRECTORY ACCESS CONTROLS",
      generateDirectoryAccessContent(currentConfig),
      undefined,
      "directory-access"
    )}

    <!-- Security Profiles -->
    ${generateSection(
      "SECURITY PROFILES",
      generateSecurityProfilesContent(),
      undefined,
      "security-profiles"
    )}

    <!-- MCP Integrity -->
    ${generateSection(
      "MCP SERVER INTEGRITY",
      integrityContent,
      hasIntegrityIssues ? "text-[#f85149]" : "text-[#8b949e]",
      "mcp-integrity"
    )}

    <!-- Enterprise -->
    ${generateSection("ENTERPRISE", enterpriseContent, undefined, "enterprise")}
  </div>

  </div><!-- End Main Content Wrapper -->

  <!-- Footer -->
  <footer class="ml-56 text-center py-6 text-sm text-[#8b949e] border-t border-[rgba(255,255,255,0.1)]">
    <p>Generated by <a href="https://github.com/gobeyondidentity/claude-defense-kit" target="_blank" class="text-[#58a6ff] hover:underline">Claude Defense Kit</a></p>
    <p class="mt-1">No data leaves your machine. All analysis happens locally.</p>
    <p class="mt-3"><a href="/about" class="text-[#30363d] hover:text-[#8b949e] transition">About this tool</a></p>
  </footer>

  <!-- Modal -->
  <div id="modal-overlay" class="fixed inset-0 bg-black/80 backdrop-blur-sm hidden items-center justify-center z-[1000]" onclick="closeModal(event)">
    <div class="glass-card rounded-xl max-w-3xl w-[95%] max-h-[90vh] flex flex-col" style="background: rgba(15, 39, 39, 0.95); backdrop-filter: blur(20px);" onclick="event.stopPropagation()">
      <div id="modal-title" class="px-5 py-4 border-b border-[rgba(255,255,255,0.1)] font-semibold text-white text-lg">Confirm Action</div>
      <div id="modal-body" class="px-5 py-5 overflow-y-auto flex-1"></div>
      <div class="px-5 py-4 border-t border-[rgba(255,255,255,0.1)] flex justify-end gap-3">
        <button onclick="closeModal()" class="btn-secondary px-4 py-2 rounded-lg font-medium">
          Cancel
        </button>
        <button id="modal-confirm" class="btn-gradient px-4 py-2 rounded-lg font-medium">
          Apply Fix
        </button>
      </div>
    </div>
  </div>

  <!-- Toast Container -->
  <div id="toast-container" class="fixed bottom-6 right-6 z-[1100]"></div>

  <script>
    // Client-side HTML escaping
    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    // Generate git-style diff view with line highlighting
    function generateDiffView(before, after) {
      const beforeLines = before.split('\\n');
      const afterLines = after.split('\\n');
      
      // Find added and removed lines
      const beforeSet = new Set(beforeLines.map(l => l.trim()));
      const afterSet = new Set(afterLines.map(l => l.trim()));
      
      // Generate before view with removed lines highlighted
      const beforeHtml = beforeLines.map(line => {
        const trimmed = line.trim();
        if (trimmed && !afterSet.has(trimmed)) {
          return '<div class="diff-removed">' + escapeHtml(line) + '</div>';
        }
        return '<div class="diff-line">' + escapeHtml(line) + '</div>';
      }).join('');
      
      // Generate after view with added lines highlighted
      const afterHtml = afterLines.map(line => {
        const trimmed = line.trim();
        if (trimmed && !beforeSet.has(trimmed)) {
          return '<div class="diff-added">' + escapeHtml(line) + '</div>';
        }
        return '<div class="diff-line">' + escapeHtml(line) + '</div>';
      }).join('');
      
      return { beforeHtml, afterHtml };
    }

    // State
    const state = {
      issues: ${JSON.stringify(issues)},
      fixedIds: new Set(),
      lastAction: null,
      total: ${totalIssues},
    };

    // Update progress bar (both header and sticky)
    function updateProgress() {
      const fixed = state.fixedIds.size;
      const percent = state.total > 0 ? Math.round((fixed / state.total) * 100) : 0;

      // Update sticky progress bar
      document.getElementById('progress-text').textContent = fixed + '/' + state.total + ' fixed';
      document.getElementById('progress-bar').style.width = percent + '%';
      document.getElementById('undo-btn').disabled = !state.lastAction;
      
      // Update header progress bar
      const headerProgressText = document.getElementById('header-progress-text');
      const headerProgressBar = document.getElementById('header-progress-bar');
      const headerUndoBtn = document.getElementById('header-undo-btn');
      if (headerProgressText) headerProgressText.textContent = fixed + '/' + state.total + ' fixed';
      if (headerProgressBar) headerProgressBar.style.width = percent + '%';
      if (headerUndoBtn) headerUndoBtn.disabled = !state.lastAction;
    }

    // Mark issue as fixed
    function markIssueFixed(id) {
      state.fixedIds.add(id);
      const card = document.getElementById('issue-' + id);
      if (card) card.classList.add('fixed');
      updateProgress();
    }

    // Mark issue as unfixed
    function markIssueUnfixed(id) {
      state.fixedIds.delete(id);
      const card = document.getElementById('issue-' + id);
      if (card) card.classList.remove('fixed');
      updateProgress();
    }

    // Modal handling
    let pendingConfirm = null;

    function showModal(title, body, onConfirm) {
      document.getElementById('modal-title').textContent = title;
      document.getElementById('modal-body').innerHTML = body;
      document.getElementById('modal-overlay').classList.remove('hidden');
      document.getElementById('modal-overlay').classList.add('flex');
      pendingConfirm = onConfirm;
    }

    function closeModal(event) {
      if (event && event.target !== document.getElementById('modal-overlay')) return;
      document.getElementById('modal-overlay').classList.add('hidden');
      document.getElementById('modal-overlay').classList.remove('flex');
      pendingConfirm = null;
    }

    document.getElementById('modal-confirm').addEventListener('click', async () => {
      if (pendingConfirm) {
        const btn = document.getElementById('modal-confirm');
        btn.disabled = true;
        btn.textContent = 'Applying...';
        try {
          await pendingConfirm();
        } finally {
          btn.disabled = false;
          btn.textContent = 'Apply Fix';
          closeModal();
        }
      }
    });

    // Toggle attack scenarios
    function toggleAttackScenarios() {
      const scenarios = document.getElementById('attack-scenarios');
      const arrow = document.getElementById('toggle-arrow');
      const toggle = document.getElementById('attack-toggle');
      if (!scenarios) return;

      const isHidden = scenarios.classList.contains('hidden');
      scenarios.classList.toggle('hidden');
      arrow.innerHTML = isHidden ? '&#9662;' : '&#9656;';
      toggle.childNodes[2].textContent = isHidden ? ' Hide Attack Scenarios' : ' View Attack Scenarios';
    }

    // Toast notifications
    function showToast(message, type = 'success') {
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      const borderColor = type === 'success' ? 'border-l-[#3fb950]' : 'border-l-[#f85149]';
      toast.className = 'bg-[#161b22] border border-[#30363d] ' + borderColor + ' border-l-4 rounded px-4 py-3 mb-2 text-sm';
      toast.textContent = message;
      container.appendChild(toast);
      setTimeout(() => toast.remove(), 3000);
    }

    // Fix issue
    async function fixIssue(id, actionType, target) {
      const issue = state.issues.find(i => i.id === id);
      if (!issue) return;

      const actionName = actionType === 'disable-mcp' ? 'Disable MCP Server' : 'Deny Credential Access';
      showModal(actionName, '<p class="text-[#8b949e]">Loading preview...</p>', () => {});

      try {
        const previewEndpoint = actionType === 'disable-mcp'
          ? '/api/preview/disable-mcp'
          : '/api/preview/deny-path';
        const previewBody = actionType === 'disable-mcp'
          ? { name: target }
          : { path: target };

        const previewRes = await fetch(previewEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(previewBody),
        });

        const preview = await previewRes.json();

        if (preview.error) {
          closeModal();
          showToast(preview.error, 'error');
          return;
        }

        const explanation = actionType === 'disable-mcp'
          ? 'This will remove the <strong>' + escapeHtml(target) + '</strong> MCP server from your configuration. Claude Code will no longer have access to this server.'
          : 'This will add a deny rule to prevent Claude Code from reading <strong>' + escapeHtml(target) + '</strong>. The files will still exist, but Claude Code will not be able to access them.';

        const diff = generateDiffView(preview.before, preview.after);
        const bodyHtml =
          '<p class="text-sm text-[#c9d1d9] mb-4">' + explanation + '</p>' +
          '<div class="font-mono text-sm text-[#8b949e] mb-4">File: ' + escapeHtml(preview.configPath) + '</div>' +
          '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">' +
          '<div>' +
          '<div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">Before</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.beforeHtml + '</div>' +
          '</div>' +
          '<div>' +
          '<div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">After</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.afterHtml + '</div>' +
          '</div>' +
          '</div>' +
          '<p class="text-xs text-[#8b949e] mt-4">A backup will be created automatically.</p>';

        document.getElementById('modal-body').innerHTML = bodyHtml;

        pendingConfirm = async () => {
          const endpoint = actionType === 'disable-mcp' ? '/api/disable-mcp' : '/api/deny-path';
          const body = actionType === 'disable-mcp' ? { name: target } : { path: target };

          const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });

          const data = await res.json();
          if (data.success) {
            markIssueFixed(id);
            state.lastAction = { id, actionType, target };
            showToast(data.message);
          } else {
            showToast(data.error || 'Failed to apply fix', 'error');
          }
        };
      } catch (err) {
        closeModal();
        showToast('Failed to load preview', 'error');
      }
    }

    // Undo specific issue
    async function undoIssue(id) {
      await undoLast();
    }

    // Undo last action
    async function undoLast() {
      if (!state.lastAction) return;

      try {
        const res = await fetch('/api/undo', { method: 'POST' });
        const data = await res.json();

        if (data.success) {
          markIssueUnfixed(state.lastAction.id);
          state.lastAction = null;
          showToast('Change reverted');
        } else {
          showToast(data.error || 'Failed to undo', 'error');
        }
      } catch (err) {
        showToast('Failed to undo', 'error');
      }
    }

    // Disable a tool
    async function disableTool(toolName) {
      showModal('Disable Tool', '<p class="text-[#8b949e]">Loading preview...</p>', () => {});

      try {
        const previewRes = await fetch('/api/preview/deny-tool', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: toolName }),
        });

        const preview = await previewRes.json();

        if (preview.error) {
          closeModal();
          showToast(preview.error, 'error');
          return;
        }

        const explanation = 'This will add <strong>' + escapeHtml(toolName) + '</strong> to your disallowedTools list. Claude Code will no longer be able to use this tool.';

        const diff = generateDiffView(preview.before, preview.after);
        const bodyHtml =
          '<p class="text-sm text-[#c9d1d9] mb-4">' + explanation + '</p>' +
          '<div class="font-mono text-sm text-[#8b949e] mb-4">File: ' + escapeHtml(preview.configPath) + '</div>' +
          '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">' +
          '<div>' +
          '<div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">Before</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.beforeHtml + '</div>' +
          '</div>' +
          '<div>' +
          '<div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">After</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.afterHtml + '</div>' +
          '</div>' +
          '</div>' +
          '<p class="text-xs text-[#8b949e] mt-4">A backup will be created automatically.</p>';

        document.getElementById('modal-body').innerHTML = bodyHtml;

        pendingConfirm = async () => {
          const res = await fetch('/api/deny-tool', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: toolName }),
          });

          const data = await res.json();
          if (data.success) {
            showToast(data.message);
            location.reload();
          } else {
            showToast(data.error || 'Failed to disable tool', 'error');
          }
        };
      } catch (err) {
        closeModal();
        showToast('Failed to load preview', 'error');
      }
    }

    // Enable a tool (remove from disallowed list)
    async function enableTool(toolName) {
      showModal('Enable Tool', '<p class="text-[#8b949e]">Loading preview...</p>', () => {});

      try {
        const previewRes = await fetch('/api/preview/enable-tool', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: toolName }),
        });

        const preview = await previewRes.json();

        if (preview.error) {
          closeModal();
          showToast(preview.error, 'error');
          return;
        }

        const explanation = 'This will remove <strong>' + escapeHtml(toolName) + '</strong> from your disallowedTools list. Claude Code will be able to use this tool again.';

        const diff = generateDiffView(preview.before, preview.after);
        const bodyHtml =
          '<p class="text-sm text-[#c9d1d9] mb-4">' + explanation + '</p>' +
          '<div class="font-mono text-sm text-[#8b949e] mb-4">File: ' + escapeHtml(preview.configPath) + '</div>' +
          '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">' +
          '<div>' +
          '<div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">Before</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.beforeHtml + '</div>' +
          '</div>' +
          '<div>' +
          '<div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">After</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.afterHtml + '</div>' +
          '</div>' +
          '</div>' +
          '<p class="text-xs text-[#8b949e] mt-4">A backup will be created automatically.</p>';

        document.getElementById('modal-body').innerHTML = bodyHtml;

        pendingConfirm = async () => {
          const res = await fetch('/api/enable-tool', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: toolName }),
          });

          const data = await res.json();
          if (data.success) {
            showToast(data.message);
            location.reload();
          } else {
            showToast(data.error || 'Failed to enable tool', 'error');
          }
        };
      } catch (err) {
        closeModal();
        showToast('Failed to load preview', 'error');
      }
    }

    // Block a bash command
    async function blockBashCommand(command, pattern) {
      showModal('Block Bash Command', '<p class="text-[#8b949e]">Loading preview...</p>', () => {});

      try {
        const previewRes = await fetch('/api/preview/deny-bash', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pattern: pattern }),
        });

        const preview = await previewRes.json();

        if (preview.error) {
          closeModal();
          showToast(preview.error, 'error');
          return;
        }

        const explanation = 'This will add a deny rule to prevent Claude Code from running <strong>' + escapeHtml(command) + '</strong> commands via Bash.';

        const diff = generateDiffView(preview.before, preview.after);
        const bodyHtml =
          '<p class="text-sm text-[#c9d1d9] mb-4">' + explanation + '</p>' +
          '<div class="font-mono text-sm text-[#8b949e] mb-4">File: ' + escapeHtml(preview.configPath) + '</div>' +
          '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">' +
          '<div>' +
          '<div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">Before</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.beforeHtml + '</div>' +
          '</div>' +
          '<div>' +
          '<div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">After</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.afterHtml + '</div>' +
          '</div>' +
          '</div>' +
          '<p class="text-xs text-[#8b949e] mt-4">A backup will be created automatically.</p>';

        document.getElementById('modal-body').innerHTML = bodyHtml;

        pendingConfirm = async () => {
          const res = await fetch('/api/deny-bash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pattern: pattern }),
          });

          const data = await res.json();
          if (data.success) {
            const card = document.getElementById('bash-' + command);
            if (card) card.classList.add('fixed');
            state.lastAction = { id: 'bash-' + command, type: 'bash', target: pattern };
            document.getElementById('undo-btn').disabled = false;
            showToast(data.message);
          } else {
            showToast(data.error || 'Failed to block command', 'error');
          }
        };
      } catch (err) {
        closeModal();
        showToast('Failed to load preview', 'error');
      }
    }

    // Undo a restriction (tool or bash)
    async function undoRestriction(cardId) {
      try {
        const res = await fetch('/api/undo', { method: 'POST' });
        const data = await res.json();

        if (data.success) {
          const card = document.getElementById(cardId);
          if (card) card.classList.remove('fixed');
          state.lastAction = null;
          document.getElementById('undo-btn').disabled = true;
          showToast('Change reverted');
        } else {
          showToast(data.error || 'Failed to undo', 'error');
        }
      } catch (err) {
        showToast('Failed to undo', 'error');
      }
    }

    // Update sandbox configuration
    async function updateSandbox(path, value, settingName) {
      showModal('Update Sandbox Setting', '<p class="text-[#8b949e]">Loading preview...</p>', () => {});

      try {
        const previewRes = await fetch('/api/preview/sandbox', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: path, value: value }),
        });

        const preview = await previewRes.json();

        if (preview.error) {
          closeModal();
          showToast(preview.error, 'error');
          return;
        }

        const explanation = 'This will update <strong>' + escapeHtml(settingName) + '</strong> in your sandbox configuration.';

        const diff = generateDiffView(preview.before, preview.after);
        const bodyHtml =
          '<p class="text-sm text-[#c9d1d9] mb-4">' + explanation + '</p>' +
          '<div class="font-mono text-sm text-[#8b949e] mb-4">File: ' + escapeHtml(preview.configPath) + '</div>' +
          '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">' +
          '<div>' +
          '<div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">Before</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.beforeHtml + '</div>' +
          '</div>' +
          '<div>' +
          '<div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">After</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.afterHtml + '</div>' +
          '</div>' +
          '</div>' +
          '<p class="text-xs text-[#8b949e] mt-4">A backup will be created automatically.</p>';

        document.getElementById('modal-body').innerHTML = bodyHtml;

        pendingConfirm = async () => {
          const res = await fetch('/api/update-sandbox', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path, value: value }),
          });

          const data = await res.json();
          if (data.success) {
            showToast(data.message);
            // Reload to show updated state
            location.reload();
          } else {
            showToast(data.error || 'Failed to update setting', 'error');
          }
        };
      } catch (err) {
        closeModal();
        showToast('Failed to load preview', 'error');
      }
    }

    // Accept a new hash as baseline
    async function acceptHash(serverName, targetPath, hash) {
      try {
        const res = await fetch('/api/accept-hash', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serverName, targetPath, hash }),
        });

        const data = await res.json();
        if (data.success) {
          showToast(data.message);
          // Reload to show updated state
          location.reload();
        } else {
          showToast(data.error || 'Failed to accept hash', 'error');
        }
      } catch (err) {
        showToast('Failed to accept hash', 'error');
      }
    }

    // Initialize
    updateProgress();

    // Scroll spy for navigation highlighting
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-link');

    function updateActiveNav() {
      let current = '';
      const scrollY = window.scrollY;

      sections.forEach(section => {
        const top = section.offsetTop - 120;
        if (scrollY >= top) {
          current = section.id;
        }
      });

      navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === '#' + current) {
          link.classList.add('active');
        }
      });
    }

    window.addEventListener('scroll', updateActiveNav);
    updateActiveNav();

    // Smooth scroll for nav links
    navLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const target = document.querySelector(link.getAttribute('href'));
        if (target) {
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
    });

    // ============================================
    // Directory Access Control Functions
    // ============================================

    // Set directory path in input field
    function setDirectoryPath(path) {
      document.getElementById('new-directory-path').value = path;
    }

    // Add deny directory rule
    async function addDenyDirectory() {
      const input = document.getElementById('new-directory-path');
      const directory = input.value.trim();
      if (!directory) {
        showToast('Please enter a directory path', 'error');
        return;
      }

      showModal('Block Directory', '<p class="text-[#8b949e]">Loading preview...</p>', () => {});

      try {
        const previewRes = await fetch('/api/preview/deny-directory', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ directory }),
        });

        const preview = await previewRes.json();
        if (preview.error) {
          closeModal();
          showToast(preview.error, 'error');
          return;
        }

        const diff = generateDiffView(preview.before, preview.after);
        const bodyHtml =
          '<p class="text-sm text-[#c9d1d9] mb-4">This will block Claude Code from accessing <strong>' + escapeHtml(directory) + '/**</strong></p>' +
          '<div class="font-mono text-sm text-[#8b949e] mb-4">File: ' + escapeHtml(preview.configPath) + '</div>' +
          '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">' +
          '<div><div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">Before</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.beforeHtml + '</div></div>' +
          '<div><div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">After</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.afterHtml + '</div></div>' +
          '</div>';

        document.getElementById('modal-body').innerHTML = bodyHtml;

        pendingConfirm = async () => {
          const res = await fetch('/api/deny-directory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ directory }),
          });
          const data = await res.json();
          if (data.success) {
            showToast(data.message);
            location.reload();
          } else {
            showToast(data.error || 'Failed to block directory', 'error');
          }
        };
      } catch (err) {
        closeModal();
        showToast('Failed to load preview', 'error');
      }
    }

    // Add allow directory rule
    async function addAllowDirectory() {
      const input = document.getElementById('new-directory-path');
      const directory = input.value.trim();
      if (!directory) {
        showToast('Please enter a directory path', 'error');
        return;
      }

      showModal('Allow Directory', '<p class="text-[#8b949e]">Loading preview...</p>', () => {});

      try {
        const previewRes = await fetch('/api/preview/allow-directory', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ directory }),
        });

        const preview = await previewRes.json();
        if (preview.error) {
          closeModal();
          showToast(preview.error, 'error');
          return;
        }

        const diff = generateDiffView(preview.before, preview.after);
        const bodyHtml =
          '<p class="text-sm text-[#c9d1d9] mb-4">This will allow Claude Code to access <strong>' + escapeHtml(directory) + '/**</strong></p>' +
          '<div class="font-mono text-sm text-[#8b949e] mb-4">File: ' + escapeHtml(preview.configPath) + '</div>' +
          '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">' +
          '<div><div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">Before</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.beforeHtml + '</div></div>' +
          '<div><div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">After</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.afterHtml + '</div></div>' +
          '</div>';

        document.getElementById('modal-body').innerHTML = bodyHtml;

        pendingConfirm = async () => {
          const res = await fetch('/api/allow-directory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ directory }),
          });
          const data = await res.json();
          if (data.success) {
            showToast(data.message);
            location.reload();
          } else {
            showToast(data.error || 'Failed to allow directory', 'error');
          }
        };
      } catch (err) {
        closeModal();
        showToast('Failed to load preview', 'error');
      }
    }

    // Remove permission rule
    async function removePermission(rule, type) {
      showModal('Remove Permission', '<p class="text-[#8b949e]">Loading preview...</p>', () => {});

      try {
        const previewRes = await fetch('/api/preview/remove-permission', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rule, type }),
        });

        const preview = await previewRes.json();
        if (preview.error) {
          closeModal();
          showToast(preview.error, 'error');
          return;
        }

        const diff = generateDiffView(preview.before, preview.after);
        const bodyHtml =
          '<p class="text-sm text-[#c9d1d9] mb-4">This will remove the <strong>' + type + '</strong> rule: <code>' + escapeHtml(rule) + '</code></p>' +
          '<div class="font-mono text-sm text-[#8b949e] mb-4">File: ' + escapeHtml(preview.configPath) + '</div>' +
          '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">' +
          '<div><div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">Before</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.beforeHtml + '</div></div>' +
          '<div><div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">After</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.afterHtml + '</div></div>' +
          '</div>';

        document.getElementById('modal-body').innerHTML = bodyHtml;

        pendingConfirm = async () => {
          const res = await fetch('/api/remove-permission', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule, type }),
          });
          const data = await res.json();
          if (data.success) {
            showToast(data.message);
            location.reload();
          } else {
            showToast(data.error || 'Failed to remove permission', 'error');
          }
        };
      } catch (err) {
        closeModal();
        showToast('Failed to load preview', 'error');
      }
    }

    // ============================================
    // Config Hierarchy Modal
    // ============================================

    function showConfigHierarchyModal() {
      const bodyHtml = \`
        <div class="space-y-4">
          <p class="text-sm text-[#c9d1d9]">
            Claude Code uses a <strong>two-tier configuration system</strong>:
          </p>
          
          <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4">
            <div class="flex items-center gap-2 mb-2">
              <span class="px-2 py-1 bg-[#58a6ff] text-white text-xs font-semibold rounded">1</span>
              <span class="font-semibold text-[#c9d1d9]">Global Settings</span>
              <code class="text-xs text-[#8b949e]">~/.claude/settings.json</code>
            </div>
            <ul class="text-sm text-[#8b949e] ml-8 list-disc space-y-1">
              <li>Applies to <strong>ALL</strong> projects</li>
              <li>User-level defaults</li>
              <li>Good for: SSH keys, AWS credentials, personal secrets</li>
            </ul>
          </div>
          
          <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4">
            <div class="flex items-center gap-2 mb-2">
              <span class="px-2 py-1 bg-[#238636] text-white text-xs font-semibold rounded">2</span>
              <span class="font-semibold text-[#c9d1d9]">Project Settings</span>
              <code class="text-xs text-[#8b949e]">.claude/settings.json</code>
            </div>
            <ul class="text-sm text-[#8b949e] ml-8 list-disc space-y-1">
              <li>Applies only to that specific project</li>
              <li>Overrides/extends global settings</li>
              <li>Good for: Project-specific MCP servers, team conventions</li>
            </ul>
          </div>
          
          <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4">
            <div class="text-sm font-semibold text-[#c9d1d9] mb-2">How They Merge</div>
            <div class="text-center text-sm text-[#8b949e]">
              <div class="inline-block text-left">
                <div class="flex items-center gap-2 mb-1">
                  <span class="w-4 text-center">↓</span>
                  <span>Global Settings (base)</span>
                </div>
                <div class="flex items-center gap-2 mb-1">
                  <span class="w-4 text-center">↓</span>
                  <span>Project Settings (override/extend)</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="w-4 text-center">↓</span>
                  <span class="text-[#3fb950]">Effective Config (what Claude uses)</span>
                </div>
              </div>
            </div>
          </div>
          
          <div class="bg-[#21262d] border border-[#30363d] rounded-lg p-4">
            <div class="text-sm font-semibold text-[#c9d1d9] mb-2">Example</div>
            <div class="text-xs text-[#8b949e] space-y-1">
              <div>Global denies: <code class="text-[#f85149]">~/.ssh/**</code></div>
              <div>Project denies: <code class="text-[#f85149]">.env</code></div>
              <div class="text-[#3fb950]">→ Effective: Both <code>~/.ssh/**</code> AND <code>.env</code> are blocked</div>
            </div>
          </div>
        </div>
      \`;
      
      showModal('Claude Code Configuration Hierarchy', bodyHtml, null);
      // Hide the confirm button for info-only modal
      document.getElementById('modal-confirm').style.display = 'none';
    }

    // ============================================
    // Security Profile Functions
    // ============================================

    // Apply security profile
    async function applyProfile(profileId) {
      showModal('Apply Security Profile', '<p class="text-[#8b949e]">Loading preview...</p>', () => {});

      try {
        const previewRes = await fetch('/api/preview/apply-profile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ profileId }),
        });

        const preview = await previewRes.json();
        if (preview.error) {
          closeModal();
          showToast(preview.error, 'error');
          return;
        }

        const diff = generateDiffView(preview.before, preview.after);
        const bodyHtml =
          '<p class="text-sm text-[#c9d1d9] mb-4">This will apply the <strong>' + escapeHtml(preview.profile.name) + '</strong> profile.</p>' +
          '<p class="text-sm text-[#8b949e] mb-4">' + escapeHtml(preview.profile.description) + '</p>' +
          '<div class="font-mono text-sm text-[#8b949e] mb-4">File: ' + escapeHtml(preview.configPath) + '</div>' +
          '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">' +
          '<div><div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">Before</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.beforeHtml + '</div></div>' +
          '<div><div class="text-xs font-semibold uppercase text-[#8b949e] mb-2">After</div>' +
          '<div class="bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs overflow-auto max-h-80 font-mono">' + diff.afterHtml + '</div></div>' +
          '</div>';

        document.getElementById('modal-body').innerHTML = bodyHtml;

        pendingConfirm = async () => {
          const res = await fetch('/api/apply-profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ profileId }),
          });
          const data = await res.json();
          if (data.success) {
            showToast(data.message);
            location.reload();
          } else {
            showToast(data.error || 'Failed to apply profile', 'error');
          }
        };
      } catch (err) {
        closeModal();
        showToast('Failed to load preview', 'error');
      }
    }
  </script>
</body>
</html>`;
}
