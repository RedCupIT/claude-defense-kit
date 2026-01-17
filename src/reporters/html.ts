import type {
  ScanResultsWithIssues,
  SecurityIssue,
  BlastRadiusItem,
  McpIntegrityResult,
  IntegrityStatus,
  ClaudeCodeConfig,
  ConfigInventory,
  EffectiveConfig,
  ConfigScopeType,
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
  id?: string,
): string {
  const colorClass = titleColor || "text-[rgba(255,255,255,0.6)]";
  const idAttr = id ? ` id="${id}"` : "";
  const contentIdAttr = id ? ` id="${id}-content"` : "";
  return `
    <section${idAttr} class="glass-card rounded-xl mb-4 overflow-hidden">
      <div class="px-5 py-3 border-b border-[rgba(255,255,255,0.1)]">
        <h2 class="text-sm font-semibold uppercase tracking-wide ${colorClass}">${title}</h2>
      </div>
      <div${contentIdAttr} class="px-5 py-4">
        ${content}
      </div>
    </section>`;
}

// Generate a finding card
function generateFindingCard(issue: SecurityIssue): string {
  const actionLabel = issue.type === "mcp-server" ? "Disable" : "Fix";
  const commandHtml = issue.command
    ? `<code class="block mt-2 text-xs text-[rgba(255,255,255,0.5)] bg-[rgba(0,0,0,0.3)] px-2 py-1 rounded overflow-x-auto">${escapeHtml(
        issue.command,
      )}</code>`
    : "";

  return `
    <div class="finding-card glass-card rounded-lg p-4 mb-3 last:mb-0"
         id="issue-${escapeHtml(issue.id)}" data-risk="${issue.risk}">
      <div class="flex justify-between items-start gap-4">
        <div class="flex-1 min-w-0">
          <h3 class="font-semibold text-white">${escapeHtml(issue.title)}</h3>
          <code class="text-sm text-[rgba(255,255,255,0.6)] break-all">${escapeHtml(
            issue.target,
          )}</code>
        </div>
        <button class="btn-fix btn-gradient shrink-0 px-3 py-1.5 rounded text-sm"
          onclick="fixIssue('${escapeHtml(issue.id)}', '${
            issue.action.type
          }', '${escapeHtml(issue.action.target)}')">
          ${actionLabel}
        </button>
      </div>
      <p class="text-sm text-[rgba(255,255,255,0.6)] mt-2">${escapeHtml(
        issue.description,
      )}</p>
      ${commandHtml}
      <div class="fixed-badge hidden mt-2 text-sm text-[#10b981]">&#10003; Fixed</div>
    </div>`;
}

// Generate a tool restriction card
function generateToolRestrictionCard(
  tool: (typeof TOOL_RESTRICTIONS)[0],
  isDisabled: boolean,
): string {
  const statusBadge = isDisabled
    ? '<span class="px-2 py-0.5 rounded text-xs font-medium bg-[#f85149] text-white">BLOCKED</span>'
    : '<span class="px-2 py-0.5 rounded text-xs font-medium bg-[#238636] text-white">ALLOWED</span>';

  const buttonLabel = isDisabled ? "Allow" : "Deny";
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
            tool.description,
          )}</span>
        </div>
        <button class="shrink-0 px-3 py-1.5 ${buttonClass} rounded text-sm font-medium hover:brightness-110 transition"
          onclick="${buttonAction}">
          ${buttonLabel}
        </button>
      </div>
      <p class="text-sm text-[rgba(255,255,255,0.6)] mt-2">${escapeHtml(
        tool.detail,
      )}</p>
    </div>`;
}

// Generate a bash command restriction card
function generateBashRestrictionCard(
  cmd: (typeof BASH_COMMAND_RESTRICTIONS)[0],
  isBlocked: boolean,
): string {
  const cardClass = isBlocked ? "finding-card fixed" : "finding-card";

  return `
    <div class="${cardClass} bg-[#21262d] border border-[#30363d] rounded-lg p-4 mb-3 last:mb-0"
         id="bash-${escapeHtml(cmd.command)}" data-risk="${cmd.risk}">
      <div class="flex justify-between items-start gap-4">
        <div class="flex-1 min-w-0">
          <h3 class="font-semibold text-[#c9d1d9]">${escapeHtml(
            cmd.command,
          )}</h3>
          <code class="text-sm text-[#8b949e] break-all">${escapeHtml(
            cmd.pattern,
          )}</code>
        </div>
        <button class="btn-fix shrink-0 px-3 py-1.5 bg-[#58a6ff] text-white rounded text-sm font-medium hover:brightness-110 transition"
          onclick="blockBashCommand('${escapeHtml(cmd.command)}', '${escapeHtml(
            cmd.pattern,
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
  currentValue: boolean | undefined,
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
            setting.name,
          )}</h3>
          <code class="text-sm text-[#8b949e]">${escapeHtml(
            setting.configKey,
          )}</code>
        </div>
        <span class="shrink-0 px-2 py-0.5 rounded text-xs font-medium ${
          isEnabled ? "bg-[#238636] text-white" : "bg-[#30363d] text-[#8b949e]"
        }">
          ${isEnabled ? "ON" : "OFF"}
        </span>
        <button class="shrink-0 px-3 py-1.5 bg-[#58a6ff] text-white rounded text-sm font-medium hover:brightness-110 transition"
          onclick="updateSandbox('${escapeHtml(
            setting.path,
          )}', ${JSON.stringify(newValue)}, '${escapeHtml(setting.name)}')">
          ${buttonLabel}
        </button>
      </div>
      <p class="text-sm text-[#8b949e] mt-2">${escapeHtml(
        setting.description,
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
          24,
        )}...</code></div>
        <div>Now: <code class="text-[#f0883e]">${item.currentHash?.slice(
          0,
          24,
        )}...</code></div>
      </div>`;
  } else if (item.status === "missing") {
    details = `<span class="text-[#f85149] text-xs">File not found: ${escapeHtml(
      item.targetPath || "unknown",
    )}</span>`;
  } else if (item.status === "unhashable") {
    details =
      '<span class="text-[#8b949e]">Cannot determine file to hash</span>';
  }

  const acceptButton =
    item.status === "changed" && item.currentHash && item.targetPath
      ? `<button class="shrink-0 px-3 py-1.5 bg-[#58a6ff] text-white rounded text-sm font-medium hover:brightness-110 transition"
         onclick="acceptHash('${escapeHtml(item.serverName)}', '${escapeHtml(
           item.targetPath,
         )}', '${escapeHtml(item.currentHash)}')">
         Accept
       </button>`
      : "";

  return `
    <div class="bg-[#21262d] border border-[#30363d] rounded-lg p-4 mb-3 last:mb-0"
         id="integrity-${escapeHtml(
           item.serverName.replace(/[^a-zA-Z0-9]/g, "-"),
         )}">
      <div class="flex justify-between items-start gap-4">
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-1">
            <span class="px-2 py-0.5 rounded text-xs font-medium ${bgClass} ${textClass}">${label}</span>
            <h3 class="font-semibold text-[#c9d1d9]">${escapeHtml(
              item.serverName,
            )}</h3>
          </div>
          ${
            item.targetPath
              ? `<code class="text-xs text-[#8b949e] break-all">${escapeHtml(
                  item.targetPath,
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
    (r) => r.includes("**") || r.endsWith("/"),
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
      `,
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
      `,
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
              profile.name,
            )}</h4>
            <p class="text-sm text-[#8b949e] mb-2">${escapeHtml(
              profile.description,
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

// Get scope badge color
function getScopeBadgeColor(scope: ConfigScopeType): string {
  switch (scope) {
    case "managed":
      return "bg-[#f85149]";
    case "local":
      return "bg-[#a371f7]";
    case "project":
      return "bg-[#238636]";
    case "user":
      return "bg-[#58a6ff]";
  }
}

// Get scope label
function getScopeLabel(scope: ConfigScopeType): string {
  switch (scope) {
    case "managed":
      return "IT-Managed";
    case "local":
      return "Local";
    case "project":
      return "Project";
    case "user":
      return "User";
  }
}

// Generate IT-Managed banner
function generateITManagedBanner(
  inventory: ConfigInventory | undefined,
): string {
  if (!inventory?.isITManaged) return "";

  const enforces = inventory.managed.enforces;
  const enforcementList: string[] = [];
  if (enforces.sandboxing) enforcementList.push("Sandbox");
  if (enforces.permissionRestrictions) enforcementList.push("Permissions");
  if (enforces.mcpRestrictions) enforcementList.push("MCP Servers");
  if (enforces.pluginRestrictions) enforcementList.push("Plugins");
  if (enforces.hookRestrictions) enforcementList.push("Hooks");

  return `
    <div class="bg-[#f85149]/20 border border-[#f85149] rounded-xl p-4 mb-4">
      <div class="flex items-start gap-3">
        <span class="text-2xl">🏢</span>
        <div class="flex-1">
          <div class="font-semibold text-white mb-1">IT-Managed Deployment Detected</div>
          <p class="text-sm text-[#8b949e] mb-2">
            Your organization has deployed managed settings that cannot be overridden.
          </p>
          ${
            enforcementList.length > 0
              ? `
          <div class="flex flex-wrap gap-2">
            ${enforcementList
              .map(
                (e) =>
                  `<span class="px-2 py-0.5 bg-[#f85149]/30 text-[#f85149] text-xs rounded">${e}</span>`,
              )
              .join("")}
          </div>
          `
              : ""
          }
          <div class="text-xs text-[#8b949e] mt-2">
            <code>${escapeHtml(inventory.managed.path)}</code>
          </div>
        </div>
      </div>
    </div>`;
}

// Generate Configuration Inventory section
function generateConfigInventoryContent(
  inventory: ConfigInventory | undefined,
): string {
  if (!inventory)
    return '<p class="text-sm text-[#8b949e] italic">Configuration inventory not available.</p>';

  const managedHtml = inventory.managed.detected
    ? `
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mb-3">
      <div class="flex items-center gap-2 mb-2">
        <span class="px-2 py-0.5 bg-[#f85149] text-white text-xs font-semibold rounded">MANAGED</span>
        <span class="text-sm text-[#c9d1d9] font-medium">IT-Deployed Configuration</span>
      </div>
      <a href="/api/config/view?path=${encodeURIComponent(
        inventory.managed.path,
      )}" target="_blank" class="text-xs text-[#58a6ff] hover:underline block mb-2">${escapeHtml(
        inventory.managed.path,
      )}</a>
      <div class="text-xs text-[#8b949e]">
        ${
          inventory.managed.settings
            ? "✓ managed-settings.json"
            : "✗ managed-settings.json"
        }
        ${inventory.managed.mcpConfig ? " · ✓ managed-mcp.json" : ""}
      </div>
    </div>
  `
    : `
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mb-3 opacity-50">
      <div class="flex items-center gap-2 mb-2">
        <span class="px-2 py-0.5 bg-[#30363d] text-[#8b949e] text-xs font-semibold rounded">MANAGED</span>
        <span class="text-sm text-[#8b949e]">Not Detected</span>
      </div>
      <p class="text-xs text-[#8b949e]">No IT-managed configuration found.</p>
    </div>
  `;

  const userHtml = `
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mb-3">
      <div class="flex items-center gap-2 mb-2">
        <span class="px-2 py-0.5 bg-[#58a6ff] text-white text-xs font-semibold rounded">USER</span>
        <span class="text-sm text-[#c9d1d9] font-medium">User Configuration</span>
      </div>
      <div class="text-xs text-[#8b949e] space-y-1">
        <div>${
          inventory.user.settings ? "✓" : "✗"
        } <a href="/api/config/view?path=${encodeURIComponent(
          inventory.user.settingsPath,
        )}" target="_blank" class="text-[#58a6ff] hover:underline">${escapeHtml(
          inventory.user.settingsPath.replace(process.env.HOME || "", "~"),
        )}</a></div>
        <div>${
          inventory.user.mcpConfig ? "✓" : "✗"
        } <a href="/api/config/view?path=${encodeURIComponent(
          inventory.user.mcpPath,
        )}" target="_blank" class="text-[#58a6ff] hover:underline">${escapeHtml(
          inventory.user.mcpPath.replace(process.env.HOME || "", "~"),
        )}</a></div>
        <div>${inventory.user.agentCount} agents · ${
          inventory.user.hasClaudeMd ? "✓" : "✗"
        } CLAUDE.md</div>
      </div>
    </div>
  `;

  const projectsHtml =
    inventory.projects.length > 0
      ? `
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4">
      <div class="flex items-center justify-between mb-3">
        <div class="flex items-center gap-2">
          <span class="px-2 py-0.5 bg-[#238636] text-white text-xs font-semibold rounded">PROJECTS</span>
          <span class="text-sm text-[#c9d1d9] font-medium">${
            inventory.projects.length
          } Discovered</span>
        </div>
        <button onclick="toggleProjectList()" class="text-xs text-[#58a6ff] hover:underline">
          Show/Hide
        </button>
      </div>
      <div id="project-list" class="hidden space-y-2 max-h-48 overflow-y-auto">
        ${inventory.projects
          .slice(0, 20)
          .map(
            (p) => `
          <div class="flex items-center justify-between text-xs py-1 border-b border-[#30363d] last:border-0">
            <code class="text-[#8b949e]">${escapeHtml(
              p.path.replace(process.env.HOME || "", "~"),
            )}</code>
            <div class="flex gap-1">
              ${
                p.settings.shared
                  ? '<span class="text-[#238636]">✓</span>'
                  : '<span class="text-[#30363d]">✗</span>'
              }
              ${p.hasClaudeMd ? '<span class="text-[#58a6ff]">📄</span>' : ""}
            </div>
          </div>
        `,
          )
          .join("")}
        ${
          inventory.projects.length > 20
            ? `<div class="text-xs text-[#8b949e] pt-2">...and ${
                inventory.projects.length - 20
              } more</div>`
            : ""
        }
      </div>
    </div>
  `
      : `
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 opacity-50">
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 bg-[#30363d] text-[#8b949e] text-xs font-semibold rounded">PROJECTS</span>
        <span class="text-sm text-[#8b949e]">None Discovered</span>
      </div>
    </div>
  `;

  return `
    <p class="text-sm text-[#8b949e] mb-4">
      Overview of all Claude Code configuration files on this system.
    </p>
    ${managedHtml}
    ${userHtml}
    ${projectsHtml}
  `;
}

// Generate Effective Config section
function generateEffectiveConfigContent(
  effectiveConfig: EffectiveConfig | undefined,
  inventory: ConfigInventory | undefined,
): string {
  if (!effectiveConfig)
    return '<p class="text-sm text-[#8b949e] italic">Effective configuration not available.</p>';

  const permissionSources = effectiveConfig.permissions.sources || [];
  const denyRules = permissionSources.filter((s) => s.type === "deny");
  const allowRules = permissionSources.filter((s) => s.type === "allow");
  const shadowedRules = effectiveConfig.shadowedRules || [];

  const denyHtml =
    denyRules.length > 0
      ? denyRules
          .map(
            (s) => `
    <div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0">
      <code class="text-sm text-[#f85149]">${escapeHtml(s.rule)}</code>
      <span class="px-2 py-0.5 ${getScopeBadgeColor(
        s.scope,
      )} text-white text-xs rounded">${getScopeLabel(s.scope)}</span>
    </div>
  `,
          )
          .join("")
      : '<p class="text-xs text-[#8b949e] italic">No deny rules configured.</p>';

  const allowHtml =
    allowRules.length > 0
      ? allowRules
          .map(
            (s) => `
    <div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0">
      <code class="text-sm text-[#3fb950]">${escapeHtml(s.rule)}</code>
      <span class="px-2 py-0.5 ${getScopeBadgeColor(
        s.scope,
      )} text-white text-xs rounded">${getScopeLabel(s.scope)}</span>
    </div>
  `,
          )
          .join("")
      : '<p class="text-xs text-[#8b949e] italic">No allow rules configured.</p>';

  const shadowedHtml =
    shadowedRules.length > 0
      ? `
    <div class="mt-4 pt-4 border-t border-[#30363d]">
      <div class="text-xs font-semibold text-[#d29922] uppercase mb-2">⚠️ Shadowed Rules</div>
      <p class="text-xs text-[#8b949e] mb-2">These rules are set but overridden by higher-precedence config:</p>
      ${shadowedRules
        .map(
          (s) => `
        <div class="flex items-center gap-2 py-1 text-xs">
          <code class="text-[#8b949e] line-through">${escapeHtml(s.rule)}</code>
          <span class="text-[#8b949e]">set at ${getScopeLabel(
            s.setAt,
          )}, overridden by ${getScopeLabel(s.overriddenBy)}</span>
        </div>
      `,
        )
        .join("")}
    </div>
  `
      : "";

  const sandboxHtml = effectiveConfig.sandbox
    ? `
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mt-4">
      <div class="flex items-center justify-between mb-2">
        <span class="text-sm font-semibold text-[#c9d1d9]">Sandbox Configuration</span>
        <span class="px-2 py-0.5 ${getScopeBadgeColor(
          effectiveConfig.sandboxSource!,
        )} text-white text-xs rounded">${getScopeLabel(
          effectiveConfig.sandboxSource!,
        )}</span>
      </div>
      <div class="text-xs text-[#8b949e]">
        <div>Enabled: <span class="${
          effectiveConfig.sandbox.enabled ? "text-[#3fb950]" : "text-[#f85149]"
        }">${effectiveConfig.sandbox.enabled ? "Yes" : "No"}</span></div>
      </div>
    </div>
  `
    : "";

  return `
    <p class="text-sm text-[#8b949e] mb-4">
      The merged configuration that Claude Code actually uses, with source attribution.
    </p>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4">
        <div class="text-xs font-semibold text-[#f85149] uppercase mb-2">Deny Rules (${
          denyRules.length
        })</div>
        ${denyHtml}
      </div>
      <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4">
        <div class="text-xs font-semibold text-[#3fb950] uppercase mb-2">Allow Rules (${
          allowRules.length
        })</div>
        ${allowHtml}
      </div>
    </div>
    ${shadowedHtml}
    ${sandboxHtml}
    ${generateToolRestrictionsHtml(effectiveConfig)}
    ${generateMcpRestrictionsHtml(effectiveConfig)}
    ${generateSecuritySettingsHtml(effectiveConfig)}
  `;
}

// Generate tool restrictions HTML for effective config
function generateToolRestrictionsHtml(
  effectiveConfig: EffectiveConfig,
): string {
  const toolSources = effectiveConfig.tools?.sources || [];
  const disallowed = toolSources.filter((s) => s.type === "disallowed");
  const allowed = toolSources.filter((s) => s.type === "allowed");

  if (disallowed.length === 0 && allowed.length === 0) return "";

  const disallowedHtml =
    disallowed.length > 0
      ? disallowed
          .map(
            (s) => `
      <div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0">
        <code class="text-sm text-[#f85149]">${escapeHtml(s.tool)}</code>
        <span class="px-2 py-0.5 ${getScopeBadgeColor(
          s.scope,
        )} text-white text-xs rounded">${getScopeLabel(s.scope)}</span>
      </div>
    `,
          )
          .join("")
      : '<p class="text-xs text-[#8b949e] italic">No tools blocked.</p>';

  const allowedHtml =
    allowed.length > 0
      ? allowed
          .map(
            (s) => `
      <div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0">
        <code class="text-sm text-[#3fb950]">${escapeHtml(s.tool)}</code>
        <span class="px-2 py-0.5 ${getScopeBadgeColor(
          s.scope,
        )} text-white text-xs rounded">${getScopeLabel(s.scope)}</span>
      </div>
    `,
          )
          .join("")
      : '<p class="text-xs text-[#8b949e] italic">No tools explicitly allowed.</p>';

  return `
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mt-4">
      <div class="text-xs font-semibold text-[#c9d1d9] uppercase mb-3">Tool Restrictions</div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <div class="text-xs font-semibold text-[#f85149] mb-2">Blocked (${disallowed.length})</div>
          ${disallowedHtml}
        </div>
        <div>
          <div class="text-xs font-semibold text-[#3fb950] mb-2">Allowed (${allowed.length})</div>
          ${allowedHtml}
        </div>
      </div>
    </div>
  `;
}

// Generate MCP server restrictions HTML for effective config
function generateMcpRestrictionsHtml(effectiveConfig: EffectiveConfig): string {
  const mcpSources = effectiveConfig.mcpRestrictions?.sources || [];
  const denied = mcpSources.filter((s) => s.type === "denied");
  const allowed = mcpSources.filter((s) => s.type === "allowed");

  if (denied.length === 0 && allowed.length === 0) return "";

  const deniedHtml =
    denied.length > 0
      ? denied
          .map(
            (s) => `
      <div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0">
        <code class="text-sm text-[#f85149]">${escapeHtml(s.server)}</code>
        <span class="px-2 py-0.5 ${getScopeBadgeColor(
          s.scope,
        )} text-white text-xs rounded">${getScopeLabel(s.scope)}</span>
      </div>
    `,
          )
          .join("")
      : '<p class="text-xs text-[#8b949e] italic">No servers blocked.</p>';

  const allowedHtml =
    allowed.length > 0
      ? allowed
          .map(
            (s) => `
      <div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0">
        <code class="text-sm text-[#3fb950]">${escapeHtml(s.server)}</code>
        <span class="px-2 py-0.5 ${getScopeBadgeColor(
          s.scope,
        )} text-white text-xs rounded">${getScopeLabel(s.scope)}</span>
      </div>
    `,
          )
          .join("")
      : '<p class="text-xs text-[#8b949e] italic">No allowlist configured.</p>';

  return `
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mt-4">
      <div class="text-xs font-semibold text-[#c9d1d9] uppercase mb-3">MCP Server Restrictions</div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <div class="text-xs font-semibold text-[#f85149] mb-2">Denied (${denied.length})</div>
          ${deniedHtml}
        </div>
        <div>
          <div class="text-xs font-semibold text-[#3fb950] mb-2">Allowed (${allowed.length})</div>
          ${allowedHtml}
        </div>
      </div>
    </div>
  `;
}

// Generate security settings HTML (hooks, bypass mode)
function generateSecuritySettingsHtml(
  effectiveConfig: EffectiveConfig,
): string {
  const hooks = effectiveConfig.hooks;
  const bypassMode = effectiveConfig.bypassMode;

  const hasHookSettings =
    hooks?.allowManagedHooksOnly || hooks?.disableAllHooks;
  const hasBypassSetting = bypassMode?.disabled;

  if (!hasHookSettings && !hasBypassSetting) return "";

  const items: string[] = [];

  if (hooks?.disableAllHooks) {
    items.push(`
      <div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0">
        <span class="text-sm text-[#c9d1d9]">All Hooks Disabled</span>
        <span class="px-2 py-0.5 ${getScopeBadgeColor(
          hooks.source!,
        )} text-white text-xs rounded">${getScopeLabel(hooks.source!)}</span>
      </div>
    `);
  } else if (hooks?.allowManagedHooksOnly) {
    items.push(`
      <div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0">
        <span class="text-sm text-[#c9d1d9]">Managed Hooks Only</span>
        <span class="px-2 py-0.5 ${getScopeBadgeColor(
          hooks.source!,
        )} text-white text-xs rounded">${getScopeLabel(hooks.source!)}</span>
      </div>
    `);
  }

  if (bypassMode?.disabled) {
    items.push(`
      <div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0">
        <span class="text-sm text-[#c9d1d9]">Bypass Mode Disabled</span>
        <span class="px-2 py-0.5 ${getScopeBadgeColor(
          bypassMode.source!,
        )} text-white text-xs rounded">${getScopeLabel(
          bypassMode.source!,
        )}</span>
      </div>
    `);
  }

  return `
    <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mt-4">
      <div class="text-xs font-semibold text-[#c9d1d9] uppercase mb-3">Security Settings</div>
      ${items.join("")}
    </div>
  `;
}

// Generate scope selector dropdown
function generateScopeSelector(
  inventory: ConfigInventory | undefined,
  currentScope: { type: string; projectPath?: string },
): string {
  if (!inventory || inventory.projects.length === 0) return "";

  const options = [
    `<option value="" ${
      currentScope.type === "global" ? "selected" : ""
    }>Global (All Projects)</option>`,
    ...inventory.projects
      .slice(0, 20)
      .map(
        (p) =>
          `<option value="${escapeHtml(p.path)}" ${
            currentScope.type === "project" &&
            currentScope.projectPath === p.path
              ? "selected"
              : ""
          }>${escapeHtml(p.name)}</option>`,
      ),
  ].join("");

  return `
    <div class="flex items-center gap-2">
      <span class="text-xs text-[#8b949e]">Scope:</span>
      <select id="scope-selector" onchange="switchScope(this.value)" 
        class="px-2 py-1 bg-[#21262d] border border-[#30363d] rounded text-xs text-[#c9d1d9] focus:border-[#58a6ff] focus:outline-none">
        ${options}
      </select>
    </div>
  `;
}

// Generate a severity section (always shown, even if empty)
function generateSeveritySection(
  risk: "high" | "medium" | "low",
  issues: SecurityIssue[],
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
        "~",
      )}</strong>`
    : "Global settings that apply to <strong>all projects</strong>";

  // Generate blast radius list
  const blastRadiusHtml = uniqueBlastRadius
    .slice(0, 8)
    .map(
      (item) =>
        `<li class="text-sm text-[#c9d1d9] py-1">${escapeHtml(
          item.description,
        )}</li>`,
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
            chain.name,
          )}</div>
          <div class="text-sm text-[#8b949e] mb-2">${escapeHtml(
            chain.scenario,
          )}</div>
          <div class="text-sm text-[#f85149]"><span class="font-semibold">Impact:</span> ${escapeHtml(
            chain.impact,
          )}</div>
        </div>
      `,
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
        actualConfigPath,
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
    generateToolRestrictionCard(tool, disabledTools.has(tool.name)),
  ).join("");

  const toolRestrictionsContent = `
    <p class="text-sm text-[#8b949e] mb-4">Disable Claude Code tools to reduce attack surface.</p>
    ${toolRestrictionsCards}`;

  // Generate bash command restrictions section
  const bashRestrictionsCards = BASH_COMMAND_RESTRICTIONS.map((cmd) =>
    generateBashRestrictionCard(cmd, denyPatterns.has(cmd.pattern)),
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
    generateSandboxCard(setting, getSandboxValue(setting.path)),
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
  <!-- Navigation Sidebar - Wizard Steps -->
  <nav id="sidebar" class="glass-sidebar fixed left-0 top-0 h-full w-56 pt-6 px-4 overflow-y-auto z-50">
    <!-- Logo -->
    <div class="flex flex-col items-center mb-6 pb-4 border-b border-[rgba(255,255,255,0.1)]">
      <div class="mb-2">${biLogoSvg}</div>
      <span class="text-sm font-semibold text-white tracking-tight">Claude Defense Kit</span>
    </div>
    
    <div class="text-xs font-semibold text-[rgba(255,255,255,0.5)] uppercase tracking-wider mb-3 px-2">Setup Wizard</div>
    
    <!-- Step 1: Environment Overview -->
    <div class="wizard-step-nav active" data-step="1" onclick="goToStep(1)">
      <div class="flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer hover:bg-[rgba(255,255,255,0.05)] transition">
        <div class="step-indicator w-6 h-6 rounded-full bg-[var(--primary)] text-[#0a2020] flex items-center justify-center text-xs font-bold">1</div>
        <span class="text-sm text-white">Environment Overview</span>
      </div>
    </div>
    
    <!-- Step 2: Select Scope -->
    <div class="wizard-step-nav" data-step="2" onclick="goToStep(2)">
      <div class="flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer hover:bg-[rgba(255,255,255,0.05)] transition">
        <div class="step-indicator w-6 h-6 rounded-full bg-[rgba(255,255,255,0.2)] text-white flex items-center justify-center text-xs font-bold">2</div>
        <span class="text-sm text-[rgba(255,255,255,0.6)]">Select Scope</span>
      </div>
    </div>
    
    <!-- Step 3: Remediation -->
    <div class="wizard-step-nav" data-step="3" onclick="goToStep(3)">
      <div class="flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer hover:bg-[rgba(255,255,255,0.05)] transition">
        <div class="step-indicator w-6 h-6 rounded-full bg-[rgba(255,255,255,0.2)] text-white flex items-center justify-center text-xs font-bold">3</div>
        <span class="text-sm text-[rgba(255,255,255,0.6)]">Remediation</span>
      </div>
    </div>
    
  </nav>

  <!-- Main Content Wrapper (offset from sidebar) -->
  <div class="ml-56 min-h-screen relative z-10">
  

  <!-- Wizard Container -->
  <div id="wizard-container" class="max-w-4xl px-6 py-6">
    
    <!-- STEP 1: Environment Overview -->
    <div class="wizard-step" data-step="1">
      
      <div class="text-center mb-8">
        <h2 class="text-2xl font-bold text-white mb-2">Environment Overview</h2>
        <p class="text-[rgba(255,255,255,0.6)]">Here's what we found on your system</p>
      </div>
      
      <!-- IT-Managed Banner -->
      ${generateITManagedBanner(results.configInventory)}
      
      <!-- ========== PART 1: WHAT WE DISCOVERED ========== -->
      <div class="mb-8">
        <div class="text-xs font-semibold text-[rgba(255,255,255,0.4)] uppercase tracking-wider mb-4">What We Discovered</div>
        
        <!-- Claude Code Installation -->
        <div class="glass-card rounded-xl p-5 mb-4">
          <div class="text-sm font-semibold text-[rgba(255,255,255,0.5)] uppercase tracking-wider mb-3">Claude Code Installation</div>
          <div class="flex items-center gap-2 mb-1">
            <span class="text-[#c9d1d9] font-medium">Claude Code</span>
            <span class="text-[#8b949e]">v${escapeHtml(version)}</span>
            ${instBadge}
            ${instStatusExplanation}
          </div>
          <p class="text-xs text-[#8b949e]">↳ We track installation integrity to detect tampering or unexpected changes.</p>
        </div>
        
        <!-- Identity -->
        ${
          identityLine
            ? `
        <div class="glass-card rounded-xl p-5 mb-4">
          <div class="text-sm font-semibold text-[rgba(255,255,255,0.5)] uppercase tracking-wider mb-3">Your Identity</div>
          ${identityLine}
          <p class="text-xs text-[#8b949e] mt-1">↳ This is the account Claude Code uses. If compromised, attackers could act as you.</p>
        </div>
        `
            : ""
        }
        
        <!-- Configurations (Combined Hierarchy + Discovered) -->
        <div class="glass-card rounded-xl p-5 mb-4">
          <div class="flex items-center justify-between mb-4">
            <div>
              <div class="text-sm font-semibold text-[rgba(255,255,255,0.5)] uppercase tracking-wider">Claude Code Configurations</div>
              <p class="text-xs text-[rgba(255,255,255,0.4)] mt-1">These JSON files control Claude Code's permissions, allowed tools, MCP servers, and security settings. Higher-precedence configs (like IT-Managed) override lower ones.</p>
            </div>
            <button onclick="showConfigHierarchyModal()" class="text-xs text-[#58a6ff] hover:underline flex items-center gap-1 shrink-0">
              <span>ℹ️</span> Learn about hierarchy
            </button>
          </div>
          
          <!-- Managed Config -->
          <div class="border-l-4 ${
            results.configInventory?.isITManaged
              ? "border-[#f85149]"
              : "border-[#30363d]"
          } pl-4 mb-4">
            <div class="flex items-center gap-2 mb-1">
              <span class="px-2 py-0.5 ${
                results.configInventory?.isITManaged
                  ? "bg-[#f85149]"
                  : "bg-[#30363d]"
              } text-white text-xs font-semibold rounded">MANAGED</span>
              <span class="text-sm ${
                results.configInventory?.isITManaged
                  ? "text-white"
                  : "text-[#8b949e]"
              }">IT-Deployed (Highest Priority)</span>
            </div>
            ${
              results.configInventory?.isITManaged
                ? `<a href="/api/config/view?path=${encodeURIComponent(
                    results.configInventory.managed.path,
                  )}" target="_blank" class="text-xs text-[#58a6ff] hover:underline">${escapeHtml(
                    results.configInventory.managed.path,
                  )}</a>`
                : '<p class="text-xs text-[#8b949e]">Not detected</p>'
            }
          </div>
          
          <!-- User Config -->
          <div class="border-l-4 border-[#58a6ff] pl-4 mb-4">
            <div class="flex items-center gap-2 mb-1">
              <span class="px-2 py-0.5 bg-[#58a6ff] text-white text-xs font-semibold rounded">USER</span>
              <span class="text-sm text-white">Global Settings</span>
            </div>
            <div class="text-xs text-[#8b949e] space-y-1">
              <div>${
                results.configInventory?.user.settings ? "✓" : "✗"
              } <a href="/api/config/view?path=${encodeURIComponent(
                results.configInventory?.user.settingsPath || "",
              )}" target="_blank" class="text-[#58a6ff] hover:underline">${escapeHtml(
                (results.configInventory?.user.settingsPath || "").replace(
                  process.env.HOME || "",
                  "~",
                ),
              )}</a></div>
              <div>${
                results.configInventory?.user.mcpConfig ? "✓" : "✗"
              } <a href="/api/config/view?path=${encodeURIComponent(
                results.configInventory?.user.mcpPath || "",
              )}" target="_blank" class="text-[#58a6ff] hover:underline">${escapeHtml(
                (results.configInventory?.user.mcpPath || "").replace(
                  process.env.HOME || "",
                  "~",
                ),
              )}</a></div>
            </div>
          </div>
          
          <!-- Project Configs -->
          <div class="border-l-4 border-[#238636] pl-4">
            <div class="flex items-center justify-between mb-1">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 bg-[#238636] text-white text-xs font-semibold rounded">PROJECT</span>
                <span class="text-sm text-white">${
                  results.configInventory?.projects.length || 0
                } Project Configs</span>
              </div>
              ${
                (results.configInventory?.projects.length || 0) > 0
                  ? '<button onclick="toggleProjectList()" class="text-xs text-[#58a6ff] hover:underline">Show/Hide</button>'
                  : ""
              }
            </div>
            <code class="text-xs text-[#8b949e]">.claude/settings.json</code> or <code class="text-xs text-[#a371f7]">.claude/settings.local.json</code>
            ${
              (results.configInventory?.projects.length || 0) > 0
                ? `
            <div id="project-list" class="hidden mt-2 space-y-1 max-h-32 overflow-y-auto">
              ${results.configInventory?.projects
                .slice(0, 10)
                .map((p) => {
                  // Show both shared and local if they exist
                  const hasShared = p.settings.shared;
                  const hasLocal = p.settings.local;
                  const badges = [];
                  if (hasShared)
                    badges.push(
                      '<span class="px-1 py-0.5 bg-[#238636] text-white text-[10px] rounded">shared</span>',
                    );
                  if (hasLocal)
                    badges.push(
                      '<span class="px-1 py-0.5 bg-[#a371f7] text-white text-[10px] rounded">local</span>',
                    );
                  const settingsFile = hasLocal
                    ? "/.claude/settings.local.json"
                    : hasShared
                      ? "/.claude/settings.json"
                      : "/.claude/settings.json";
                  return `
                <div class="text-xs py-0.5 flex items-center gap-2">
                  <a href="/api/config/view?path=${encodeURIComponent(
                    p.path + settingsFile,
                  )}" target="_blank" class="text-[#58a6ff] hover:underline">${escapeHtml(
                    p.path.replace(process.env.HOME || "", "~"),
                  )}</a>
                  ${badges.join(" ")}
                </div>
              `;
                })
                .join("")}
              ${
                (results.configInventory?.projects.length || 0) > 10
                  ? `<div class="text-xs text-[#8b949e]">...and ${
                      (results.configInventory?.projects.length || 0) - 10
                    } more</div>`
                  : ""
              }
            </div>
            `
                : ""
            }
          </div>
        </div>
        
      </div>

      <!-- ========== PART 2: SECURITY SCAN RESULTS ========== -->
      <div class="mb-6">
        <div class="text-xs font-semibold text-[rgba(255,255,255,0.4)] uppercase tracking-wider mb-4">Security Scan Results</div>
        
        <!-- Stats Cards -->
        <div class="grid grid-cols-3 gap-4 mb-4">
          <div class="glass-card rounded-xl p-5 text-center">
            <div class="text-3xl font-bold text-white mb-1">${
              results.configInventory?.isITManaged ? "1" : "0"
            }</div>
            <div class="text-sm text-[rgba(255,255,255,0.6)]">Managed Config</div>
          </div>
          <div class="glass-card rounded-xl p-5 text-center">
            <div class="text-3xl font-bold text-white mb-1">${
              results.configInventory?.projects.length || 0
            }</div>
            <div class="text-sm text-[rgba(255,255,255,0.6)]">Projects Found</div>
          </div>
          <div class="glass-card rounded-xl p-5 text-center">
            <div class="text-3xl font-bold ${
              totalIssues > 0 ? "text-[#f85149]" : "text-[#3fb950]"
            } mb-1">${totalIssues}</div>
            <div class="text-sm text-[rgba(255,255,255,0.6)]">Issues Found</div>
          </div>
        </div>
        
        <!-- Issue Breakdown -->
        <div class="glass-card rounded-xl p-5 mb-4">
          <div class="text-sm font-semibold text-[rgba(255,255,255,0.5)] uppercase tracking-wider mb-3">Issue Breakdown</div>
          <p class="text-sm text-[#c9d1d9] mb-3">
            Found <strong>${totalIssues}</strong> security ${
              totalIssues === 1 ? "issue" : "issues"
            }:
          </p>
          ${issueBreakdown}
        </div>
        
        <!-- Why This Matters -->
        <div class="glass-card rounded-xl p-5 mb-4">
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
        </div>
        
        <!-- What's at Risk -->
        ${generateSection(
          "WHAT'S AT RISK",
          whatsAtRiskContent,
          undefined,
          "whats-at-risk",
        )}
      </div>
      
      <!-- Navigation -->
      <div class="flex justify-end mt-6">
        <button onclick="goToStep(2)" class="btn-gradient px-6 py-3 rounded-lg font-semibold">
          Continue →
        </button>
      </div>
    </div>
    
    <!-- STEP 2: Select Scope (was Step 4) -->
    <div class="wizard-step hidden" data-step="2">
      <div class="text-center mb-8">
        <h2 class="text-2xl font-bold text-white mb-2">Select Scope to Remediate</h2>
        <p class="text-[rgba(255,255,255,0.6)]">Choose which configuration you want to modify</p>
      </div>
      
      <!-- Best Practices Guidance -->
      <div class="glass-card rounded-xl p-5 mb-6 border-l-4 border-[var(--primary)]">
        <div class="flex items-start gap-3">
          <span class="text-xl">💡</span>
          <div>
            <div class="font-semibold text-white mb-2">Recommended Strategy</div>
            <p class="text-sm text-[rgba(255,255,255,0.7)] mb-3">
              <strong class="text-[var(--primary)]">Lock down your Global config tightly</strong> — it serves as the secure baseline for ALL projects:
            </p>
            <ul class="text-sm text-[rgba(255,255,255,0.6)] space-y-1 mb-3 ml-4">
              <li>• Block sensitive directories (~/.ssh, ~/.aws, ~/.gnupg)</li>
              <li>• Restrict dangerous tools and commands</li>
              <li>• Deny access to personal credentials</li>
            </ul>
            <p class="text-sm text-[rgba(255,255,255,0.7)] mb-2">
              <strong class="text-[#238636]">Project configs can be more permissive</strong> for specific needs:
            </p>
            <ul class="text-sm text-[rgba(255,255,255,0.6)] space-y-1 ml-4">
              <li>• Allow project-specific MCP servers</li>
              <li>• Enable tools needed for that project</li>
              <li>• Override global restrictions when necessary</li>
            </ul>
            <p class="text-xs text-[rgba(255,255,255,0.4)] mt-3 pt-3 border-t border-[rgba(255,255,255,0.1)]">
              Think of it as: <strong>Global = secure baseline</strong>, <strong>Project = targeted exceptions</strong>
            </p>
          </div>
        </div>
      </div>
      
      <div class="space-y-4 mb-6">
        <!-- Global Option -->
        <label class="glass-card rounded-xl p-5 block cursor-pointer hover:border-[var(--primary)] transition">
          <div class="flex items-start gap-4">
            <input type="radio" name="scope" value="global" class="mt-1" checked onchange="selectScope('global')">
            <div class="flex-1">
              <div class="flex items-center gap-2 mb-1">
                <span class="px-2 py-0.5 bg-[#58a6ff] text-white text-xs font-semibold rounded">GLOBAL</span>
                <span class="font-semibold text-white">User Settings</span>
              </div>
              <code class="text-xs text-[#8b949e] block mb-2">~/.claude/settings.json</code>
              <p class="text-sm text-[#8b949e]">Applies to <strong>all projects</strong>. Good for protecting SSH keys, AWS credentials, and personal secrets.</p>
              <div class="mt-2 text-xs text-[#d29922]">${
                highIssues.length
              } high, ${mediumIssues.length} medium, ${
                lowIssues.length
              } low risk issues</div>
            </div>
          </div>
        </label>
        
        <!-- Project Options -->
        ${
          results.configInventory?.projects
            .slice(0, 5)
            .map((p, i) => {
              const hasShared = p.settings.shared;
              const hasLocal = p.settings.local;
              const settingsFile = hasLocal
                ? "settings.local.json"
                : "settings.json";
              const badges = [];
              if (hasShared)
                badges.push(
                  '<span class="px-1 py-0.5 bg-[#238636] text-white text-[10px] rounded ml-2">shared</span>',
                );
              if (hasLocal)
                badges.push(
                  '<span class="px-1 py-0.5 bg-[#a371f7] text-white text-[10px] rounded ml-2">local</span>',
                );
              return `
        <label class="glass-card rounded-xl p-5 block cursor-pointer hover:border-[var(--primary)] transition">
          <div class="flex items-start gap-4">
            <input type="radio" name="scope" value="${escapeHtml(
              p.path,
            )}" class="mt-1" onchange="selectScope('project', '${escapeHtml(
              p.path,
            )}')">
            <div class="flex-1">
              <div class="flex items-center gap-2 mb-1">
                <span class="px-2 py-0.5 bg-[#238636] text-white text-xs font-semibold rounded">PROJECT</span>
                <span class="font-semibold text-white">${escapeHtml(
                  p.name,
                )}</span>
                ${badges.join("")}
              </div>
              <code class="text-xs text-[#8b949e] block mb-2">${escapeHtml(
                p.path.replace(process.env.HOME || "", "~"),
              )}/.claude/${settingsFile}</code>
              <p class="text-sm text-[#8b949e]">Project-specific settings that override global config.</p>
            </div>
          </div>
        </label>
        `;
            })
            .join("") || ""
        }
      </div>
      
      ${
        results.configInventory?.isITManaged
          ? `
      <div class="bg-[#d29922]/20 border border-[#d29922] rounded-xl p-4 mb-6">
        <div class="flex items-start gap-3">
          <span class="text-xl">⚠️</span>
          <div>
            <div class="font-semibold text-white mb-1">IT-Managed Settings Active</div>
            <p class="text-sm text-[#8b949e]">Some settings may be overridden by your organization's managed configuration and cannot be changed.</p>
          </div>
        </div>
      </div>
      `
          : ""
      }
      
      <!-- Navigation -->
      <div class="flex justify-between mt-6">
        <button onclick="goToStep(1)" class="btn-secondary px-6 py-3 rounded-lg font-semibold">
          ← Back
        </button>
        <button onclick="goToStep(3)" class="btn-gradient px-6 py-3 rounded-lg font-semibold">
          View Issues →
        </button>
      </div>
    </div>
    
    <!-- STEP 3: Remediation (was Step 5) -->
    <div class="wizard-step hidden" data-step="3">
      <div class="text-center mb-8">
        <h2 class="text-2xl font-bold text-white mb-2">Remediation</h2>
        <div class="flex items-center justify-center gap-2 mb-2">
          <span id="selected-scope-badge" class="px-2 py-0.5 ${
            isProjectScope ? "bg-[#238636]" : "bg-[#58a6ff]"
          } text-white text-xs font-semibold rounded">${scopeLabel}</span>
          <span id="selected-scope-label" class="text-[var(--primary)] font-medium">${
            isProjectScope
              ? escapeHtml(scope.projectPath?.split("/").pop() || "Project")
              : "Global Settings"
          }</span>
        </div>
        <code id="selected-scope-path" class="text-xs text-[rgba(255,255,255,0.5)]">${escapeHtml(
          actualConfigPath,
        )}</code>
        <div class="mt-3">
          <button onclick="goToStep(2)" class="btn-secondary px-4 py-2 rounded-lg text-sm font-medium">
            ← Change Scope
          </button>
        </div>
      </div>
      
      <!-- Merged Permissions for Selected Scope -->
      ${generateSection(
        "MERGED PERMISSIONS",
        generateEffectiveConfigContent(
          results.effectiveConfig,
          results.configInventory,
        ),
        undefined,
        "effective-config",
      )}
      
      <!-- Progress Bar -->
      <div class="glass-card rounded-xl p-4 mb-6">
        <div class="flex items-center gap-4">
          <span class="text-sm text-[#8b949e]">Progress:</span>
          <span class="text-sm text-[#c9d1d9]" id="progress-text">0/${totalIssues} fixed</span>
          <div class="flex-1 h-2 bg-[#21262d] rounded-full overflow-hidden">
            <div id="progress-bar" class="h-full bg-[var(--primary)] rounded-full transition-all duration-300" style="width: 0%"></div>
          </div>
        </div>
      </div>
      
      <!-- Severity Sections -->
      ${generateSeveritySection("high", highIssues)}
      ${generateSeveritySection("medium", mediumIssues)}
      ${generateSeveritySection("low", lowIssues)}
      
      <!-- Tool Restrictions -->
      ${generateSection(
        "TOOL RESTRICTIONS",
        toolRestrictionsContent,
        undefined,
        "tool-restrictions",
      )}
      
      <!-- Bash Command Restrictions -->
      ${generateSection(
        "BASH COMMAND RESTRICTIONS",
        bashRestrictionsContent,
        undefined,
        "bash-restrictions",
      )}
      
      <!-- Sandbox Configuration -->
      ${generateSection(
        "SANDBOX CONFIGURATION",
        sandboxContent,
        undefined,
        "sandbox-config",
      )}
      
      <!-- Directory Access Controls -->
      ${generateSection(
        "DIRECTORY ACCESS CONTROLS",
        generateDirectoryAccessContent(currentConfig),
        undefined,
        "directory-access",
      )}
      
      <!-- Security Profiles -->
      ${generateSection(
        "SECURITY PROFILES",
        generateSecurityProfilesContent(),
        undefined,
        "security-profiles",
      )}
      
      <!-- MCP Integrity -->
      ${generateSection(
        "MCP SERVER INTEGRITY",
        integrityContent,
        hasIntegrityIssues ? "text-[#f85149]" : "text-[#8b949e]",
        "mcp-integrity",
      )}
      
      <!-- Navigation -->
      <div class="flex justify-between mt-6">
        <button onclick="goToStep(2)" class="btn-secondary px-6 py-3 rounded-lg font-semibold">
          ← Change Scope
        </button>
      </div>
      
      <!-- Enterprise -->
      <div class="mt-8">
        ${generateSection(
          "ENTERPRISE",
          enterpriseContent,
          undefined,
          "enterprise",
        )}
      </div>
    </div>
    
  </div><!-- End Wizard Container -->

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

    // Refresh merged permissions section dynamically
    async function refreshMergedPermissions() {
      console.log('[DEBUG] refreshMergedPermissions called');
      try {
        const projectPath = selectedProjectPath || null;
        const url = projectPath
          ? '/api/effective-config?project=' + encodeURIComponent(projectPath)
          : '/api/effective-config';
        console.log('[DEBUG] Fetching:', url);
        const res = await fetch(url);
        const effectiveConfig = await res.json();
        console.log('[DEBUG] Got effective config:', effectiveConfig);

        // Generate the updated HTML for merged permissions
        const contentDiv = document.getElementById('effective-config-content');
        console.log('[DEBUG] Found content div:', contentDiv);
        if (contentDiv) {
          const newHtml = generateMergedPermissionsHtml(effectiveConfig);
          console.log('[DEBUG] Generated HTML length:', newHtml.length);
          contentDiv.innerHTML = newHtml;
          console.log('[DEBUG] Updated innerHTML');
        } else {
          console.error('[DEBUG] Could not find #effective-config-content');
        }
      } catch (err) {
        console.error('Failed to refresh merged permissions:', err);
      }
    }
    
    // Generate merged permissions HTML from effective config data
    function generateMergedPermissionsHtml(config) {
      if (!config) return '<p class="text-sm text-[#8b949e] italic">Effective configuration not available.</p>';
      
      const permissionSources = config.permissions?.sources || [];
      const denyRules = permissionSources.filter(s => s.type === 'deny');
      const allowRules = permissionSources.filter(s => s.type === 'allow');
      const toolSources = config.tools?.sources || [];
      const disallowedTools = toolSources.filter(s => s.type === 'disallowed');
      const allowedTools = toolSources.filter(s => s.type === 'allowed');
      
      const getScopeBadgeColor = (scope) => {
        switch (scope) {
          case 'managed': return 'bg-[#f85149]';
          case 'local': return 'bg-[#a371f7]';
          case 'project': return 'bg-[#238636]';
          case 'user': return 'bg-[#58a6ff]';
          default: return 'bg-[#30363d]';
        }
      };
      
      const getScopeLabel = (scope) => {
        switch (scope) {
          case 'managed': return 'IT-Managed';
          case 'local': return 'Local';
          case 'project': return 'Project';
          case 'user': return 'User';
          default: return scope;
        }
      };
      
      const denyHtml = denyRules.length > 0
        ? denyRules.map(s => '<div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0"><code class="text-sm text-[#f85149]">' + escapeHtml(s.rule) + '</code><span class="px-2 py-0.5 ' + getScopeBadgeColor(s.scope) + ' text-white text-xs rounded">' + getScopeLabel(s.scope) + '</span></div>').join('')
        : '<p class="text-xs text-[#8b949e] italic">No deny rules configured.</p>';
      
      const allowHtml = allowRules.length > 0
        ? allowRules.map(s => '<div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0"><code class="text-sm text-[#3fb950]">' + escapeHtml(s.rule) + '</code><span class="px-2 py-0.5 ' + getScopeBadgeColor(s.scope) + ' text-white text-xs rounded">' + getScopeLabel(s.scope) + '</span></div>').join('')
        : '<p class="text-xs text-[#8b949e] italic">No allow rules configured.</p>';
      
      // Tool restrictions
      let toolHtml = '';
      if (disallowedTools.length > 0 || allowedTools.length > 0) {
        const disallowedHtml = disallowedTools.length > 0
          ? disallowedTools.map(s => '<div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0"><code class="text-sm text-[#f85149]">' + escapeHtml(s.tool) + '</code><span class="px-2 py-0.5 ' + getScopeBadgeColor(s.scope) + ' text-white text-xs rounded">' + getScopeLabel(s.scope) + '</span></div>').join('')
          : '<p class="text-xs text-[#8b949e] italic">No tools blocked.</p>';
        
        const allowedToolsHtml = allowedTools.length > 0
          ? allowedTools.map(s => '<div class="flex items-center justify-between py-1.5 border-b border-[#30363d] last:border-0"><code class="text-sm text-[#3fb950]">' + escapeHtml(s.tool) + '</code><span class="px-2 py-0.5 ' + getScopeBadgeColor(s.scope) + ' text-white text-xs rounded">' + getScopeLabel(s.scope) + '</span></div>').join('')
          : '<p class="text-xs text-[#8b949e] italic">No tools explicitly allowed.</p>';
        
        toolHtml = '<div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mt-4"><div class="text-xs font-semibold text-[#c9d1d9] uppercase mb-3">Tool Restrictions</div><div class="grid grid-cols-1 md:grid-cols-2 gap-4"><div><div class="text-xs font-semibold text-[#f85149] mb-2">Blocked (' + disallowedTools.length + ')</div>' + disallowedHtml + '</div><div><div class="text-xs font-semibold text-[#3fb950] mb-2">Allowed (' + allowedTools.length + ')</div>' + allowedToolsHtml + '</div></div></div>';
      }
      
      // Sandbox
      let sandboxHtml = '';
      if (config.sandbox) {
        sandboxHtml = '<div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 mt-4"><div class="flex items-center justify-between mb-2"><span class="text-sm font-semibold text-[#c9d1d9]">Sandbox Configuration</span><span class="px-2 py-0.5 ' + getScopeBadgeColor(config.sandboxSource) + ' text-white text-xs rounded">' + getScopeLabel(config.sandboxSource) + '</span></div><div class="text-xs text-[#8b949e]"><div>Enabled: <span class="' + (config.sandbox.enabled ? 'text-[#3fb950]' : 'text-[#f85149]') + '">' + (config.sandbox.enabled ? 'Yes' : 'No') + '</span></div></div></div>';
      }
      
      return '<p class="text-sm text-[#8b949e] mb-4">The merged configuration that Claude Code actually uses, with source attribution.</p><div class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4"><div class="text-xs font-semibold text-[#f85149] uppercase mb-2">Deny Rules (' + denyRules.length + ')</div>' + denyHtml + '</div><div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4"><div class="text-xs font-semibold text-[#3fb950] uppercase mb-2">Allow Rules (' + allowRules.length + ')</div>' + allowHtml + '</div></div>' + sandboxHtml + toolHtml;
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

    // Wizard state variables (must be declared before functions that use them)
    let currentStep = 1;
    let selectedScopeType = 'global';
    let selectedProjectPath = null;

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
      const undoBtn = document.getElementById('undo-btn');
      if (undoBtn) undoBtn.disabled = !state.lastAction;
      
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

        // Check if fix is already applied
        if (preview.alreadyApplied) {
          const bodyHtml =
            '<div class="text-center py-8">' +
            '<div class="text-4xl mb-4">✅</div>' +
            '<p class="text-lg text-[#3fb950] font-semibold mb-2">Already Protected</p>' +
            '<p class="text-sm text-[#8b949e]">This rule is already in your configuration.</p>' +
            '<div class="mt-4 bg-[#0d1117] border border-[#30363d] rounded p-3 text-xs font-mono text-left">' +
            '<code class="text-[#f85149]">' + escapeHtml(target) + '</code>' +
            '</div>' +
            '</div>';
          document.getElementById('modal-body').innerHTML = bodyHtml;
          document.getElementById('modal-confirm').style.display = 'none';
          markIssueFixed(id);
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
        document.getElementById('modal-confirm').style.display = 'block';

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
            // Refresh merged permissions to show the new rule
            await refreshMergedPermissions();
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
          // Refresh merged permissions to reflect the reverted change
          await refreshMergedPermissions();
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
            await refreshMergedPermissions();
            // Update the tool card button to reflect the new state
            updateToolCardState(toolName, true);
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
            await refreshMergedPermissions();
            // Update the tool card button to reflect the new state
            updateToolCardState(toolName, false);
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
            const undoBtnBash = document.getElementById('undo-btn');
            if (undoBtnBash) undoBtnBash.disabled = false;
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
          const undoBtnRestriction = document.getElementById('undo-btn');
          if (undoBtnRestriction) undoBtnRestriction.disabled = true;
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
            await refreshMergedPermissions();
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
          await refreshMergedPermissions();
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
            await refreshMergedPermissions();
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
            await refreshMergedPermissions();
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
            await refreshMergedPermissions();
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
            Claude Code uses a <strong>layered configuration system</strong> with local overrides:
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
              <li>Typically committed to git for team sharing</li>
            </ul>
          </div>
          
          <div class="bg-[#0d1117] border border-[#a371f7] rounded-lg p-4">
            <div class="flex items-center gap-2 mb-2">
              <span class="px-2 py-1 bg-[#a371f7] text-white text-xs font-semibold rounded">LOCAL</span>
              <span class="font-semibold text-[#c9d1d9]">Local Settings Override</span>
              <code class="text-xs text-[#a371f7]">settings.local.json</code>
            </div>
            <ul class="text-sm text-[#8b949e] ml-8 list-disc space-y-1">
              <li>Can exist at <strong>both</strong> user and project level</li>
              <li>User: <code class="text-[#a371f7]">~/.claude/settings.local.json</code></li>
              <li>Project: <code class="text-[#a371f7]">.claude/settings.local.json</code></li>
              <li><strong>Not committed to git</strong> (add to .gitignore)</li>
              <li>Good for: Personal dev overrides, local testing configs</li>
            </ul>
          </div>
          
          <div class="bg-[#0d1117] border border-[#30363d] rounded-lg p-4">
            <div class="text-sm font-semibold text-[#c9d1d9] mb-2">How They Merge (Precedence Order)</div>
            <div class="text-center text-sm text-[#8b949e]">
              <div class="inline-block text-left">
                <div class="flex items-center gap-2 mb-1">
                  <span class="w-4 text-center">↓</span>
                  <span>Global Settings (base)</span>
                </div>
                <div class="flex items-center gap-2 mb-1">
                  <span class="w-4 text-center">↓</span>
                  <span class="text-[#a371f7]">Global Local Settings (override)</span>
                </div>
                <div class="flex items-center gap-2 mb-1">
                  <span class="w-4 text-center">↓</span>
                  <span>Project Settings (override)</span>
                </div>
                <div class="flex items-center gap-2 mb-1">
                  <span class="w-4 text-center">↓</span>
                  <span class="text-[#a371f7]">Project Local Settings (highest)</span>
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
              <div>Project local allows: <code class="text-[#a371f7]">.env.example</code> (personal override)</div>
              <div class="text-[#3fb950]">→ Effective: <code>~/.ssh/**</code> and <code>.env</code> blocked, but <code>.env.example</code> allowed</div>
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

    // Toggle project list visibility
    function toggleProjectList() {
      const list = document.getElementById('project-list');
      if (list) list.classList.toggle('hidden');
    }

    // Switch scope
    async function switchScope(projectPath) {
      try {
        const res = await fetch('/api/switch-scope', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ projectPath: projectPath || null }),
        });
        const data = await res.json();
        if (data.success) {
          showToast('Switched scope to ' + (projectPath ? projectPath.split('/').pop() : 'Global'));
          await refreshMergedPermissions();
        } else {
          showToast(data.error || 'Failed to switch scope', 'error');
        }
      } catch (err) {
        showToast('Failed to switch scope', 'error');
      }
    }

    // ============================================
    // Wizard Navigation Functions
    // ============================================
    
    function goToStep(step, updateHash = true) {
      // Hide all steps
      document.querySelectorAll('.wizard-step').forEach(el => {
        el.classList.add('hidden');
      });
      
      // Show target step
      const targetStep = document.querySelector('.wizard-step[data-step="' + step + '"]');
      if (targetStep) {
        targetStep.classList.remove('hidden');
      }
      
      // Update sidebar indicators
      document.querySelectorAll('.wizard-step-nav').forEach(nav => {
        const navStep = parseInt(nav.dataset.step);
        const indicator = nav.querySelector('.step-indicator');
        const label = nav.querySelector('span:last-child');
        
        if (navStep < step) {
          // Completed step
          indicator.className = 'step-indicator w-6 h-6 rounded-full bg-[#3fb950] text-white flex items-center justify-center text-xs font-bold';
          indicator.innerHTML = '✓';
          label.className = 'text-sm text-white';
        } else if (navStep === step) {
          // Current step
          indicator.className = 'step-indicator w-6 h-6 rounded-full bg-[var(--primary)] text-[#0a2020] flex items-center justify-center text-xs font-bold';
          indicator.textContent = navStep;
          label.className = 'text-sm text-white';
        } else {
          // Future step
          indicator.className = 'step-indicator w-6 h-6 rounded-full bg-[rgba(255,255,255,0.2)] text-white flex items-center justify-center text-xs font-bold';
          indicator.textContent = navStep;
          label.className = 'text-sm text-[rgba(255,255,255,0.6)]';
        }
      });
      
      currentStep = step;
      
      // Update URL hash to persist step across reloads
      if (updateHash) {
        window.location.hash = 'step-' + step;
      }
      
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    
    async function selectScope(type, projectPath) {
      console.log('[DEBUG] selectScope called:', type, projectPath);
      selectedScopeType = type;
      selectedProjectPath = projectPath || null;

      // Call API to switch server-side scope
      try {
        const res = await fetch('/api/switch-scope', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ projectPath: projectPath || null }),
        });
        const data = await res.json();
        console.log('[DEBUG] switch-scope response:', data);
        if (!data.success) {
          showToast(data.error || 'Failed to switch scope', 'error');
        }
      } catch (err) {
        console.error('[DEBUG] switch-scope error:', err);
        showToast('Failed to switch scope', 'error');
      }

      // Update the Step 3 header elements
      const badge = document.getElementById('selected-scope-badge');
      const label = document.getElementById('selected-scope-label');
      const pathEl = document.getElementById('selected-scope-path');
      
      console.log('[DEBUG] Found elements:', { badge: !!badge, label: !!label, pathEl: !!pathEl });

      if (badge) {
        if (type === 'global') {
          badge.textContent = 'GLOBAL';
          badge.className = 'px-2 py-0.5 bg-[#58a6ff] text-white text-xs font-semibold rounded';
        } else {
          badge.textContent = 'PROJECT';
          badge.className = 'px-2 py-0.5 bg-[#238636] text-white text-xs font-semibold rounded';
        }
        console.log('[DEBUG] Updated badge to:', badge.textContent);
      }

      if (label) {
        if (type === 'global') {
          label.textContent = 'Global Settings';
        } else {
          label.textContent = projectPath ? projectPath.split('/').pop() : 'Project';
        }
        console.log('[DEBUG] Updated label to:', label.textContent);
      }

      if (pathEl) {
        if (type === 'global') {
          pathEl.textContent = '~/.claude/settings.json';
        } else {
          const shortPath = projectPath ? projectPath.replace(/^\\/Users\\/[^\\/]+/, '~') : '';
          pathEl.textContent = shortPath + '/.claude/settings.json';
        }
        console.log('[DEBUG] Updated path to:', pathEl.textContent);
      }

      // Refresh merged permissions for the new scope
      await refreshMergedPermissions();
    }
    
    // Initialize wizard on page load - read step from URL hash
    document.addEventListener('DOMContentLoaded', () => {
      const hash = window.location.hash;
      const stepMatch = hash.match(/step-(\d)/);
      const initialStep = stepMatch ? parseInt(stepMatch[1]) : 1;
      goToStep(initialStep, false); // Don't update hash on initial load
    });
    
    // Handle browser back/forward buttons
    window.addEventListener('hashchange', () => {
      const hash = window.location.hash;
      const stepMatch = hash.match(/step-(\d)/);
      if (stepMatch) {
        const step = parseInt(stepMatch[1]);
        if (step !== currentStep) {
          goToStep(step, false);
        }
      }
    });

    // ============================================
    // Welcome Card Dismissal
    // ============================================
    
    function dismissWelcome() {
      const card = document.getElementById('welcome-card');
      if (card) {
        card.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
        card.style.opacity = '0';
        card.style.transform = 'translateY(-10px)';
        setTimeout(() => {
          card.remove();
          localStorage.setItem('cdk-welcome-dismissed', 'true');
        }, 300);
      }
    }
    
    // Check if welcome was previously dismissed
    document.addEventListener('DOMContentLoaded', () => {
      if (localStorage.getItem('cdk-welcome-dismissed') === 'true') {
        const card = document.getElementById('welcome-card');
        if (card) card.remove();
      }
    });

    // Update tool card state after enable/disable
    function updateToolCardState(toolName, isDisabled) {
      const card = document.getElementById('tool-' + toolName);
      if (!card) return;
      
      // Find the status badge and button
      const badge = card.querySelector('.flex.items-center.gap-2 span');
      const button = card.querySelector('button');
      
      if (badge) {
        if (isDisabled) {
          badge.className = 'px-2 py-0.5 rounded text-xs font-medium bg-[#f85149] text-white';
          badge.textContent = 'BLOCKED';
        } else {
          badge.className = 'px-2 py-0.5 rounded text-xs font-medium bg-[#238636] text-white';
          badge.textContent = 'ALLOWED';
        }
      }
      
      if (button) {
        if (isDisabled) {
          button.className = 'shrink-0 px-3 py-1.5 bg-[#238636] text-white rounded text-sm font-medium hover:brightness-110 transition';
          button.textContent = 'Allow';
          button.setAttribute('onclick', "enableTool('" + toolName + "')");
        } else {
          button.className = 'shrink-0 px-3 py-1.5 bg-[#f85149] text-white rounded text-sm font-medium hover:brightness-110 transition';
          button.textContent = 'Deny';
          button.setAttribute('onclick', "disableTool('" + toolName + "')");
        }
      }
    }

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
            await refreshMergedPermissions();
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
