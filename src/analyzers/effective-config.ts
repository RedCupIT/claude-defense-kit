/**
 * Effective Configuration Analyzer
 *
 * Computes the effective (merged) configuration by applying
 * Claude Code's scope precedence rules:
 *
 * 1. Managed (highest) - can't be overridden
 * 2. Local - overrides project and user
 * 3. Project - overrides user
 * 4. User (lowest) - applies when nothing else specifies
 *
 * Also tracks what's "shadowed" (set at a lower level but overridden).
 */

import type {
  ConfigInventory,
  EffectiveConfig,
  ConfigScopeType,
  SandboxConfig,
  McpServerConfig,
  ProjectConfigInfo,
} from "../types/index.js";

/**
 * Compute effective configuration for a specific project
 * (or global/user level if projectPath is null)
 */
export function computeEffectiveConfig(
  inventory: ConfigInventory,
  projectPath: string | null = null
): EffectiveConfig {
  const result: EffectiveConfig = {
    projectPath,
    permissions: {
      allow: [],
      deny: [],
      sources: [],
    },
    tools: {
      allowed: [],
      disallowed: [],
      sources: [],
    },
    mcpRestrictions: {
      allowed: [],
      denied: [],
      sources: [],
    },
    sandbox: null,
    sandboxSource: null,
    mcpServers: {},
    hooks: {
      allowManagedHooksOnly: false,
      disableAllHooks: false,
      source: null,
    },
    bypassMode: {
      disabled: false,
      source: null,
    },
    shadowedRules: [],
  };

  // Find the project if specified
  const project = projectPath
    ? inventory.projects.find((p) => p.path === projectPath)
    : null;

  // Collect permissions from all scopes (lowest to highest precedence)
  // We'll track what gets shadowed as we go

  // 1. User scope (lowest precedence)
  const userAllow = inventory.user.settings?.permissions?.allow || [];
  const userDeny = inventory.user.settings?.permissions?.deny || [];

  for (const rule of userAllow) {
    result.permissions.allow.push(rule);
    result.permissions.sources.push({ rule, scope: "user", type: "allow" });
  }
  for (const rule of userDeny) {
    result.permissions.deny.push(rule);
    result.permissions.sources.push({ rule, scope: "user", type: "deny" });
  }

  // User tool restrictions
  const userAllowedTools = inventory.user.settings?.allowedTools || [];
  const userDisallowedTools = inventory.user.settings?.disallowedTools || [];
  for (const tool of userAllowedTools) {
    result.tools.allowed.push(tool);
    result.tools.sources.push({ tool, scope: "user", type: "allowed" });
  }
  for (const tool of userDisallowedTools) {
    result.tools.disallowed.push(tool);
    result.tools.sources.push({ tool, scope: "user", type: "disallowed" });
  }

  // User sandbox
  if (inventory.user.settings?.sandbox) {
    result.sandbox = { ...inventory.user.settings.sandbox };
    result.sandboxSource = "user";
  }

  // User MCP servers
  if (inventory.user.mcpConfig?.mcpServers) {
    for (const [name, config] of Object.entries(
      inventory.user.mcpConfig.mcpServers
    )) {
      result.mcpServers[name] = { ...config, source: "user" };
    }
  }

  // 2. Project scope (if applicable)
  if (project) {
    const projectAllow = project.settings.shared?.permissions?.allow || [];
    const projectDeny = project.settings.shared?.permissions?.deny || [];

    for (const rule of projectAllow) {
      // Check if this shadows a user deny
      if (result.permissions.deny.includes(rule)) {
        result.shadowedRules.push({
          rule,
          setAt: "project",
          overriddenBy: "user", // Actually project overrides user, so this is the other way
          type: "allow",
        });
      }
      if (!result.permissions.allow.includes(rule)) {
        result.permissions.allow.push(rule);
        result.permissions.sources.push({
          rule,
          scope: "project",
          type: "allow",
        });
      }
    }
    for (const rule of projectDeny) {
      // Check if this shadows a user allow
      const userAllowIndex = result.permissions.sources.findIndex(
        (s) => s.rule === rule && s.scope === "user" && s.type === "allow"
      );
      if (userAllowIndex >= 0) {
        result.shadowedRules.push({
          rule,
          setAt: "user",
          overriddenBy: "project",
          type: "allow",
        });
      }
      if (!result.permissions.deny.includes(rule)) {
        result.permissions.deny.push(rule);
        result.permissions.sources.push({
          rule,
          scope: "project",
          type: "deny",
        });
      }
    }

    // Project sandbox (overrides user)
    if (project.settings.shared?.sandbox) {
      if (result.sandbox) {
        result.shadowedRules.push({
          rule: "sandbox",
          setAt: "user",
          overriddenBy: "project",
          type: "sandbox",
        });
      }
      result.sandbox = { ...project.settings.shared.sandbox };
      result.sandboxSource = "project";
    }

    // Project MCP servers
    if (project.mcpConfig?.mcpServers) {
      for (const [name, config] of Object.entries(
        project.mcpConfig.mcpServers
      )) {
        if (result.mcpServers[name]) {
          result.shadowedRules.push({
            rule: `mcp:${name}`,
            setAt: "user",
            overriddenBy: "project",
            type: "mcp",
          });
        }
        result.mcpServers[name] = { ...config, source: "project" };
      }
    }

    // 3. Local scope (overrides project)
    if (project.settings.local) {
      const localAllow = project.settings.local.permissions?.allow || [];
      const localDeny = project.settings.local.permissions?.deny || [];

      for (const rule of localAllow) {
        if (!result.permissions.allow.includes(rule)) {
          result.permissions.allow.push(rule);
          result.permissions.sources.push({
            rule,
            scope: "local",
            type: "allow",
          });
        }
      }
      for (const rule of localDeny) {
        // Check if this shadows a project allow
        const projectAllowIndex = result.permissions.sources.findIndex(
          (s) => s.rule === rule && s.scope === "project" && s.type === "allow"
        );
        if (projectAllowIndex >= 0) {
          result.shadowedRules.push({
            rule,
            setAt: "project",
            overriddenBy: "local",
            type: "allow",
          });
        }
        if (!result.permissions.deny.includes(rule)) {
          result.permissions.deny.push(rule);
          result.permissions.sources.push({
            rule,
            scope: "local",
            type: "deny",
          });
        }
      }

      // Local sandbox (overrides project)
      if (project.settings.local.sandbox) {
        if (result.sandbox && result.sandboxSource === "project") {
          result.shadowedRules.push({
            rule: "sandbox",
            setAt: "project",
            overriddenBy: "local",
            type: "sandbox",
          });
        }
        result.sandbox = { ...project.settings.local.sandbox };
        result.sandboxSource = "local";
      }
    }
  }

  // 4. Managed scope (highest precedence - can't be overridden)
  if (inventory.managed.detected && inventory.managed.settings) {
    const managedAllow = inventory.managed.settings.permissions?.allow || [];
    const managedDeny = inventory.managed.settings.permissions?.deny || [];

    for (const rule of managedAllow) {
      if (!result.permissions.allow.includes(rule)) {
        result.permissions.allow.push(rule);
        result.permissions.sources.push({
          rule,
          scope: "managed",
          type: "allow",
        });
      }
    }
    for (const rule of managedDeny) {
      // Managed deny shadows ALL lower-level allows
      const lowerAllows = result.permissions.sources.filter(
        (s) => s.rule === rule && s.type === "allow" && s.scope !== "managed"
      );
      for (const lower of lowerAllows) {
        result.shadowedRules.push({
          rule,
          setAt: lower.scope,
          overriddenBy: "managed",
          type: "allow",
        });
      }
      if (!result.permissions.deny.includes(rule)) {
        result.permissions.deny.push(rule);
        result.permissions.sources.push({
          rule,
          scope: "managed",
          type: "deny",
        });
      }
    }

    // Managed sandbox (overrides everything)
    if (inventory.managed.settings.sandbox) {
      if (result.sandbox) {
        result.shadowedRules.push({
          rule: "sandbox",
          setAt: result.sandboxSource!,
          overriddenBy: "managed",
          type: "sandbox",
        });
      }
      result.sandbox = { ...inventory.managed.settings.sandbox };
      result.sandboxSource = "managed";
    }

    // Managed MCP servers
    if (inventory.managed.mcpConfig?.mcpServers) {
      for (const [name, config] of Object.entries(
        inventory.managed.mcpConfig.mcpServers
      )) {
        if (result.mcpServers[name]) {
          result.shadowedRules.push({
            rule: `mcp:${name}`,
            setAt: result.mcpServers[name].source,
            overriddenBy: "managed",
            type: "mcp",
          });
        }
        result.mcpServers[name] = { ...config, source: "managed" };
      }
    }

    // Managed MCP server restrictions (allowlist/denylist)
    const allowedServers = inventory.managed.settings.allowedMcpServers || [];
    const deniedServers = inventory.managed.settings.deniedMcpServers || [];
    for (const s of allowedServers) {
      result.mcpRestrictions.allowed.push(s.serverName);
      result.mcpRestrictions.sources.push({
        server: s.serverName,
        scope: "managed",
        type: "allowed",
      });
    }
    for (const s of deniedServers) {
      result.mcpRestrictions.denied.push(s.serverName);
      result.mcpRestrictions.sources.push({
        server: s.serverName,
        scope: "managed",
        type: "denied",
      });
    }

    // Managed hook restrictions
    if (inventory.managed.settings.allowManagedHooksOnly) {
      result.hooks.allowManagedHooksOnly = true;
      result.hooks.source = "managed";
    }
    if (inventory.managed.settings.disableAllHooks) {
      result.hooks.disableAllHooks = true;
      result.hooks.source = "managed";
    }

    // Managed bypass mode
    if (
      inventory.managed.settings.permissions?.disableBypassPermissionsMode ===
      "disable"
    ) {
      result.bypassMode.disabled = true;
      result.bypassMode.source = "managed";
    }
  }

  return result;
}

/**
 * Check if a specific setting is controlled by managed config
 * (and therefore cannot be modified by the user)
 */
export function isSettingManaged(
  inventory: ConfigInventory,
  settingType: "sandbox" | "permissions" | "mcp" | "hooks"
): boolean {
  if (!inventory.managed.detected) return false;

  switch (settingType) {
    case "sandbox":
      return inventory.managed.enforces.sandboxing;
    case "permissions":
      return inventory.managed.enforces.permissionRestrictions;
    case "mcp":
      return inventory.managed.enforces.mcpRestrictions;
    case "hooks":
      return inventory.managed.enforces.hookRestrictions;
    default:
      return false;
  }
}

/**
 * Get a human-readable label for a config scope
 */
export function getScopeLabel(scope: ConfigScopeType): string {
  switch (scope) {
    case "managed":
      return "IT-Managed";
    case "local":
      return "Local (Personal)";
    case "project":
      return "Project (Shared)";
    case "user":
      return "User (Global)";
  }
}

/**
 * Get the CSS color class for a config scope
 */
export function getScopeColor(scope: ConfigScopeType): string {
  switch (scope) {
    case "managed":
      return "text-[#f85149]"; // Red - can't override
    case "local":
      return "text-[#a371f7]"; // Purple
    case "project":
      return "text-[#238636]"; // Green
    case "user":
      return "text-[#58a6ff]"; // Blue
  }
}
