import type {
  ScanResults,
  RiskLevel,
  McpServer,
  IntegrityStatus,
  ClaudeInstallationStatus,
} from "../types/index.js";
import { getRiskLevel, getRiskDescription } from "../analyzers/risk-score.js";
import { generateImpactSummary } from "../analyzers/blast-radius.js";

// ANSI color codes (we'll use these directly to avoid chalk ESM issues)
const colors = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",

  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",

  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
  bgBlue: "\x1b[44m",
};

function color(text: string, ...codes: string[]): string {
  return codes.join("") + text + colors.reset;
}

function getRiskColor(risk: RiskLevel, useColor: boolean): string {
  if (!useColor) return "";
  switch (risk) {
    case "critical":
      return colors.red + colors.bold;
    case "high":
      return colors.red;
    case "medium":
      return colors.yellow;
    case "low":
      return colors.green;
  }
}

function getRiskEmoji(risk: RiskLevel): string {
  switch (risk) {
    case "critical":
      return "\u{1F534}"; // Red circle
    case "high":
      return "\u{1F7E0}"; // Orange circle
    case "medium":
      return "\u{1F7E1}"; // Yellow circle
    case "low":
      return "\u{1F7E2}"; // Green circle
  }
}

function getIntegrityStatusInfo(
  status: IntegrityStatus,
  useColor: boolean
): { label: string; color: string } {
  const c = useColor ? colors : { green: "", yellow: "", red: "", reset: "" };
  switch (status) {
    case "new":
      return { label: "[NEW]", color: c.yellow };
    case "unchanged":
      return { label: "[OK]", color: c.green };
    case "changed":
      return { label: "[CHANGED]", color: c.red };
    case "missing":
      return { label: "[MISSING]", color: c.red };
    case "unhashable":
      return { label: "[SKIP]", color: "" };
  }
}

function getInstallationStatusInfo(
  status: ClaudeInstallationStatus,
  useColor: boolean
): { label: string; color: string } {
  const c = useColor ? colors : { green: "", yellow: "", red: "", reset: "" };
  switch (status) {
    case "new":
      return { label: "[NEW]", color: c.yellow };
    case "unchanged":
      return { label: "[OK]", color: c.green };
    case "changed":
      return { label: "[CHANGED]", color: c.red };
    case "not-found":
      return { label: "[NOT FOUND]", color: c.red };
  }
}

export function generateTerminalReport(
  results: ScanResults,
  useColor: boolean = true
): string {
  const lines: string[] = [];
  const c = useColor
    ? colors
    : {
        reset: "",
        bold: "",
        dim: "",
        red: "",
        green: "",
        yellow: "",
        blue: "",
        magenta: "",
        cyan: "",
        white: "",
        bgRed: "",
        bgGreen: "",
        bgYellow: "",
        bgBlue: "",
      };

  // Header
  lines.push("");
  lines.push(`  ${c.bold}\u{1F6E1} Claude Defense Kit${c.reset}`);
  lines.push(`  ${"═".repeat(60)}`);
  lines.push("");

  // Agent detection
  if (results.agent.detected) {
    const version = results.agent.version ? ` v${results.agent.version}` : "";
    lines.push(
      `  ${c.bold}Agent Detected:${c.reset} ${results.agent.name}${version}`
    );
    if (results.agent.configPath) {
      lines.push(`  ${c.dim}Config: ${results.agent.configPath}${c.reset}`);
    }
  } else {
    lines.push(`  ${c.yellow}No AI agent detected${c.reset}`);
  }
  lines.push("");

  // Claude Code Installation section
  if (results.claudeInstallation) {
    const inst = results.claudeInstallation;
    lines.push(`  ${c.bold}\u{1F527} CLAUDE CODE INSTALLATION${c.reset}`);
    lines.push(`  ${"┌" + "─".repeat(60)}`);

    if (inst.status === "not-found") {
      lines.push(`  │ ${c.yellow}Claude Code installation not found${c.reset}`);
    } else {
      const { label, color: statusColor } = getInstallationStatusInfo(
        inst.status,
        useColor
      );

      if (inst.version) {
        lines.push(`  │ ${c.bold}Version:${c.reset} ${inst.version}`);
      }
      if (inst.installPath) {
        // Truncate path if too long
        const displayPath =
          inst.installPath.length > 50
            ? "..." + inst.installPath.slice(-47)
            : inst.installPath;
        lines.push(
          `  │ ${c.bold}Path:${c.reset} ${c.dim}${displayPath}${c.reset}`
        );
      }

      if (inst.status === "new") {
        lines.push(
          `  │ ${c.bold}Integrity:${c.reset} ${statusColor}${label}${c.reset} ` +
            `${c.dim}(baseline recorded)${c.reset}`
        );
      } else if (inst.status === "unchanged") {
        const date = inst.recordedAt
          ? new Date(inst.recordedAt).toLocaleDateString()
          : "unknown";
        lines.push(
          `  │ ${c.bold}Integrity:${c.reset} ${statusColor}${label}${c.reset} ` +
            `${c.dim}unchanged since ${date}${c.reset}`
        );
      } else if (inst.status === "changed") {
        lines.push(
          `  │ ${c.bold}Integrity:${c.reset} ${statusColor}${label}${c.reset}`
        );
        lines.push(
          `  │            ${c.dim}Was: ${inst.baselineHash?.slice(0, 16)}...${
            c.reset
          }`
        );
        lines.push(
          `  │            ${c.dim}Now: ${inst.cliHash?.slice(0, 16)}...${
            c.reset
          }`
        );
      }

      if (inst.cliHash && inst.status !== "changed") {
        lines.push(
          `  │ ${c.dim}Hash: ${inst.cliHash.slice(0, 16)}...${c.reset}`
        );
      }
    }

    lines.push(`  ${"└" + "─".repeat(60)}`);
    lines.push("");
  }

  // Identity & Credentials section
  if (results.identityExposure) {
    const { identity, exposedEnvVars } = results.identityExposure;

    lines.push(`  ${c.bold}\u{1F510} IDENTITY & CREDENTIALS${c.reset}`);
    lines.push(`  ${"┌" + "─".repeat(60)}`);

    // ~/.claude.json identity info
    const cj = identity.claudeJson;
    if (cj.email || cj.displayName || cj.organizationName) {
      if (cj.email) {
        lines.push(`  │ ${c.bold}Email:${c.reset} ${cj.email}`);
      }
      if (cj.displayName || cj.organizationName) {
        const namePart = cj.displayName ? `Name: ${cj.displayName}` : "";
        const orgPart = cj.organizationName
          ? `Org: ${cj.organizationName}`
          : "";
        const parts = [namePart, orgPart].filter((p) => p).join(" | ");
        lines.push(`  │ ${parts}`);
      }
      if (cj.userID) {
        lines.push(
          `  │ ${c.dim}User ID: ${cj.userID.slice(0, 12)}...${c.reset}`
        );
      }
      if (cj.firstStartTime) {
        const startDate = new Date(cj.firstStartTime).toLocaleDateString();
        lines.push(
          `  │ ${c.dim}First Start: ${startDate} | Startups: ${cj.numStartups}${c.reset}`
        );
      }
      lines.push(`  │`);
    }

    // User info from filesystem
    if (identity.username) {
      lines.push(`  │ ${c.bold}User:${c.reset} ${identity.username}`);
    }
    lines.push(
      `  │ ${c.bold}Projects:${c.reset} ${identity.projectCount} | ` +
        `${c.bold}Sessions:${c.reset} ${identity.sessionCount} | ` +
        `${c.bold}History:${c.reset} ${identity.historyExists ? "Yes" : "No"}`
    );
    lines.push(
      `  │ ${c.bold}Custom API Key:${c.reset} ${
        identity.hasCustomApiKey ? "Yes" : "No"
      } | ` +
        `${c.bold}Keys Dir:${c.reset} ${
          identity.hasKeysDirectory ? "Yes" : "No"
        }`
    );

    // Exposed env vars
    if (exposedEnvVars.length > 0) {
      lines.push(`  │`);
      lines.push(
        `  │ ${c.yellow}\u{26A0}\u{FE0F}  Exposed Environment Variables:${c.reset}`
      );
      for (const envVar of exposedEnvVars) {
        const riskColor = envVar.risk === "high" ? c.red : c.yellow;
        lines.push(
          `  │    ${c.dim}•${c.reset} ${envVar.serverName}: ` +
            `${riskColor}${envVar.varName}${c.reset} ${c.dim}(${envVar.valuePreview})${c.reset}`
        );
      }
    } else {
      lines.push(`  │`);
      lines.push(
        `  │ ${c.green}\u{2713} No sensitive environment variables exposed${c.reset}`
      );
    }

    lines.push(`  ${"└" + "─".repeat(60)}`);
    lines.push("");
  }

  // Filesystem access section
  lines.push(`  ${c.bold}\u{1F4C1} FILE SYSTEM ACCESS${c.reset}`);
  lines.push(`  ${"┌" + "─".repeat(60)}`);
  lines.push(
    `  │ ${c.bold}Read Access:${c.reset}    ${results.filesystem.readPaths.join(
      ", "
    )}`
  );
  lines.push(
    `  │ ${c.bold}Write Access:${c.reset}   ${results.filesystem.writePaths
      .slice(0, 3)
      .join(", ")}`
  );
  lines.push(`  │`);

  // Sensitive files
  const sensitiveFiles = results.filesystem.sensitiveFiles;
  if (sensitiveFiles.length > 0) {
    lines.push(
      `  │ ${c.yellow}\u{26A0}\u{FE0F}  Sensitive files accessible:${c.reset}`
    );
    const topFiles = sensitiveFiles.slice(0, 5);
    for (const file of topFiles) {
      const riskColor = getRiskColor(file.risk, useColor);
      lines.push(
        `  │    ${c.dim}•${c.reset} ${riskColor}${file.path}${c.reset} ${c.dim}(${file.type})${c.reset}`
      );
    }
    if (sensitiveFiles.length > 5) {
      lines.push(
        `  │    ${c.dim}... and ${sensitiveFiles.length - 5} more${c.reset}`
      );
    }
  } else {
    lines.push(
      `  │ ${c.green}\u{2713} No sensitive files detected in accessible paths${c.reset}`
    );
  }
  lines.push(`  ${"└" + "─".repeat(60)}`);
  lines.push("");

  // MCP Servers section
  lines.push(
    `  ${c.bold}\u{1F50C} MCP SERVERS (${results.mcpServers.length} configured)${c.reset}`
  );
  lines.push(`  ${"┌" + "─".repeat(60)}`);

  if (results.mcpServers.length === 0) {
    lines.push(`  │ ${c.dim}No MCP servers configured${c.reset}`);
  } else {
    let serverNum = 1;
    for (const server of results.mcpServers) {
      const riskEmoji = getRiskEmoji(server.risk);
      const riskColor = getRiskColor(server.risk, useColor);

      lines.push(
        `  │ ${c.bold}${serverNum}. ${server.name}${c.reset} (${server.type})`
      );
      lines.push(`  │    Tools: ${server.tools.map((t) => t.name).join(", ")}`);
      lines.push(
        `  │    Risk: ${riskEmoji} ${riskColor}${server.risk.toUpperCase()}${
          c.reset
        }` + (server.riskReason ? ` - ${server.riskReason}` : "")
      );
      if (serverNum < results.mcpServers.length) {
        lines.push(`  │`);
      }
      serverNum++;
    }
  }
  lines.push(`  ${"└" + "─".repeat(60)}`);
  lines.push("");

  // MCP Integrity section
  if (results.integrity && results.integrity.length > 0) {
    lines.push(`  ${c.bold}\u{1F512} MCP SERVER INTEGRITY${c.reset}`);
    lines.push(`  ${"┌" + "─".repeat(60)}`);

    for (const item of results.integrity) {
      const { label, color: statusColor } = getIntegrityStatusInfo(
        item.status,
        useColor
      );
      const labelPadded = label.padEnd(10);

      if (item.status === "unhashable") {
        lines.push(
          `  │ ${c.dim}${labelPadded}${item.serverName} (cannot hash)${c.reset}`
        );
      } else if (item.status === "new") {
        lines.push(
          `  │ ${statusColor}${labelPadded}${c.reset}${item.serverName} ${c.dim}(baseline recorded)${c.reset}`
        );
      } else if (item.status === "unchanged") {
        const date = item.recordedAt
          ? new Date(item.recordedAt).toLocaleDateString()
          : "unknown";
        lines.push(
          `  │ ${statusColor}${labelPadded}${c.reset}${item.serverName} ${c.dim}(unchanged since ${date})${c.reset}`
        );
      } else if (item.status === "changed") {
        lines.push(
          `  │ ${statusColor}${labelPadded}${c.reset}${item.serverName}`
        );
        lines.push(
          `  │            ${c.dim}Was: ${item.baselineHash?.slice(0, 16)}...${
            c.reset
          }`
        );
        lines.push(
          `  │            ${c.dim}Now: ${item.currentHash?.slice(0, 16)}...${
            c.reset
          }`
        );
      } else if (item.status === "missing") {
        lines.push(
          `  │ ${statusColor}${labelPadded}${c.reset}${item.serverName}`
        );
        lines.push(
          `  │            ${c.dim}File not found: ${item.targetPath}${c.reset}`
        );
      }
    }
    lines.push(`  ${"└" + "─".repeat(60)}`);
    lines.push("");
  }

  // Blast radius summary
  const riskLevel = getRiskLevel(results.riskScore);
  const riskColor = getRiskColor(riskLevel, useColor);

  lines.push(`  ${c.bold}\u{1F3AF} BLAST RADIUS SUMMARY${c.reset}`);
  lines.push(`  ${"╔" + "═".repeat(60)}`);
  lines.push(
    `  ║  ${c.bold}Risk Level:${
      c.reset
    } ${riskColor}${riskLevel.toUpperCase()}${c.reset} ` +
      `(Score: ${results.riskScore}/100)`
  );
  lines.push(`  ║`);

  const impactSummary = generateImpactSummary(results.blastRadius);
  if (impactSummary.length > 0) {
    lines.push(`  ║  ${c.bold}If compromised, this agent could:${c.reset}`);
    for (const impact of impactSummary) {
      lines.push(`  ║    • ${impact}`);
    }
  }
  lines.push(`  ${"╚" + "═".repeat(60)}`);
  lines.push("");

  // Recommendations section
  if (results.recommendations.length > 0) {
    lines.push(`  ${c.bold}\u{1F4A1} RECOMMENDATIONS${c.reset}`);
    lines.push(`  ${"─".repeat(62)}`);

    let recNum = 1;
    for (const rec of results.recommendations) {
      const recColor = getRiskColor(rec.risk, useColor);
      lines.push(`  ${recNum}. ${recColor}${rec.title}${c.reset}`);
      // Wrap description to ~55 chars
      const wrapped = wrapText(rec.description, 55);
      for (const line of wrapped) {
        lines.push(`     ${c.dim}${line}${c.reset}`);
      }
      recNum++;
    }
    lines.push("");
  }

  // Footer
  lines.push(`  ${"─".repeat(62)}`);
  lines.push(
    `  ${c.dim}\u{1F4CA} Full report: claude-defense-kit --format html -o report.html${c.reset}`
  );
  lines.push("");

  return lines.join("\n");
}

function wrapText(text: string, maxWidth: number): string[] {
  const words = text.split(" ");
  const lines: string[] = [];
  let currentLine = "";

  for (const word of words) {
    if (currentLine.length + word.length + 1 <= maxWidth) {
      currentLine += (currentLine ? " " : "") + word;
    } else {
      if (currentLine) lines.push(currentLine);
      currentLine = word;
    }
  }
  if (currentLine) lines.push(currentLine);

  return lines;
}
