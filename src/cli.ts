import { Command } from "commander";
import * as path from "path";
import * as fs from "fs";
import type { CliOptions, OutputFormat, ConfigScope } from "./types/index.js";

const VERSION = "0.1.0";

export function parseArgs(argv: string[]): CliOptions {
  const program = new Command();

  program
    .name("claude-defense-kit")
    .description(
      "Claude Defense Kit - Secure your Claude Code installation.\n\n" +
        "Scans your Claude Code configuration and generates a security report\n" +
        "showing what could be accessed if Claude is compromised via prompt injection."
    )
    .version(VERSION)
    .option(
      "-f, --format <type>",
      "Output format: terminal, json, html",
      "terminal"
    )
    .option("-o, --output <file>", "Write output to file instead of stdout")
    .option(
      "-p, --project <path>",
      "Target a specific project directory (edits project-level .claude/settings.json)"
    )
    .option("--no-color", "Disable colored output")
    .option("--verbose", "Show detailed scan progress", false)
    .option(
      "--no-open",
      "Don't open report in browser (by default opens HTML report in browser)"
    );

  program.parse(argv);

  const opts = program.opts();

  // Validate format
  const validFormats: OutputFormat[] = ["terminal", "json", "html"];
  const format = opts.format as OutputFormat;
  if (!validFormats.includes(format)) {
    console.error(`Invalid format: ${format}. Use: terminal, json, or html`);
    process.exit(1);
  }

  // Determine config scope
  let scope: ConfigScope = { type: "global" };
  if (opts.project) {
    const projectPath = path.resolve(opts.project);
    if (!fs.existsSync(projectPath)) {
      console.error(`Project path does not exist: ${projectPath}`);
      process.exit(1);
    }
    scope = { type: "project", projectPath };
  }

  return {
    format,
    output: opts.output,
    color: opts.color !== false,
    verbose: opts.verbose,
    openBrowser: opts.open !== false,
    scope,
  };
}
