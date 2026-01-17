import { Command } from "commander";
import type { CliOptions } from "./types/index.js";

const VERSION = "0.1.0";

export function parseArgs(argv: string[]): CliOptions {
  const program = new Command();

  program
    .name("claude-defense-kit")
    .description(
      "Claude Defense Kit - Secure your Claude Code installation.\n\n" +
        "Launches an interactive web dashboard to scan your Claude Code configuration\n" +
        "and help you lock down security settings with one-click fixes.",
    )
    .version(VERSION)
    .option("--no-open", "Don't open browser automatically (start server only)")
    .option("--port <number>", "Port to run the server on", "3456")
    .option("--verbose", "Show detailed scan progress", false);

  program.parse(argv);

  const opts = program.opts();

  return {
    openBrowser: opts.open !== false,
    port: parseInt(opts.port, 10) || 3456,
    verbose: opts.verbose,
  };
}
