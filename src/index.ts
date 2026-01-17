#!/usr/bin/env node

import { parseArgs } from "./cli.js";
import { startServer } from "./server.js";

async function main(): Promise<void> {
  const options = parseArgs(process.argv);

  console.log("Starting Claude Defense Kit...\n");
  await startServer({ type: "global" }, options);
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
