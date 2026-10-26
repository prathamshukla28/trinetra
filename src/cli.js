#!/usr/bin/env node
// REFORGE — command-line entry point.
// Usage:
//   reforge teardown <target>     tear a target apart, audit it, write a report
//   reforge teardown <target> --rebuild   also attempt a clean reimplementation

import { teardown } from "./pipeline.js";

function parseArgs(argv) {
  const [command, target, ...rest] = argv;
  const flags = new Set(rest.filter((a) => a.startsWith("--")));
  return { command, target, rebuild: flags.has("--rebuild") };
}

async function main() {
  const { command, target, rebuild } = parseArgs(process.argv.slice(2));

  if (command !== "teardown" || !target) {
    console.log("REFORGE — tear it down, then forge it back.\n");
    console.log("  reforge teardown <target> [--rebuild]\n");
    console.log("Example:");
    console.log("  reforge teardown targets/sample-cli");
    process.exit(command ? 1 : 0);
  }

  await teardown(target, { rebuild });
}

main().catch((err) => {
  console.error("\n✖ REFORGE failed:", err.message);
  process.exit(1);
});
