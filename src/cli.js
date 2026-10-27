#!/usr/bin/env node
// Trinetra — command-line entry point.
// Usage:
//   trinetra teardown <target>     tear a target apart, audit it, write a report
//   trinetra teardown <target> --rebuild   also attempt a clean reimplementation

import { teardown } from "./pipeline.js";

function parseArgs(argv) {
  const [command, target, ...rest] = argv;
  const flags = new Set(rest.filter((a) => a.startsWith("--")));
  return { command, target, rebuild: flags.has("--rebuild") };
}

async function main() {
  const { command, target, rebuild } = parseArgs(process.argv.slice(2));

  if (command !== "teardown" || !target) {
    console.log("Trinetra — tear it down, then forge it back.\n");
    console.log("  trinetra teardown <target> [--rebuild]\n");
    console.log("Example:");
    console.log("  trinetra teardown targets/sample-cli");
    process.exit(command ? 1 : 0);
  }

  await teardown(target, { rebuild });
}

main().catch((err) => {
  console.error("\n✖ Trinetra failed:", err.message);
  process.exit(1);
});
