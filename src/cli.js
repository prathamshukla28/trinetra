#!/usr/bin/env node
// Trinetra — command-line entry point.
// Usage:
//   trinetra teardown <target> [--rebuild]   tear a target apart, audit it, report
//   trinetra compare <a> <b>                 diff two targets (what changed)

import { teardown, compare } from "./pipeline.js";

function usage(code) {
  console.log("Trinetra — the third eye that sees inside any software.\n");
  console.log("  trinetra teardown <target> [--rebuild]");
  console.log("  trinetra compare  <targetA> <targetB>\n");
  console.log("Examples:");
  console.log("  trinetra teardown targets/sample-cli");
  console.log("  trinetra compare ./app-v1 ./app-v2");
  process.exit(code);
}

async function main() {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (command === "teardown") {
    const target = argv[1];
    if (!target || target.startsWith("--")) usage(1);
    await teardown(target, { rebuild: argv.includes("--rebuild") });
  } else if (command === "compare") {
    const [, a, b] = argv;
    if (!a || !b) usage(1);
    await compare(a, b);
  } else {
    usage(command ? 1 : 0);
  }
}

main().catch((err) => {
  console.error("\n✖ Trinetra failed:", err.message);
  process.exit(1);
});
