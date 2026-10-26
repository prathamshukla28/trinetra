// Stage 4 — REBUILD (optional).  Forge a clean reimplementation, test-first.
//
// This is where the superpowers discipline lives: for every behavior we want to
// recreate, we write the test before the code. For now this stage scaffolds the
// test + stub pair so the test-first loop is ready; filling the stubs is the
// model-driven step we add next.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

export async function rebuild(map, _memory) {
  const outDir = path.join(ROOT, "src", "rebuilt", safe(map));
  fs.mkdirSync(outDir, { recursive: true });

  const files = [];
  for (const b of map.behaviors) {
    const base = b.name.replace(/[^A-Za-z0-9_$]/g, "_");
    const testFile = path.join(outDir, `${base}.test.js`);
    const implFile = path.join(outDir, `${base}.js`);
    if (!fs.existsSync(testFile)) {
      fs.writeFileSync(
        testFile,
        `// TEST FIRST (superpowers discipline). Describe ${b.name} — "${b.guess}".\n` +
          `import { ${base} } from "./${base}.js";\n\n` +
          `// TODO: assert the real behavior before implementing it.\n` +
          `console.assert(typeof ${base} === "function", "${base} should exist");\n`,
      );
      files.push(testFile);
    }
    if (!fs.existsSync(implFile)) {
      fs.writeFileSync(implFile, `export function ${base}() {\n  // TODO: implement to pass ${base}.test.js\n}\n`);
      files.push(implFile);
    }
  }
  return { outDir, files };
}

function safe(map) {
  return (map.target || "target").replace(/[^A-Za-z0-9_-]/g, "_");
}
