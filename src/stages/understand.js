// Stage 2 — UNDERSTAND.  Turn raw units into a human-readable map of what the
// target *does*, and save it to memory so future runs start from what we know.

export async function understand(inspection, memory) {
  const behaviors = inspection.units.map((u) => ({
    name: u.name,
    where: `${u.file}:${u.line}`,
    guess: describe(u),
  }));

  const map = {
    engine: inspection.engine,
    fileCount: inspection.files.length,
    behaviors,
  };

  memory.remember("map", map);
  return map;
}

// A cheap heuristic "what does this do" based on the name. A real run would ask
// the model; this keeps the pipeline self-contained and offline.
function describe(unit) {
  const n = unit.name.toLowerCase();
  if (/auth|login|token|password|secret|cred/.test(n)) return "authentication / secrets";
  if (/read|load|open|fetch|get/.test(n)) return "reads input / data";
  if (/write|save|store|put|set/.test(n)) return "writes output / state";
  if (/exec|run|spawn|eval|shell|command/.test(n)) return "executes code / commands";
  if (/parse|decode|deserialize/.test(n)) return "parses untrusted input";
  if (/encrypt|decrypt|hash|sign|verify/.test(n)) return "cryptography";
  return "general logic";
}
