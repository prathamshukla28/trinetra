import test from "node:test";
import assert from "node:assert/strict";
import { understand } from "../src/stages/understand.js";
import { analyzeJs } from "../src/analysis/js-ast.js";
import { analyzeBinary } from "../src/binary/index.js";
import { buildElf } from "./helpers/binaries.js";

test("source summary comes from imports, exports and call sites — not names", async () => {
  const src = `
    import { execSync } from "node:child_process";
    import express from "express";
    export function getUser(id) { return execSync("id " + id).toString(); }  // name says "get", code runs a shell
    export function helper() { return 1; }
    const app = express();
    app.post("/run", (req, res) => res.send(getUser(req.body.id)));
  `;
  const js = [analyzeJs(src, "srv.js")];
  const map = await understand({ engine: "trinetra-ast", kind: "source", files: ["srv.js"], units: [], js });
  assert.deepEqual(map.imports.builtin, ["node:child_process"]);
  assert.deepEqual(map.imports.external, ["express"]);
  assert.deepEqual(map.exports, ["getUser", "helper"]);
  const getUser = map.behaviors.find((b) => b.name === "getUser");
  assert.deepEqual(getUser.capabilities, ["runs shell commands / processes"]);
  assert.match(getUser.summary, /child_process\.execSync/);
  assert.match(map.behaviors.find((b) => b.name === "helper").summary, /no sensitive APIs/);
  assert.ok(map.entryPoints.includes("POST /run handler"));
  assert.ok(map.summary.some((s) => /runs shell commands \/ processes in getUser/.test(s)));
  assert.ok(map.summary.some((s) => /handles HTTP request input in POST \/run handler/.test(s)));
});

test("native summary comes from parsed imports and libraries", async () => {
  const binary = analyzeBinary(buildElf({ imports: ["socket", "connect", "getenv", "system"] }));
  const map = await understand({
    engine: "trinetra-binary",
    kind: "native",
    files: ["b"],
    units: [],
    unitKind: "import",
    binary,
  });
  assert.match(map.summary[0], /ELF shared-object \(x86_64\)/);
  assert.match(map.summary.join(" "), /Links libc\.so\.6/);
  assert.match(map.summary.join(" "), /process execution \(system\)/);
  assert.match(map.summary.join(" "), /network \(connect, socket\)/);
  assert.deepEqual(map.capabilities.environment, ["getenv"]);
});
