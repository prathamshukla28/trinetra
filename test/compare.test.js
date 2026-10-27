import test from "node:test";
import assert from "node:assert/strict";
import { diffTeardowns } from "../src/stages/compare.js";

test("detects added and removed units", () => {
  const a = { name: "v1", inspection: { units: [{ name: "foo" }, { name: "bar" }] }, findings: [] };
  const b = { name: "v2", inspection: { units: [{ name: "bar" }, { name: "baz" }] }, findings: [] };
  const d = diffTeardowns(a, b);
  assert.deepEqual(d.procedures.added, ["baz"]);
  assert.deepEqual(d.procedures.removed, ["foo"]);
  assert.equal(d.procedures.unchanged, 1);
});

test("computes per-category finding deltas", () => {
  const a = { name: "v1", inspection: { units: [] }, findings: [{ rule: "insecure-random", title: "rng" }] };
  const b = { name: "v2", inspection: { units: [] }, findings: [] };
  const row = diffTeardowns(a, b).findingRows.find((r) => r.category === "insecure-random");
  assert.equal(row.a, 1);
  assert.equal(row.b, 0);
  assert.equal(row.delta, -1);
});

test("detects changed functions when native hashes are present", () => {
  const a = { name: "a", inspection: { units: [{ name: "f" }], fnHashes: { f: "h1" } }, findings: [] };
  const b = { name: "b", inspection: { units: [{ name: "f" }], fnHashes: { f: "h2" } }, findings: [] };
  const d = diffTeardowns(a, b);
  assert.deepEqual(d.procedures.changed, ["f"]);
  assert.ok(d.hashable);
});
