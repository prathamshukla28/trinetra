import test from "node:test";
import assert from "node:assert/strict";
import { extractJson } from "../src/adapters/llm.js";

test("extracts JSON from a fenced ```json block", () => {
  const reply = 'Sure!\n```json\n{"impl":"a","test":"b","notes":"c"}\n```\nDone.';
  const obj = extractJson(reply);
  assert.equal(obj.impl, "a");
  assert.equal(obj.test, "b");
});

test("extracts JSON from a bare object", () => {
  const obj = extractJson('prefix {"impl":"x","test":"y"} suffix');
  assert.equal(obj.impl, "x");
  assert.equal(obj.test, "y");
});

test("throws on reply with no JSON", () => {
  assert.throws(() => extractJson("no json here"));
});
