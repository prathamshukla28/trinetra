// TEST FIRST. Describe evalExpression — "executes code / commands".
import { evalExpression } from "./evalExpression.js";

import test from "node:test";
import assert from "node:assert/strict";

test("evalExpression exists", () => { assert.equal(typeof evalExpression, "function"); });
