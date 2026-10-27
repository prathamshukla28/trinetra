// TEST FIRST. Describe runUserCommand — "executes code / commands".
import { runUserCommand } from "./runUserCommand.js";

import test from "node:test";
import assert from "node:assert/strict";

test("runUserCommand exists", () => { assert.equal(typeof runUserCommand, "function"); });
