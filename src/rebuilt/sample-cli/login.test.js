// TEST FIRST. Describe login — "authentication / secrets".
import { login } from "./login.js";

import test from "node:test";
import assert from "node:assert/strict";

test("login exists", () => { assert.equal(typeof login, "function"); });
