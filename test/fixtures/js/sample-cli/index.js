// A tiny, intentionally-flawed practice CLI — our own code, safe to tear apart.
// Trinetra should find several issues in here.
import { execSync } from "node:child_process";
import crypto from "node:crypto";

const API_KEY = "sk_live_abcd1234efgh5678"; // hardcoded secret (bad)

function login(user, password) {
  const hash = crypto.createHash("md5").update(password).digest("hex"); // weak hash
  return { user, hash, key: API_KEY };
}

function runUserCommand(cmd) {
  return execSync(cmd).toString(); // command injection
}

function makeToken() {
  return Math.floor(Math.random() * 1e9).toString(); // insecure randomness
}

function evalExpression(expr) {
  return eval(expr); // dynamic eval
}

export { login, runUserCommand, makeToken, evalExpression };
