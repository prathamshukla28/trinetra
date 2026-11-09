// Run context — where Trinetra reads configuration from and writes output to.
//
// Everything is resolved from the *caller's* working directory, never from the
// package install directory, so a global/npx install behaves exactly like a
// source checkout. Precedence for every setting:
//
//   CLI flag  >  environment variable  >  ./trinetra.config.json  >  default

import fs from "node:fs";
import path from "node:path";

export const CONFIG_FILE = "trinetra.config.json";
export const DEFAULT_OUT_DIR = "trinetra-out";

// Read ./trinetra.config.json (or an explicit path). A missing file is normal;
// a malformed one is a user error worth surfacing.
export function loadConfigFile({ cwd = process.cwd(), file } = {}) {
  const full = path.resolve(cwd, file ?? CONFIG_FILE);
  let text;
  try {
    text = fs.readFileSync(full, "utf8");
  } catch (err) {
    if (err.code === "ENOENT" && !file) return { values: {}, source: null };
    throw new Error(`Cannot read config file ${full}: ${err.message}`);
  }
  try {
    const values = JSON.parse(text);
    if (!values || typeof values !== "object" || Array.isArray(values)) throw new Error("not an object");
    return { values, source: full };
  } catch (err) {
    throw new Error(`Invalid JSON in ${full}: ${err.message}`);
  }
}

// Resolve the effective engine configuration. Environment wins over the config
// file so a user's GHIDRA_INSTALL_DIR / JAVA_HOME is never silently overridden.
export function resolveConfig({ cwd = process.cwd(), env = process.env, configFile } = {}) {
  const { values: file, source } = loadConfigFile({ cwd, file: configFile });
  const fromFile = (key) =>
    typeof file[key] === "string" && file[key] ? path.resolve(cwd, file[key]) : null;

  const ghidraInstallDir = env.GHIDRA_INSTALL_DIR || fromFile("ghidraInstallDir") || null;
  const javaBinDir =
    env.TRINETRA_JAVA_BIN_DIR ||
    (env.JAVA_HOME ? path.join(env.JAVA_HOME, "bin") : null) ||
    fromFile("javaBinDir") ||
    null;

  return {
    ghidraInstallDir,
    javaBinDir,
    outDir: env.TRINETRA_OUT || fromFile("outDir"),
    source,
  };
}

// Build the per-run context: absolute output locations under one directory.
export function createContext({ cwd = process.cwd(), env = process.env, out, configFile } = {}) {
  const config = resolveConfig({ cwd, env, configFile });
  const outDir = path.resolve(cwd, out || config.outDir || DEFAULT_OUT_DIR);
  return {
    cwd,
    env,
    config,
    outDir,
    reportsDir: outDir,
    memoryDir: path.join(outDir, ".memory"),
    workDir: path.join(outDir, ".work"),
    rebuiltDir: path.join(outDir, "rebuilt"),
    // Display a path relative to where the user ran the command.
    rel: (p) => {
      const r = path.relative(cwd, p);
      return r && !r.startsWith("..") && !path.isAbsolute(r) ? r : p;
    },
  };
}

// A filesystem-safe name for report files derived from a target name.
export function safeName(s) {
  const name = String(s || "").replace(/[^A-Za-z0-9_.-]/g, "_");
  return !name || /^\.+$/.test(name) ? "target" : name;
}
