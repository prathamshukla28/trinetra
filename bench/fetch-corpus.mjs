#!/usr/bin/env node
// Fetch the external benchmark corpus at a pinned commit into bench/corpus/.
//
// The downloaded code is treated as untrusted DATA: it is only parsed by
// Trinetra's analyzer. Nothing in it is installed, required, or executed —
// no `npm install`, no git hooks (a fresh fetch has none), no scripts.
//
//   node bench/fetch-corpus.mjs          # fetch (idempotent)
//   node bench/fetch-corpus.mjs --check  # verify the checkout is at the pin

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const CORPUS_DIR = path.join(HERE, "corpus");

export const CORPORA = [
  {
    name: "NodeGoat",
    repo: "https://github.com/OWASP/NodeGoat.git",
    // master as of 2026-11-10 (`git ls-remote https://github.com/OWASP/NodeGoat HEAD`)
    commit: "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
    dir: "NodeGoat",
  },
];

const git = (cwd, ...args) =>
  execFileSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "advice.detachedHead=false", ...args], {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
  })
    .toString()
    .trim();

export function corpusPath(c) {
  return path.join(CORPUS_DIR, c.dir);
}

export function checkoutHead(c) {
  try {
    return git(corpusPath(c), "rev-parse", "HEAD");
  } catch {
    return null;
  }
}

function fetchOne(c) {
  const dest = corpusPath(c);
  if (checkoutHead(c) === c.commit) {
    console.log(`${c.name}: already at ${c.commit}`);
    return;
  }
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });
  git(dest, "init", "-q");
  git(dest, "remote", "add", "origin", c.repo);
  git(dest, "fetch", "-q", "--depth", "1", "origin", c.commit);
  git(dest, "checkout", "-q", "FETCH_HEAD");
  const head = checkoutHead(c);
  if (head !== c.commit) throw new Error(`${c.name}: expected ${c.commit}, got ${head}`);
  console.log(`${c.name}: fetched ${c.commit}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  fs.mkdirSync(CORPUS_DIR, { recursive: true });
  for (const c of CORPORA) {
    if (process.argv.includes("--check")) {
      const head = checkoutHead(c);
      console.log(`${c.name}: ${head === c.commit ? "ok" : `MISMATCH (${head ?? "missing"})`}`);
      if (head !== c.commit) process.exitCode = 1;
    } else fetchOne(c);
  }
}
