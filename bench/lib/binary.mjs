// Binary benchmark: run Trinetra's pure-JS parsers (src/binary) over real
// binaries and compare each hardening field against an independent oracle:
//
//   Mach-O   otool -hv (filetype, PIE, ALLOW_STACK_EXECUTION), nm -u (imported
//            symbols, ___stack_chk_fail), codesign -dvvv (signature, ad-hoc,
//            hardened runtime, platform binary), lipo -archs (slices)
//   ELF      file(1) (PIE / static), llvm-objdump -p (GNU_STACK, RELRO,
//            BIND_NOW, RPATH/RUNPATH), llvm-objdump -T (undefined symbols)
//
// Corpus: system binaries (/bin, a deterministic stride of /usr/bin and
// /usr/sbin), Homebrew and /Applications executables when present, Node itself,
// plus fixtures generated locally (clang for Mach-O variants; Go cross-builds
// and the test-suite ELF builder for ELF). Nothing downloaded is executed.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { analyzeBinary } from "../../src/binary/index.js";
import { detectFormat } from "../../src/binary/magic.js";
import { findBundleExecutable } from "../../src/stages/inspect.js";
import { buildElf } from "../../test/helpers/binaries.js";

const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...opts });
  return { code: r.status, out: r.stdout ?? "", err: r.stderr ?? "", error: r.error };
};
const have = (cmd) => !run("/usr/bin/which", [cmd]).code;

// ---------------------------------------------------------------------------
// Corpus selection (deterministic for a given machine)

function machOFilesIn(dir) {
  let names;
  try {
    names = fs.readdirSync(dir).sort();
  } catch {
    return [];
  }
  const out = [];
  for (const n of names) {
    const full = path.join(dir, n);
    try {
      const real = fs.realpathSync(full);
      if (!fs.statSync(real).isFile()) continue;
      const fmt = detectFormat(real);
      if (fmt === "macho" || fmt === "fat") out.push(real);
    } catch {
      /* unreadable: skip */
    }
  }
  return [...new Set(out)];
}

const stride = (list, max) => {
  if (list.length <= max) return list;
  const step = list.length / max;
  return Array.from({ length: max }, (_, i) => list[Math.floor(i * step)]);
};

function appExecutables() {
  let apps;
  try {
    apps = fs
      .readdirSync("/Applications")
      .filter((n) => n.endsWith(".app"))
      .sort();
  } catch {
    return [];
  }
  return apps.map((a) => findBundleExecutable(path.join("/Applications", a))).filter(Boolean);
}

function buildMachOFixtures(outDir) {
  if (!have("clang") || !have("codesign"))
    return { files: [], notes: ["clang/codesign missing: no Mach-O fixtures"] };
  fs.mkdirSync(outDir, { recursive: true });
  const src = path.resolve("bench/fixtures/vuln.c");
  const notes = [];
  const files = [];
  const variants = [
    ["canary", ["-fstack-protector-all"]],
    ["no-canary", ["-fno-stack-protector"]],
    ["fat", ["-arch", "arm64", "-arch", "x86_64"]],
    ["x86_64-no-pie", ["-arch", "x86_64", "-Wl,-no_pie"]],
    ["dylib", ["-dynamiclib"]],
  ];
  for (const [name, flags] of variants) {
    const out = path.join(outDir, `macho-${name}`);
    const r = run("clang", ["-O0", ...flags, "-o", out, src]);
    if (r.code !== 0) notes.push(`fixture ${name}: clang failed (${r.err.split("\n")[0]})`);
    else files.push(out);
  }
  const base = path.join(outDir, "macho-canary");
  if (fs.existsSync(base)) {
    const unsigned = path.join(outDir, "macho-unsigned");
    fs.copyFileSync(base, unsigned);
    run("codesign", ["--remove-signature", unsigned]);
    files.push(unsigned);
    const hardened = path.join(outDir, "macho-hardened-runtime");
    fs.copyFileSync(base, hardened);
    const r = run("codesign", ["-f", "-s", "-", "-o", "runtime", hardened]);
    if (r.code === 0) files.push(hardened);
    else notes.push("fixture hardened-runtime: codesign failed");
    // Current Apple ld dropped -allow_stack_execute, so set MH_ALLOW_STACK_EXECUTION
    // (0x20000) in the header flags of a copy directly, then re-sign it ad hoc.
    const execStack = path.join(outDir, "macho-exec-stack");
    const buf = fs.readFileSync(base);
    if (buf.readUInt32LE(0) === 0xfeedfacf) {
      buf.writeUInt32LE(buf.readUInt32LE(24) | 0x20000, 24);
      fs.writeFileSync(execStack, buf);
      if (run("codesign", ["-f", "-s", "-", execStack]).code === 0) files.push(execStack);
      else notes.push("fixture exec-stack: codesign failed");
    }
  }
  return { files, notes };
}

function buildElfFixtures(outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const files = [];
  const notes = [];
  // 1. Real toolchain output: Go cross-compiled to Linux (pure Go, no cgo).
  if (have("go")) {
    const src = path.resolve("bench/fixtures/hello.go");
    const env = {
      ...process.env,
      CGO_ENABLED: "0",
      GOOS: "linux",
      GOFLAGS: "-trimpath",
      GOCACHE: path.join(outDir, ".gocache"),
    };
    for (const [arch, mode] of [
      ["amd64", "exe"],
      ["amd64", "pie"],
      ["arm64", "exe"],
      ["arm64", "pie"],
      ["386", "exe"],
    ]) {
      const out = path.join(outDir, `go-linux-${arch}-${mode}`);
      if (!fs.existsSync(out)) {
        const r = run("go", ["build", `-buildmode=${mode}`, "-o", out, src], {
          env: { ...env, GOARCH: arch },
        });
        if (r.code !== 0) {
          notes.push(`go ${arch}/${mode}: build failed`);
          continue;
        }
      }
      files.push(out);
    }
  } else notes.push("go not installed: no toolchain-built ELF fixtures");
  // 2. Hand-built variants from the test-suite ELF builder (covers imports,
  //    executable stack, RELRO levels and RUNPATH, which Go output lacks).
  const variants = {
    "builder-hardened": {},
    "builder-weak": {
      type: 2,
      stack: "RWX",
      relro: false,
      bindNow: false,
      pieFlag: false,
      imports: ["gets", "strcpy", "system", "puts"],
      runpath: "lib:$ORIGIN/../lib",
    },
    "builder-partial-relro": { bindNow: false, imports: ["printf", "memcpy"] },
    "builder-no-gnu-stack": { stack: null },
    "builder-et-dyn-no-pie-flag": { pieFlag: false },
  };
  for (const [name, opts] of Object.entries(variants)) {
    const out = path.join(outDir, `elf-${name}`);
    fs.writeFileSync(out, buildElf(opts));
    files.push(out);
  }
  return { files, notes };
}

// ---------------------------------------------------------------------------
// Oracles

const stripUnderscore = (s) => (s.startsWith("_") ? s.slice(1) : s);

function machOTruth(file, arch, isFat) {
  const archArgs = isFat ? ["-arch", arch] : [];
  const hv = run("otool", ["-hv", ...archArgs, file]).out;
  const row = hv.split("\n").find((l) => /^\s*MH_(MAGIC|CIGAM)/.test(l)) ?? "";
  const tokens = row.trim().split(/\s+/);
  const nm = run("nm", ["-u", ...archArgs, file]);
  const imports = nm.out
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map(stripUnderscore);
  const cs = run("codesign", ["-dvvv", ...(isFat ? ["--arch", arch] : []), file]);
  const csText = cs.err + cs.out;
  const signed = !/not signed at all/.test(csText) && /CodeDirectory/.test(csText);
  const flags = Number.parseInt(
    csText.match(/CodeDirectory v=\S+ size=\d+ flags=(0x[0-9a-f]+)/)?.[1] ?? "0",
    16,
  );
  return {
    executable: tokens.includes("EXECUTE"),
    pie: tokens.includes("PIE"),
    execStack: tokens.includes("ALLOW_STACK_EXECUTION"),
    imports: [...new Set(imports)].sort(),
    canary: imports.includes("__stack_chk_fail") || imports.includes("__stack_chk_guard"),
    signed,
    adhoc: signed && Boolean(flags & 0x2),
    hardenedRuntime: signed && Boolean(flags & 0x10000),
    platformBinary: signed && /Platform identifier=\d+/.test(csText),
  };
}

function machOTrinetra(slice) {
  const imports = slice.imports ?? [];
  const sig = slice.codeSignature;
  return {
    executable: slice.isExecutable,
    pie: slice.pie,
    execStack: slice.stackExecutable,
    imports: [...new Set(imports)].sort(),
    canary: imports.includes("__stack_chk_fail") || imports.includes("__stack_chk_guard"),
    signed: Boolean(sig),
    adhoc: Boolean(sig?.adhoc),
    hardenedRuntime: Boolean(sig?.hardenedRuntime),
    platformBinary: Boolean(sig?.platformBinary),
  };
}

function elfTruth(file) {
  const desc = run("file", ["-b", file]).out;
  const p = run("objdump", ["-p", file]).out;
  const t = run("objdump", ["-T", file]).out;
  const phdrFlags = (name) => {
    const m = p.match(new RegExp(`^\\s*${name} off[^\\n]*\\n\\s*filesz[^\\n]*flags (\\S+)`, "m"));
    return m ? m[1] : null;
  };
  const dyn = (tag) => p.match(new RegExp(`^\\s*${tag}\\s+(\\S+)`, "m"))?.[1] ?? null;
  const stack = phdrFlags("STACK");
  const flags = Number.parseInt(dyn("FLAGS") ?? "0", 16) || 0;
  const flags1 = Number.parseInt(dyn("FLAGS_1") ?? "0", 16) || 0;
  const bindNow = dyn("BIND_NOW") !== null || Boolean(flags & 0x8) || Boolean(flags1 & 0x1);
  const relro = phdrFlags("RELRO") === null ? "none" : bindNow ? "full" : "partial";
  const imports = t
    .split("\n")
    .filter((l) => /\*UND\*/.test(l))
    .map((l) => l.trim().split(/\s+/).at(-1).split("@")[0])
    .filter(Boolean);
  return {
    pie: /\bpie executable\b/.test(desc),
    static: /statically linked/.test(desc),
    nx: stack !== null && !stack.includes("x"),
    relro,
    imports: [...new Set(imports)].sort(),
    canary: imports.includes("__stack_chk_fail"),
    runpath: [dyn("RPATH"), dyn("RUNPATH")].filter(Boolean).sort(),
  };
}

function elfTrinetra(s) {
  const imports = s.imports ?? [];
  return {
    pie: s.pie,
    static: s.isStatic,
    nx: s.nx,
    relro: s.relro,
    imports: [...new Set(imports)].sort(),
    canary: imports.includes("__stack_chk_fail"),
    runpath: [...s.rpaths, ...s.runpaths].sort(),
  };
}

// ---------------------------------------------------------------------------

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const display = (file) => {
  const corpus = path.resolve("bench/corpus");
  return file.startsWith(corpus)
    ? `bench/corpus/${path.relative(corpus, file)}`
    : file.replace(os.homedir(), "~");
};

function tally(rows, checks) {
  return Object.fromEntries(
    checks.map((c) => {
      const applicable = rows.filter((r) => c in r.truth);
      const agree = applicable.filter((r) => same(r.truth[c], r.trinetra[c])).length;
      return [
        c,
        { agree, total: applicable.length, rate: applicable.length ? agree / applicable.length : null },
      ];
    }),
  );
}

export function runBinaryBench({ fixturesDir = path.resolve("bench/corpus/fixtures") } = {}) {
  const notes = [];
  const result = { platform: null, macho: null, elf: null, notes };

  if (process.platform === "darwin" && have("otool") && have("codesign") && have("nm")) {
    result.platform = `macOS ${run("sw_vers", ["-productVersion"]).out.trim()} (${run("sw_vers", ["-buildVersion"]).out.trim()}), ${os.arch()}`;
    const groups = {
      "/bin": machOFilesIn("/bin"),
      "/usr/bin (stride)": stride(machOFilesIn("/usr/bin"), 80),
      "/usr/sbin (stride)": stride(machOFilesIn("/usr/sbin"), 20),
      "/opt/homebrew/bin (stride)": stride(machOFilesIn("/opt/homebrew/bin"), 25),
      "/Applications": appExecutables(),
      "node (process.execPath)": [fs.realpathSync(process.execPath)],
    };
    const fx = buildMachOFixtures(path.join(fixturesDir, "macho"));
    notes.push(...fx.notes);
    groups["generated fixtures (clang)"] = fx.files;

    const seen = new Set();
    const rows = [];
    const fileRows = [];
    for (const [group, files] of Object.entries(groups)) {
      for (const file of files) {
        if (seen.has(file)) continue;
        seen.add(file);
        let a;
        try {
          a = analyzeBinary(file);
        } catch (err) {
          fileRows.push({ file: display(file), group, error: err.message });
          continue;
        }
        const isFat = a.format === "fat";
        const lipo = run("lipo", ["-archs", file]).out.trim().split(/\s+/).filter(Boolean).sort();
        fileRows.push({
          file: display(file),
          group,
          archs: { truth: lipo, trinetra: [...a.archs].sort(), agree: same(lipo, [...a.archs].sort()) },
        });
        for (const s of a.slices) {
          if (s.error) {
            rows.push({ file: display(file), group, arch: s.arch, error: s.error, truth: {}, trinetra: {} });
            continue;
          }
          rows.push({
            file: display(file),
            group,
            arch: s.arch,
            truth: machOTruth(file, s.arch, isFat),
            trinetra: machOTrinetra(s),
          });
        }
      }
    }
    const checks = [
      "executable",
      "pie",
      "execStack",
      "canary",
      "imports",
      "signed",
      "adhoc",
      "hardenedRuntime",
      "platformBinary",
    ];
    const perCheck = tally(rows, checks);
    const archRows = fileRows.filter((r) => r.archs);
    perCheck.archs = {
      agree: archRows.filter((r) => r.archs.agree).length,
      total: archRows.length,
      rate: archRows.length ? archRows.filter((r) => r.archs.agree).length / archRows.length : null,
    };
    const groupCounts = {};
    for (const r of fileRows) groupCounts[r.group] = (groupCounts[r.group] ?? 0) + 1;
    const truthCounts = Object.fromEntries(
      ["pie", "canary", "signed", "adhoc", "hardenedRuntime", "platformBinary", "execStack"].map((k) => [
        k,
        rows.filter((r) => r.truth[k] === true).length,
      ]),
    );
    result.macho = {
      binaries: fileRows.length,
      slices: rows.length,
      groups: groupCounts,
      positivesInOracle: truthCounts,
      perCheck,
      disagreements: rows
        .flatMap((r) =>
          checks
            .filter((c) => c in r.truth && !same(r.truth[c], r.trinetra[c]))
            .map((c) => ({
              file: r.file,
              arch: r.arch,
              check: c,
              truth: c === "imports" ? diffSets(r.truth.imports, r.trinetra.imports) : r.truth[c],
              trinetra: c === "imports" ? undefined : r.trinetra[c],
            })),
        )
        .concat(
          archRows.filter((r) => !r.archs.agree).map((r) => ({ file: r.file, check: "archs", ...r.archs })),
        ),
      errors: [...fileRows.filter((r) => r.error), ...rows.filter((r) => r.error)].map((r) => ({
        file: r.file,
        arch: r.arch,
        error: r.error,
      })),
    };
  } else {
    notes.push("Mach-O checks skipped: needs macOS with otool, nm and codesign.");
  }

  if (have("objdump") && have("file") && /LLVM/.test(run("objdump", ["--version"]).out)) {
    const fx = buildElfFixtures(path.join(fixturesDir, "elf"));
    notes.push(...fx.notes);
    const rows = [];
    for (const file of fx.files) {
      const a = analyzeBinary(file);
      const s = a.slices[0];
      rows.push({ file: display(file), truth: elfTruth(file), trinetra: elfTrinetra(s) });
    }
    const checks = ["pie", "static", "nx", "relro", "canary", "imports", "runpath"];
    result.elf = {
      binaries: rows.length,
      perCheck: tally(rows, checks),
      disagreements: rows.flatMap((r) =>
        checks
          .filter((c) => !same(r.truth[c], r.trinetra[c]))
          .map((c) => ({ file: r.file, check: c, truth: r.truth[c], trinetra: r.trinetra[c] })),
      ),
      files: rows.map((r) => r.file),
    };
  } else {
    notes.push("ELF checks skipped: needs llvm-objdump (as `objdump`) and file(1).");
  }
  return result;
}

function diffSets(truth, mine) {
  const t = new Set(truth);
  const m = new Set(mine);
  return {
    onlyOracle: truth.filter((x) => !m.has(x)).slice(0, 10),
    onlyTrinetra: mine.filter((x) => !t.has(x)).slice(0, 10),
    counts: [truth.length, mine.length],
  };
}
