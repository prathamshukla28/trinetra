import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { detectFormatFromBytes } from "../src/binary/magic.js";
import { analyzeBinary, capabilitiesFromImports } from "../src/binary/index.js";
import { parseElf } from "../src/binary/elf.js";
import { parseMachO, parseFat, cpuName, parseEntitlementsXml } from "../src/binary/macho.js";
import { parsePe } from "../src/binary/pe.js";
import { BufferSource } from "../src/binary/source.js";
import { buildElf, buildFat, buildMachO, buildPe } from "./helpers/binaries.js";

const rules = (r) => r.findings.map((f) => f.rule).sort();

test("magic bytes: ELF, Mach-O (both endians), fat, PE", () => {
  assert.equal(detectFormatFromBytes(buildElf()), "elf");
  assert.equal(detectFormatFromBytes(buildMachO()), "macho");
  assert.equal(detectFormatFromBytes(Buffer.from([0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 0])), "macho"); // big-endian 64
  assert.equal(detectFormatFromBytes(buildFat([{ cputype: 0x0100000c, data: buildMachO() }])), "fat");
  assert.equal(detectFormatFromBytes(buildPe()), "pe");
});

test("magic bytes: text files and Java classes are not binaries", () => {
  assert.equal(detectFormatFromBytes(Buffer.from("#!/bin/sh\necho hi\n")), null);
  assert.equal(detectFormatFromBytes(Buffer.from("all:\n\tcc main.c\n")), null);
  // Java class: CAFEBABE + minor 0 + major 65 → not a fat binary.
  assert.equal(detectFormatFromBytes(Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65])), null);
  assert.equal(detectFormatFromBytes(Buffer.from("MZ")), null);
  assert.equal(detectFormatFromBytes(Buffer.alloc(0)), null);
});

test("ELF: fully hardened PIE with canary, NX, full RELRO", () => {
  const info = parseElf(new BufferSource(buildElf()));
  assert.equal(info.arch, "x86_64");
  assert.equal(info.pie, true);
  assert.equal(info.nx, true);
  assert.equal(info.relro, "full");
  assert.equal(info.bindNow, true);
  assert.equal(info.interpreter, "/lib64/ld-linux-x86-64.so.2");
  assert.deepEqual(info.libraries, ["libc.so.6"]);
  assert.deepEqual(info.imports, ["__stack_chk_fail", "puts"]); // defined `main` excluded
  assert.deepEqual(rules(analyzeBinary(buildElf())), []);
});

test("ELF: weak build is flagged (no PIE, exec stack, no RELRO, no canary, dangerous imports)", () => {
  const elf = buildElf({
    type: 2,
    stack: "RWX",
    relro: false,
    bindNow: false,
    pieFlag: false,
    imports: ["gets", "strcpy", "system", "puts"],
    runpath: "lib:$ORIGIN/../lib",
  });
  const info = parseElf(new BufferSource(elf));
  assert.equal(info.pie, false);
  assert.equal(info.nx, false);
  assert.equal(info.relro, "none");
  assert.deepEqual(info.runpaths, ["lib:$ORIGIN/../lib"]);
  assert.deepEqual(rules(analyzeBinary(elf)), [
    "binary-command-exec-import",
    "binary-exec-stack",
    "binary-gets-import",
    "binary-no-pie",
    "binary-no-relro",
    "binary-no-stack-canary",
    "binary-relative-rpath",
    "binary-unsafe-string-import",
  ]);
});

test("ELF: missing PT_GNU_STACK means NX is off; GNU_RELRO without BIND_NOW is partial", () => {
  const info = parseElf(new BufferSource(buildElf({ stack: null, bindNow: false })));
  assert.equal(info.nx, false);
  assert.match(info.nxReason, /no PT_GNU_STACK/);
  assert.equal(info.relro, "partial");
  assert.ok(rules(analyzeBinary(buildElf({ bindNow: false }))).includes("binary-partial-relro"));
});

test("ELF: PIE inferred from ET_DYN + interpreter even without DF_1_PIE", () => {
  assert.equal(parseElf(new BufferSource(buildElf({ pieFlag: false }))).pie, true);
  assert.equal(parseElf(new BufferSource(buildElf({ pieFlag: false, interp: false }))).pie, false);
});

test("ELF: rejects non-ELF input", () => {
  assert.throws(() => parseElf(new BufferSource(Buffer.alloc(64))), /not an ELF/);
});

test("Mach-O: header flags, W+X segment, imports, unsigned", () => {
  const bin = buildMachO({ pie: false, stackExec: true, wx: true, imports: ["_gets", "_strcpy", "_puts"] });
  const info = parseMachO(new BufferSource(bin));
  assert.equal(info.arch, "arm64");
  assert.equal(info.filetype, "executable");
  assert.equal(info.pie, false);
  assert.equal(info.stackExecutable, true);
  assert.deepEqual(info.wxSegments, ["__TEXT"]);
  assert.deepEqual(info.imports, ["gets", "puts", "strcpy"]); // leading underscore removed
  assert.equal(info.codeSignature, null);
  assert.deepEqual(rules(analyzeBinary(bin)), [
    "binary-exec-stack",
    "binary-gets-import",
    "binary-no-pie",
    "binary-no-stack-canary",
    "binary-unsafe-string-import",
    "binary-unsigned",
    "binary-wx-segment",
  ]);
});

test("Mach-O: canary import satisfies the stack-protector check", () => {
  const r = analyzeBinary(buildMachO({ imports: ["___stack_chk_fail", "_puts"] }));
  assert.ok(!rules(r).includes("binary-no-stack-canary"));
});

test("fat: lists architectures and merges identical findings across slices", () => {
  const thin = buildMachO({ imports: ["_strcpy"] });
  const fat = buildFat([
    { cputype: 0x01000007, data: thin },
    { cputype: 0x0100000c, cpusubtype: 2, data: thin },
  ]);
  assert.deepEqual(
    parseFat(new BufferSource(fat)).archs.map((a) => a.arch),
    ["x86_64", "arm64e"],
  );
  const r = analyzeBinary(fat);
  assert.equal(r.format, "fat");
  assert.deepEqual(r.archs, ["x86_64", "arm64e"]);
  const s = r.findings.find((f) => f.rule === "binary-unsafe-string-import");
  assert.equal(r.findings.filter((f) => f.rule === "binary-unsafe-string-import").length, 1);
  assert.match(s.evidence, /\[x86_64, arm64e\]/);
});

test("cpu names", () => {
  assert.equal(cpuName(0x01000007, 3), "x86_64");
  assert.equal(cpuName(7, 3), "i386");
  assert.equal(cpuName(0x0100000c, 0x80000002), "arm64e");
  assert.equal(cpuName(0x0200000c, 0), "arm64_32");
});

test("entitlements XML parsing", () => {
  const xml = `<plist><dict><key>com.apple.security.get-task-allow</key><true/><key>x</key><false/></dict></plist>`;
  assert.deepEqual(parseEntitlementsXml(xml), { "com.apple.security.get-task-allow": true, x: false });
});

test("PE: mitigations and imports", () => {
  const weak = parsePe(
    new BufferSource(buildPe({ aslr: false, nx: false, imports: ["WinExec", "lstrcpyA"] })),
  );
  assert.equal(weak.arch, "x86_64");
  assert.equal(weak.aslr, false);
  assert.equal(weak.nx, false);
  assert.deepEqual(weak.libraries, ["KERNEL32.dll"]);
  assert.deepEqual(weak.imports, ["WinExec", "lstrcpyA"]);
  assert.deepEqual(
    rules(analyzeBinary(buildPe({ aslr: false, nx: false, imports: ["WinExec", "lstrcpyA"] }))),
    [
      "binary-command-exec-import",
      "binary-exec-stack",
      "binary-no-cfg",
      "binary-no-pie",
      "binary-unsafe-string-import",
      "binary-unsigned",
    ],
  );
  const strong = analyzeBinary(buildPe({ cfg: true, imports: ["ExitProcess"] }));
  assert.deepEqual(rules(strong), ["binary-unsigned"]);
});

test("capabilities are grouped from imports", () => {
  const caps = capabilitiesFromImports(["socket", "connect", "getenv", "dlopen", "execve", "printf"]);
  assert.deepEqual(caps.network, ["socket", "connect"]);
  assert.deepEqual(caps.environment, ["getenv"]);
  assert.deepEqual(caps["dynamic loading"], ["dlopen"]);
  assert.deepEqual(caps["process execution"], ["execve"]);
  assert.equal(caps.printf, undefined);
});

const ECHO = "/bin/echo";
test(
  "real Mach-O: /bin/echo (macOS only)",
  { skip: !(process.platform === "darwin" && fs.existsSync(ECHO)) },
  () => {
    const r = analyzeBinary(ECHO);
    assert.ok(["fat", "macho"].includes(r.format));
    assert.ok(r.archs.length >= 1);
    assert.ok(r.imports.includes("getenv"), "echo reads POSIXLY_CORRECT via getenv");
    assert.ok(r.libraries.some((l) => l.includes("libSystem")));
    for (const s of r.slices) {
      assert.equal(s.pie, true);
      assert.equal(s.codeSignature?.present, true);
    }
    // Apple platform binaries are not flagged for missing Hardened Runtime.
    assert.ok(!rules(r).includes("binary-no-hardened-runtime"));
  },
);

// --- regressions found by the accuracy benchmark (bench/, oracle: otool/nm/lipo) ---

test("cpuName: x86_64h (cpusubtype 8) is distinct from x86_64", () => {
  assert.equal(cpuName(0x01000007, 8), "x86_64h");
  assert.equal(cpuName(0x01000007, 3), "x86_64");
});

test("chained fixups: weak-definition coalescing entries are not imports", () => {
  // lib_ordinal -3 (BIND_SPECIAL_DYLIB_WEAK_LOOKUP) binds a symbol the binary
  // defines itself; nm -u does not list it, and neither should Trinetra.
  const bin = buildMachO({
    imports: [],
    chained: [
      { name: "_strcpy", ordinal: 1 },
      { name: "__ZTSNSt3__114default_deleteIiEE", ordinal: -3 },
      { name: "___stack_chk_fail", ordinal: 2 },
    ],
  });
  const info = parseMachO(new BufferSource(bin));
  assert.deepEqual(info.imports, ["__stack_chk_fail", "strcpy"]);
});
