// Native binary analysis owned by Trinetra (no Ghidra / REA needed): parse the
// executable format directly, then derive hardening findings and a capability
// profile from header flags and imported functions.

import { BufferSource, FileSource } from "./source.js";
import { detectFormatFromBytes } from "./magic.js";
import { parseMachO, parseFatSlices } from "./macho.js";
import { parseElf } from "./elf.js";
import { parsePe } from "./pe.js";

// Parse any supported binary from a byte source. Returns { format, slices }.
export function parseBinary(src) {
  const format = detectFormatFromBytes(src.read(0, 4096));
  if (format === "fat") return { format, slices: parseFatSlices(src) };
  if (format === "macho") return { format, slices: [parseMachO(src)] };
  if (format === "elf") return { format, slices: [parseElf(src)] };
  if (format === "pe") return { format, slices: [parsePe(src)] };
  throw new Error("unrecognized binary format");
}

const IMPORT_RULES = [
  {
    id: "binary-gets-import",
    severity: "high",
    names: ["gets"],
    title: "Imports gets()",
    why: "gets() cannot bound its input; any use is a stack buffer overflow waiting for long input.",
  },
  {
    id: "binary-unsafe-string-import",
    severity: "medium",
    names: [
      "strcpy",
      "strcat",
      "sprintf",
      "vsprintf",
      "stpcpy",
      "wcscpy",
      "wcscat",
      "lstrcpyA",
      "lstrcpyW",
      "lstrcatA",
      "lstrcatW",
    ],
    title: "Imports unbounded string functions",
    why: "These copy without a length limit — classic buffer-overflow sources if any input reaches them.",
  },
  {
    id: "binary-command-exec-import",
    severity: "medium",
    names: ["system", "popen", "execl", "execlp", "execvp", "WinExec", "ShellExecuteA", "ShellExecuteW"],
    title: "Imports shell / command execution",
    why: "Spawning a shell is command-injection-prone if any external input is part of the command.",
  },
  {
    id: "binary-insecure-tempfile-import",
    severity: "low",
    names: ["mktemp", "tmpnam", "tempnam"],
    title: "Imports race-prone temp-file functions",
    why: "mktemp/tmpnam create predictable names (TOCTOU symlink attacks); use mkstemp.",
  },
];

const CAPABILITIES = [
  [
    "network",
    /^(socket|connect|bind|listen|accept|getaddrinfo|gethostbyname|send|sendto|recv|recvfrom|curl_.*|SSL_.*|WSAStartup|InternetOpen.*|WinHttp.*|URLDownloadToFile.*)$/,
  ],
  [
    "process execution",
    /^(system|popen|fork|vfork|execve?|execv?p|execl[ep]?|posix_spawnp?|CreateProcess[AW]?|ShellExecute.*|WinExec)$/,
  ],
  [
    "filesystem",
    /^(fopen|open|openat|unlink|remove|rename|mkdir|rmdir|chmod|CreateFile[AW]?|WriteFile|DeleteFile[AW]?)$/,
  ],
  ["environment", /^(getenv|secure_getenv|setenv|GetEnvironmentVariable[AW]?)$/],
  ["dynamic loading", /^(dlopen|dlsym|LoadLibrary.*|GetProcAddress)$/],
  ["cryptography", /^(CC[A-Z].*|SecKey.*|EVP_.*|RAND_bytes|arc4random.*|BCrypt.*|Crypt[A-Z].*)$/],
  [
    "privilege / debugging",
    /^(setuid|setgid|seteuid|setegid|ptrace|task_for_pid|AdjustTokenPrivileges|OpenProcessToken)$/,
  ],
  ["memory protection changes", /^(mprotect|VirtualProtect(Ex)?|VirtualAlloc(Ex)?)$/],
];

const RISKY_ENTITLEMENTS = {
  "com.apple.security.cs.disable-library-validation": "loads unsigned/third-party dylibs (dylib hijacking)",
  "com.apple.security.cs.allow-unsigned-executable-memory": "allows unsigned executable memory",
  "com.apple.security.cs.allow-dyld-environment-variables": "honours DYLD_* injection variables",
  "com.apple.security.get-task-allow": "debuggable by other processes (development signing)",
  "com.apple.security.cs.disable-executable-page-protection": "disables executable page protection",
};

const finding = (rule, severity, title, why, where, evidence, confidence = "high") => ({
  rule,
  severity,
  title,
  why,
  where,
  evidence,
  engine: "trinetra-binary",
  confidence,
});

// Hardening findings for one parsed slice.
function sliceFindings(s, where) {
  const out = [];
  const imports = new Set(s.imports ?? []);
  const exec = s.isExecutable;

  if (s.format === "macho" || s.format === "elf") {
    if (exec && !s.pie && s.filetype !== "shared-object")
      out.push(
        finding(
          "binary-no-pie",
          "medium",
          "Not position-independent (no ASLR)",
          "Fixed load addresses make memory-corruption exploits reliable.",
          where,
          `filetype=${s.filetype}, PIE=false`,
        ),
      );
    const canary = imports.has("__stack_chk_fail") || imports.has("__stack_chk_guard");
    if (exec && !canary && imports.size > 0 && !s.isStatic)
      out.push(
        finding(
          "binary-no-stack-canary",
          "low",
          "No stack canary (__stack_chk_fail not imported)",
          "Built without -fstack-protector (or no function needed one); stack overflows go undetected.",
          where,
          `${imports.size} imports, none of __stack_chk_fail/__stack_chk_guard`,
          "medium",
        ),
      );
  }

  if (s.format === "macho") {
    if (s.stackExecutable)
      out.push(
        finding(
          "binary-exec-stack",
          "high",
          "Executable stack",
          "MH_ALLOW_STACK_EXECUTION lets injected shellcode run from the stack.",
          where,
          "MH_ALLOW_STACK_EXECUTION set",
        ),
      );
    const sig = s.codeSignature;
    if (!sig) {
      out.push(
        finding(
          "binary-unsigned",
          "low",
          "No code signature",
          "Unsigned code can't be verified or notarized and is trivially tampered with.",
          where,
          "no LC_CODE_SIGNATURE",
        ),
      );
    } else if (exec && !sig.hardenedRuntime && !sig.platformBinary && s.platform === "macOS") {
      out.push(
        finding(
          "binary-no-hardened-runtime",
          "low",
          "Hardened Runtime not enabled",
          "Without the Hardened Runtime, code injection and DYLD_* environment abuse are not blocked.",
          where,
          sig.adhoc ? "ad-hoc signature, CS_RUNTIME not set" : "CS_RUNTIME not set",
        ),
      );
    }
    for (const [ent, risk] of Object.entries(RISKY_ENTITLEMENTS)) {
      if (sig?.entitlements?.[ent])
        out.push(
          finding(
            "binary-risky-entitlement",
            "medium",
            `Risky entitlement: ${ent}`,
            `This entitlement ${risk}.`,
            where,
            `${ent} = true`,
          ),
        );
    }
  }

  if (s.format === "elf") {
    if (!s.nx)
      out.push(
        finding(
          "binary-exec-stack",
          "high",
          "Executable stack (NX disabled)",
          "Injected shellcode can execute from the stack.",
          where,
          s.nxReason,
        ),
      );
    if (s.relro === "none" && !s.isStatic)
      out.push(
        finding(
          "binary-no-relro",
          "medium",
          "No RELRO",
          "The GOT stays writable, so a write primitive can redirect library calls.",
          where,
          "no PT_GNU_RELRO",
        ),
      );
    else if (s.relro === "partial")
      out.push(
        finding(
          "binary-partial-relro",
          "low",
          "Partial RELRO (no BIND_NOW)",
          "Lazy binding leaves the .got.plt writable at runtime.",
          where,
          "PT_GNU_RELRO without BIND_NOW",
        ),
      );
    const paths = [...s.rpaths, ...s.runpaths].filter((p) =>
      p.split(":").some((x) => x && !x.startsWith("/") && !x.startsWith("$ORIGIN")),
    );
    if (paths.length)
      out.push(
        finding(
          "binary-relative-rpath",
          "medium",
          "Relative RPATH/RUNPATH",
          "Libraries can be hijacked from an attacker-controlled working directory.",
          where,
          paths.join(", "),
        ),
      );
  }

  if (s.format === "pe") {
    if (!s.aslr)
      out.push(
        finding(
          "binary-no-pie",
          "medium",
          "ASLR disabled (no DYNAMIC_BASE)",
          "Fixed load addresses make exploits reliable.",
          where,
          "DllCharacteristics lacks DYNAMIC_BASE",
        ),
      );
    if (!s.nx)
      out.push(
        finding(
          "binary-exec-stack",
          "high",
          "DEP/NX not enabled",
          "Data pages may be executable, enabling shellcode.",
          where,
          "DllCharacteristics lacks NX_COMPAT",
        ),
      );
    if (!s.cfg)
      out.push(
        finding(
          "binary-no-cfg",
          "low",
          "Control Flow Guard not enabled",
          "Indirect calls are not validated.",
          where,
          "DllCharacteristics lacks GUARD_CF",
          "medium",
        ),
      );
    if (!s.signed)
      out.push(
        finding(
          "binary-unsigned",
          "low",
          "No Authenticode signature",
          "Unsigned code can't be verified and is trivially tampered with.",
          where,
          "empty certificate table",
        ),
      );
  }

  if (s.wxSegments?.length)
    out.push(
      finding(
        "binary-wx-segment",
        "high",
        "Writable + executable segment",
        "W^X violation: code can be written and then executed.",
        where,
        s.wxSegments.join(", "),
      ),
    );

  for (const r of IMPORT_RULES) {
    const hit = r.names.filter((n) => imports.has(n));
    if (hit.length) out.push(finding(r.id, r.severity, r.title, r.why, where, hit.join(", ")));
  }
  return out;
}

// Group imported functions into what the program can *do*.
export function capabilitiesFromImports(imports) {
  const caps = {};
  for (const name of imports) {
    for (const [cap, re] of CAPABILITIES) {
      if (re.test(name)) (caps[cap] ??= []).push(name);
    }
  }
  return caps;
}

// Merge identical findings across fat-binary slices, noting which archs hit.
function mergeSlices(perSlice) {
  const merged = new Map();
  for (const { arch, findings } of perSlice) {
    for (const f of findings) {
      const key = `${f.rule}|${f.title}|${f.evidence}`;
      const g = merged.get(key);
      if (g) g.archs.push(arch);
      else merged.set(key, { ...f, archs: [arch] });
    }
  }
  return [...merged.values()].map(({ archs, ...f }) =>
    perSlice.length > 1 ? { ...f, evidence: `${f.evidence} [${archs.join(", ")}]` } : f,
  );
}

// Analyze a binary file (or buffer). `where` is the label used in findings.
export function analyzeBinary(fileOrBuffer, { where } = {}) {
  const src = Buffer.isBuffer(fileOrBuffer) ? new BufferSource(fileOrBuffer) : new FileSource(fileOrBuffer);
  try {
    const { format, slices } = parseBinary(src);
    const label = where ?? (Buffer.isBuffer(fileOrBuffer) ? "<buffer>" : fileOrBuffer);
    const ok = slices.filter((s) => !s.error);
    const findings = mergeSlices(ok.map((s) => ({ arch: s.arch, findings: sliceFindings(s, label) })));
    const imports = [...new Set(ok.flatMap((s) => s.imports ?? []))].sort();
    return {
      format,
      archs: slices.map((s) => s.arch),
      slices,
      imports,
      libraries: [...new Set(ok.flatMap((s) => s.libraries ?? []))],
      capabilities: capabilitiesFromImports(imports),
      findings,
    };
  } finally {
    src.close();
  }
}
