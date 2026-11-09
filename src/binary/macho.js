// Mach-O and universal (fat) binary parser — pure JavaScript, no external tools.
//
// Extracts what a hardening review needs: file type and header flags (PIE,
// executable stack), segments (W+X), linked libraries, imported symbols (from
// both the classic symbol table and the newer chained-fixups import table),
// and the code signature (ad-hoc vs. CMS-signed, Hardened Runtime, entitlements).

import { cstring, SliceSource } from "./source.js";

const MH_EXECUTE = 0x2;
const FILETYPES = {
  1: "object",
  2: "executable",
  3: "fvmlib",
  4: "core",
  5: "preload",
  6: "dylib",
  7: "dylinker",
  8: "bundle",
  9: "dylib-stub",
  10: "dsym",
  11: "kext",
};

const MH_ALLOW_STACK_EXECUTION = 0x20000;
const MH_PIE = 0x200000;
const MH_NO_HEAP_EXECUTION = 0x1000000;

const LC = {
  SEGMENT: 0x1,
  SYMTAB: 0x2,
  DYSYMTAB: 0xb,
  LOAD_DYLIB: 0xc,
  LAZY_LOAD_DYLIB: 0x20,
  SEGMENT_64: 0x19,
  CODE_SIGNATURE: 0x1d,
  ENCRYPTION_INFO: 0x21,
  ENCRYPTION_INFO_64: 0x2c,
  BUILD_VERSION: 0x32,
  LOAD_WEAK_DYLIB: 0x80000018,
  RPATH: 0x8000001c,
  REEXPORT_DYLIB: 0x8000001f,
  LOAD_UPWARD_DYLIB: 0x80000023,
  MAIN: 0x80000028,
  DYLD_CHAINED_FIXUPS: 0x80000034,
};
const DYLIB_CMDS = new Set([
  LC.LOAD_DYLIB,
  LC.LAZY_LOAD_DYLIB,
  LC.LOAD_WEAK_DYLIB,
  LC.REEXPORT_DYLIB,
  LC.LOAD_UPWARD_DYLIB,
]);

const PLATFORMS = { 1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "macCatalyst", 11: "visionOS" };

const CPU_ARCH_ABI64 = 0x01000000;
const CPU_ARCH_ABI64_32 = 0x02000000;

// Human-readable architecture name from cputype/cpusubtype.
export function cpuName(cputype, cpusubtype) {
  const base = cputype & 0xffffff;
  const sub = cpusubtype & 0xff;
  if (base === 7) return cputype & CPU_ARCH_ABI64 ? "x86_64" : "i386";
  if (base === 12) {
    if (cputype & CPU_ARCH_ABI64) return sub === 2 ? "arm64e" : "arm64";
    if (cputype & CPU_ARCH_ABI64_32) return "arm64_32";
    return "arm";
  }
  if (base === 18) return cputype & CPU_ARCH_ABI64 ? "ppc64" : "ppc";
  return `cpu-${cputype >>> 0}`;
}

// Parse a fat header. Returns the list of architecture slices.
export function parseFat(src) {
  const head = src.read(0, 8);
  const magic = head.readUInt32BE(0);
  const is64 = magic === 0xcafebabf;
  const n = Math.min(head.readUInt32BE(4), 64);
  const entSize = is64 ? 32 : 20;
  const table = src.read(8, n * entSize);
  const archs = [];
  for (let i = 0; i < n && (i + 1) * entSize <= table.length; i++) {
    const o = i * entSize;
    const cputype = table.readUInt32BE(o);
    const cpusubtype = table.readUInt32BE(o + 4);
    const offset = is64 ? Number(table.readBigUInt64BE(o + 8)) : table.readUInt32BE(o + 8);
    const size = is64 ? Number(table.readBigUInt64BE(o + 16)) : table.readUInt32BE(o + 12);
    archs.push({ arch: cpuName(cputype, cpusubtype), offset, size });
  }
  return { archs };
}

// Boolean entitlements from an XML plist (enough for risk review).
export function parseEntitlementsXml(xml) {
  const out = {};
  const re = /<key>([^<]+)<\/key>\s*<(true|false)\s*\/>/g;
  let m;
  while ((m = re.exec(xml))) out[m[1]] = m[2] === "true";
  return out;
}

// Code signature SuperBlob (big-endian). Reports how the binary is signed.
function parseCodeSignature(src, dataoff, datasize) {
  const sig = {
    present: true,
    adhoc: false,
    hardenedRuntime: false,
    cms: false,
    platformBinary: false,
    identifier: null,
    entitlements: {},
  };
  const blob = src.read(dataoff, Math.min(datasize, 4 * 1024 * 1024));
  if (blob.length < 12 || blob.readUInt32BE(0) !== 0xfade0cc0) return sig;
  const count = Math.min(blob.readUInt32BE(8), 64);
  for (let i = 0; i < count; i++) {
    const e = 12 + i * 8;
    if (e + 8 > blob.length) break;
    const type = blob.readUInt32BE(e);
    const off = blob.readUInt32BE(e + 4);
    if (off + 8 > blob.length) continue;
    const magic = blob.readUInt32BE(off);
    const len = blob.readUInt32BE(off + 4);
    if (type === 0 && magic === 0xfade0c02 && off + 40 <= blob.length) {
      const flags = blob.readUInt32BE(off + 12);
      sig.adhoc = Boolean(flags & 0x2);
      sig.hardenedRuntime = Boolean(flags & 0x10000);
      sig.identifier = cstring(blob, off + blob.readUInt32BE(off + 20), 256);
      sig.platformBinary = blob[off + 38] !== 0; // Apple-signed OS component
    } else if (type === 0x10000 && magic === 0xfade0b01) {
      sig.cms = len > 8;
    } else if (type === 5 && magic === 0xfade7171) {
      sig.entitlements = parseEntitlementsXml(
        blob.toString("utf8", off + 8, Math.min(blob.length, off + len)),
      );
    }
  }
  return sig;
}

// Imported symbol names from the chained-fixups import table (macOS 12+ binaries).
function chainedImports(src, dataoff, datasize, u32) {
  const blob = src.read(dataoff, Math.min(datasize, 64 * 1024 * 1024));
  if (blob.length < 28) return [];
  const importsOffset = u32(blob, 8);
  const symbolsOffset = u32(blob, 12);
  const count = Math.min(u32(blob, 16), 1_000_000);
  const format = u32(blob, 20);
  const stride = { 1: 4, 2: 8, 3: 16 }[format];
  if (!stride || u32(blob, 24) !== 0) return []; // compressed symbol names unsupported
  const names = [];
  for (let i = 0; i < count; i++) {
    const o = importsOffset + i * stride;
    if (o + stride > blob.length) break;
    const nameOff = format === 3 ? u32(blob, o + 4) : u32(blob, o) >>> 9;
    const name = cstring(blob, symbolsOffset + nameOff);
    if (name) names.push(name);
  }
  return names;
}

// Undefined external symbols from LC_SYMTAB (+ LC_DYSYMTAB range when present).
function symtabImports(src, symtab, dysymtab, is64, le) {
  if (!symtab) return [];
  const entSize = is64 ? 16 : 12;
  let first = 0;
  let count = symtab.nsyms;
  if (dysymtab && dysymtab.nundefsym > 0) {
    first = dysymtab.iundefsym;
    count = dysymtab.nundefsym;
  }
  count = Math.min(count, 2_000_000);
  const syms = src.read(symtab.symoff + first * entSize, count * entSize);
  const strs = src.read(symtab.stroff, Math.min(symtab.strsize, 64 * 1024 * 1024));
  const names = [];
  for (let i = 0; i + entSize <= syms.length; i += entSize) {
    const strx = le ? syms.readUInt32LE(i) : syms.readUInt32BE(i);
    const type = syms[i + 4];
    const isExt = type & 0x01;
    const isUndef = (type & 0x0e) === 0 && (type & 0xe0) === 0; // N_UNDF, not a debug stab
    if (isExt && isUndef) {
      const name = cstring(strs, strx);
      if (name) names.push(name);
    }
  }
  return names;
}

// Mach-O C symbols carry one leading underscore: `_strcpy` → `strcpy`.
export const demangleMachO = (s) => (s.startsWith("_") ? s.slice(1) : s);

export function parseMachO(src) {
  const head = src.read(0, 32);
  if (head.length < 28) throw new Error("truncated Mach-O header");
  const magic = head.readUInt32LE(0);
  const le = magic === 0xfeedface || magic === 0xfeedfacf;
  const is64 = magic === 0xfeedfacf || magic === 0xcffaedfe;
  if (!le && magic !== 0xcefaedfe && magic !== 0xcffaedfe) throw new Error("not a Mach-O file");
  const u32 = (b, o) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
  const u64 = (b, o) => Number(le ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o));

  const cputype = u32(head, 4);
  const cpusubtype = u32(head, 8);
  const filetype = u32(head, 12);
  const ncmds = u32(head, 16);
  const sizeofcmds = Math.min(u32(head, 20), 16 * 1024 * 1024);
  const flags = u32(head, 24);
  const cmds = src.read(is64 ? 32 : 28, sizeofcmds);

  const info = {
    format: "macho",
    arch: cpuName(cputype, cpusubtype),
    bits: is64 ? 64 : 32,
    endian: le ? "little" : "big",
    filetype: FILETYPES[filetype] ?? `type-${filetype}`,
    isExecutable: filetype === MH_EXECUTE,
    pie: Boolean(flags & MH_PIE),
    stackExecutable: Boolean(flags & MH_ALLOW_STACK_EXECUTION),
    noHeapExecution: Boolean(flags & MH_NO_HEAP_EXECUTION),
    libraries: [],
    rpaths: [],
    segments: [],
    codeSignature: null,
    encrypted: false,
    platform: null,
    minOS: null,
    hasMain: false,
    imports: [],
  };

  let symtab = null;
  let dysymtab = null;
  let chained = null;
  let off = 0;
  for (let i = 0; i < ncmds && off + 8 <= cmds.length; i++) {
    const cmd = u32(cmds, off);
    const size = u32(cmds, off + 4);
    if (size < 8 || off + size > cmds.length) break;
    const c = cmds.subarray(off, off + size);

    if (DYLIB_CMDS.has(cmd) && size >= 12) {
      info.libraries.push(cstring(c, u32(c, 8)));
    } else if (cmd === LC.RPATH && size >= 12) {
      info.rpaths.push(cstring(c, u32(c, 8)));
    } else if (cmd === LC.SYMTAB && size >= 24) {
      symtab = { symoff: u32(c, 8), nsyms: u32(c, 12), stroff: u32(c, 16), strsize: u32(c, 20) };
    } else if (cmd === LC.DYSYMTAB && size >= 32) {
      dysymtab = { iundefsym: u32(c, 24), nundefsym: u32(c, 28) };
    } else if (cmd === LC.CODE_SIGNATURE && size >= 16) {
      info.codeSignature = parseCodeSignature(src, u32(c, 8), u32(c, 12));
    } else if ((cmd === LC.ENCRYPTION_INFO || cmd === LC.ENCRYPTION_INFO_64) && size >= 20) {
      info.encrypted = u32(c, 16) !== 0;
    } else if (cmd === LC.DYLD_CHAINED_FIXUPS && size >= 16) {
      chained = { dataoff: u32(c, 8), datasize: u32(c, 12) };
    } else if (cmd === LC.BUILD_VERSION && size >= 16) {
      info.platform = PLATFORMS[u32(c, 8)] ?? `platform-${u32(c, 8)}`;
      const v = u32(c, 12);
      info.minOS = `${v >>> 16}.${(v >> 8) & 0xff}`;
    } else if (cmd === LC.MAIN) {
      info.hasMain = true;
    } else if (cmd === LC.SEGMENT_64 && size >= 72) {
      info.segments.push({
        name: cstring(c, 8, 16),
        vmsize: u64(c, 32),
        maxprot: u32(c, 56),
        initprot: u32(c, 60),
      });
    } else if (cmd === LC.SEGMENT && size >= 56) {
      info.segments.push({
        name: cstring(c, 8, 16),
        vmsize: u32(c, 28),
        maxprot: u32(c, 40),
        initprot: u32(c, 44),
      });
    }
    off += size;
  }

  const raw = new Set(symtabImports(src, symtab, dysymtab, is64, le));
  if (chained) for (const n of chainedImports(src, chained.dataoff, chained.datasize, u32)) raw.add(n);
  info.imports = [...raw].map(demangleMachO).sort();
  // VM_PROT_WRITE = 2, VM_PROT_EXECUTE = 4
  info.wxSegments = info.segments.filter((s) => (s.initprot & 6) === 6).map((s) => s.name);
  return info;
}

// Parse every slice of a fat binary.
export function parseFatSlices(src) {
  const { archs } = parseFat(src);
  return archs.map((a) => {
    try {
      return { ...parseMachO(new SliceSource(src, a.offset, a.size)), arch: a.arch };
    } catch (err) {
      return { format: "macho", arch: a.arch, error: err.message };
    }
  });
}
