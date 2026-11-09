// ELF parser — pure JavaScript. Reads the header, program headers, dynamic
// section, and dynamic symbol table to answer the classic `checksec` questions:
// PIE, NX (PT_GNU_STACK), RELRO / BIND_NOW, RPATH/RUNPATH, stack canary and
// FORTIFY usage (via imported symbols), and which libc functions are imported.

import { cstring } from "./source.js";

const ET = { 1: "relocatable", 2: "executable", 3: "shared-object", 4: "core" };
const MACHINES = {
  3: "x86",
  8: "mips",
  20: "ppc",
  21: "ppc64",
  40: "arm",
  62: "x86_64",
  183: "aarch64",
  243: "riscv",
};

const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PT_INTERP = 3;
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;
const PF_X = 1;
const PF_W = 2;

const DT_NULL = 0;
const DT_NEEDED = 1;
const DT_STRTAB = 5;
const DT_STRSZ = 10;
const DT_RPATH = 15;
const DT_BIND_NOW = 24;
const DT_RUNPATH = 29;
const DT_FLAGS = 30;
const DT_FLAGS_1 = 0x6ffffffb;
const DF_BIND_NOW = 0x8;
const DF_1_NOW = 0x1;
const DF_1_PIE = 0x08000000;

const SHT_DYNSYM = 11;

export function parseElf(src) {
  const id = src.read(0, 64);
  if (id.length < 52 || id.readUInt32BE(0) !== 0x7f454c46) throw new Error("not an ELF file");
  const is64 = id[4] === 2;
  const le = id[5] !== 2;
  const u16 = (b, o) => (le ? b.readUInt16LE(o) : b.readUInt16BE(o));
  const u32 = (b, o) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
  const uw = (b, o) => (is64 ? Number(le ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o)) : u32(b, o));
  const sw = (b, o) => (is64 ? Number(le ? b.readBigInt64LE(o) : b.readBigInt64BE(o)) : u32(b, o) | 0);
  if (is64 && id.length < 64) throw new Error("truncated ELF header");

  const type = u16(id, 16);
  const machine = u16(id, 18);
  const phoff = uw(id, is64 ? 32 : 28);
  const shoff = uw(id, is64 ? 40 : 32);
  const phentsize = u16(id, is64 ? 54 : 42);
  const phnum = Math.min(u16(id, is64 ? 56 : 44), 4096);
  const shentsize = u16(id, is64 ? 58 : 46);
  const shnum = Math.min(u16(id, is64 ? 60 : 48), 65535);

  // Program headers.
  const phdrs = [];
  const ph = src.read(phoff, phnum * phentsize);
  for (let i = 0; i < phnum && (i + 1) * phentsize <= ph.length; i++) {
    const o = i * phentsize;
    phdrs.push(
      is64
        ? {
            type: u32(ph, o),
            flags: u32(ph, o + 4),
            offset: uw(ph, o + 8),
            vaddr: uw(ph, o + 16),
            filesz: uw(ph, o + 32),
          }
        : {
            type: u32(ph, o),
            offset: u32(ph, o + 4),
            vaddr: u32(ph, o + 8),
            filesz: u32(ph, o + 16),
            flags: u32(ph, o + 24),
          },
    );
  }
  const find = (t) => phdrs.find((p) => p.type === t);
  const vaddrToOffset = (va) => {
    const seg = phdrs.find((p) => p.type === PT_LOAD && va >= p.vaddr && va < p.vaddr + p.filesz);
    return seg ? seg.offset + (va - seg.vaddr) : null;
  };

  const info = {
    format: "elf",
    arch: MACHINES[machine] ?? `machine-${machine}`,
    bits: is64 ? 64 : 32,
    endian: le ? "little" : "big",
    filetype: ET[type] ?? `type-${type}`,
    isExecutable: type === 2 || (type === 3 && Boolean(find(PT_INTERP))),
    interpreter: null,
    pie: false,
    nx: null,
    relro: "none",
    bindNow: false,
    libraries: [],
    rpaths: [],
    runpaths: [],
    wxSegments: [],
    imports: [],
    isStatic: false,
  };

  const interp = find(PT_INTERP);
  if (interp) info.interpreter = cstring(src.read(interp.offset, Math.min(interp.filesz, 4096)), 0);

  const stack = find(PT_GNU_STACK);
  info.nx = stack ? !(stack.flags & PF_X) : false; // no PT_GNU_STACK → executable stack on most loaders
  info.nxReason = stack ? "PT_GNU_STACK" : "no PT_GNU_STACK header";
  info.wxSegments = phdrs
    .filter((p) => p.type === PT_LOAD && p.flags & PF_W && p.flags & PF_X)
    .map((p) => `LOAD@0x${p.vaddr.toString(16)}`);

  // Dynamic section.
  const dyn = find(PT_DYNAMIC);
  let flags1 = 0;
  if (dyn) {
    const entSize = is64 ? 16 : 8;
    const d = src.read(dyn.offset, Math.min(dyn.filesz, 1024 * 1024));
    const entries = [];
    for (let o = 0; o + entSize <= d.length; o += entSize) {
      const tag = sw(d, o);
      if (tag === DT_NULL) break;
      entries.push({ tag, val: uw(d, o + (is64 ? 8 : 4)) });
    }
    const get = (t) => entries.find((e) => e.tag === t)?.val;
    const strtabOff = get(DT_STRTAB) !== undefined ? vaddrToOffset(get(DT_STRTAB)) : null;
    const strtab =
      strtabOff !== null ? src.read(strtabOff, Math.min(get(DT_STRSZ) ?? 65536, 16 * 1024 * 1024)) : null;
    const str = (v) => (strtab ? cstring(strtab, v) : "");
    for (const e of entries) {
      if (e.tag === DT_NEEDED) info.libraries.push(str(e.val));
      else if (e.tag === DT_RPATH) info.rpaths.push(str(e.val));
      else if (e.tag === DT_RUNPATH) info.runpaths.push(str(e.val));
    }
    flags1 = get(DT_FLAGS_1) ?? 0;
    info.bindNow =
      entries.some((e) => e.tag === DT_BIND_NOW) ||
      Boolean((get(DT_FLAGS) ?? 0) & DF_BIND_NOW) ||
      Boolean(flags1 & DF_1_NOW);
  } else {
    info.isStatic = type === 2;
  }

  info.pie = type === 3 && (Boolean(flags1 & DF_1_PIE) || Boolean(interp));
  if (find(PT_GNU_RELRO)) info.relro = info.bindNow ? "full" : "partial";

  // Imported (undefined) dynamic symbols via the section headers.
  if (shoff && shnum && shentsize) {
    const sh = src.read(shoff, shnum * shentsize);
    const sect = (i) => {
      const o = i * shentsize;
      if (o + shentsize > sh.length) return null;
      return is64
        ? {
            type: u32(sh, o + 4),
            offset: uw(sh, o + 24),
            size: uw(sh, o + 32),
            link: u32(sh, o + 40),
            entsize: uw(sh, o + 56),
          }
        : {
            type: u32(sh, o + 4),
            offset: u32(sh, o + 16),
            size: u32(sh, o + 20),
            link: u32(sh, o + 24),
            entsize: u32(sh, o + 36),
          };
    };
    for (let i = 0; i < shnum; i++) {
      const s = sect(i);
      if (!s || s.type !== SHT_DYNSYM) continue;
      const strs = sect(s.link);
      if (!strs) continue;
      const names = src.read(strs.offset, Math.min(strs.size, 16 * 1024 * 1024));
      const syms = src.read(s.offset, Math.min(s.size, 64 * 1024 * 1024));
      const ent = s.entsize || (is64 ? 24 : 16);
      const out = new Set();
      for (let o = ent; o + ent <= syms.length; o += ent) {
        const nameOff = u32(syms, o);
        const shndx = is64 ? u16(syms, o + 6) : u16(syms, o + 14);
        if (shndx !== 0) continue; // defined here, not imported
        const name = cstring(names, nameOff).split("@")[0];
        if (name) out.add(name);
      }
      info.imports = [...out].sort();
    }
  }
  return info;
}
