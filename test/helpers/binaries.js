// Builders for minimal, well-formed executables so the binary parsers can be
// tested on every platform (CI runs on Linux; macOS adds real system binaries).

const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PT_INTERP = 3;
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;

/**
 * 64-bit little-endian ELF with a dynamic section and .dynsym.
 * @param {object} o
 */
export function buildElf({
  type = 3,
  interp = true,
  stack = "RW", // "RW" | "RWX" | null (no PT_GNU_STACK)
  relro = true,
  bindNow = true,
  pieFlag = true,
  needed = ["libc.so.6"],
  runpath = null,
  imports = ["puts", "__stack_chk_fail"],
  defined = ["main"],
} = {}) {
  // String table: index 0 is "".
  const strs = [""];
  const strOff = new Map();
  let strSize = 1;
  const addStr = (s) => {
    if (!strOff.has(s)) {
      strOff.set(s, strSize);
      strs.push(s);
      strSize += Buffer.byteLength(s) + 1;
    }
    return strOff.get(s);
  };
  for (const n of needed) addStr(n);
  if (runpath) addStr(runpath);
  for (const n of [...imports, ...defined]) addStr(n);
  const dynstr = Buffer.from(`${strs.join("\0")}\0`);

  const phdrs = [{ type: PT_LOAD, flags: 5 }];
  if (interp) phdrs.push({ type: PT_INTERP, flags: 4 });
  phdrs.push({ type: PT_DYNAMIC, flags: 6 });
  if (stack) phdrs.push({ type: PT_GNU_STACK, flags: stack === "RWX" ? 7 : 6 });
  if (relro) phdrs.push({ type: PT_GNU_RELRO, flags: 4 });

  const ehsize = 64;
  const phOff = ehsize;
  const phSize = 56 * phdrs.length;
  const interpStr = Buffer.from("/lib64/ld-linux-x86-64.so.2\0");
  const interpOff = phOff + phSize;
  const dynstrOff = interpOff + interpStr.length;
  const symCount = 1 + imports.length + defined.length;
  const dynsymOff = align(dynstrOff + dynstr.length, 8);
  const dynsymSize = 24 * symCount;

  const dyn = [];
  for (const n of needed) dyn.push([1, strOff.get(n)]);
  if (runpath) dyn.push([29, strOff.get(runpath)]);
  dyn.push([5, dynstrOff]); // DT_STRTAB (vaddr == offset: one PT_LOAD at 0)
  dyn.push([10, dynstr.length]); // DT_STRSZ
  let flags1 = 0;
  if (pieFlag) flags1 |= 0x08000000;
  if (bindNow) {
    dyn.push([24, 0]); // DT_BIND_NOW
    flags1 |= 0x1;
  }
  if (flags1) dyn.push([0x6ffffffb, flags1]);
  dyn.push([0, 0]);
  const dynOff = align(dynsymOff + dynsymSize, 8);
  const dynSize = 16 * dyn.length;
  const shOff = align(dynOff + dynSize, 8);
  const shnum = 3;
  const total = shOff + 64 * shnum;

  const b = Buffer.alloc(total);
  b.writeUInt32BE(0x7f454c46, 0);
  b[4] = 2; // 64-bit
  b[5] = 1; // little-endian
  b[6] = 1;
  b.writeUInt16LE(type, 16);
  b.writeUInt16LE(62, 18); // x86_64
  b.writeUInt32LE(1, 20);
  b.writeBigUInt64LE(BigInt(phOff), 32);
  b.writeBigUInt64LE(BigInt(shOff), 40);
  b.writeUInt16LE(ehsize, 52);
  b.writeUInt16LE(56, 54);
  b.writeUInt16LE(phdrs.length, 56);
  b.writeUInt16LE(64, 58);
  b.writeUInt16LE(shnum, 60);

  phdrs.forEach((p, i) => {
    const o = phOff + i * 56;
    let off = 0;
    let size = 0;
    if (p.type === PT_LOAD) size = total;
    if (p.type === PT_INTERP) [off, size] = [interpOff, interpStr.length];
    if (p.type === PT_DYNAMIC) [off, size] = [dynOff, dynSize];
    b.writeUInt32LE(p.type, o);
    b.writeUInt32LE(p.flags, o + 4);
    b.writeBigUInt64LE(BigInt(off), o + 8);
    b.writeBigUInt64LE(BigInt(off), o + 16);
    b.writeBigUInt64LE(BigInt(off), o + 24);
    b.writeBigUInt64LE(BigInt(size), o + 32);
    b.writeBigUInt64LE(BigInt(size), o + 40);
  });
  interpStr.copy(b, interpOff);
  dynstr.copy(b, dynstrOff);

  [...imports.map((n) => [n, 0]), ...defined.map((n) => [n, 1])].forEach(([n, shndx], i) => {
    const o = dynsymOff + 24 * (i + 1);
    b.writeUInt32LE(strOff.get(n), o);
    b[o + 4] = 0x12; // GLOBAL FUNC
    b.writeUInt16LE(shndx, o + 6);
  });
  dyn.forEach(([tag, val], i) => {
    b.writeBigInt64LE(BigInt(tag), dynOff + 16 * i);
    b.writeBigUInt64LE(BigInt(val), dynOff + 16 * i + 8);
  });

  const sh = (i, typ, off, size, link, entsize) => {
    const o = shOff + 64 * i;
    b.writeUInt32LE(typ, o + 4);
    b.writeBigUInt64LE(BigInt(off), o + 24);
    b.writeBigUInt64LE(BigInt(size), o + 32);
    b.writeUInt32LE(link, o + 40);
    b.writeBigUInt64LE(BigInt(entsize), o + 56);
  };
  sh(1, 3, dynstrOff, dynstr.length, 0, 0); // .dynstr
  sh(2, 11, dynsymOff, dynsymSize, 1, 24); // .dynsym → link .dynstr
  return b;
}

const align = (n, a) => Math.ceil(n / a) * a;

/**
 * Thin 64-bit Mach-O (arm64) with LC_SEGMENT_64 + LC_SYMTAB, and optionally an
 * LC_DYLD_CHAINED_FIXUPS import table (`chained`: [{ name, ordinal }], format 1).
 */
export function buildMachO({
  pie = true,
  stackExec = false,
  wx = false,
  imports = ["_puts"],
  cputype = 0x0100000c,
  chained = null,
} = {}) {
  const strtab = Buffer.from(`\0${imports.join("\0")}\0`);
  const nsyms = imports.length;
  const segSize = 72;
  const symtabCmdSize = 24;
  const chainedCmdSize = chained ? 16 : 0;
  const sizeofcmds = segSize + symtabCmdSize + chainedCmdSize;
  const symoff = align(32 + sizeofcmds, 8);
  const stroff = symoff + 16 * nsyms;
  let fixups = null;
  if (chained) {
    // dyld_chained_fixups_header (28 bytes), then DYLD_CHAINED_IMPORT entries, then names.
    const names = Buffer.from(`\0${chained.map((c) => c.name).join("\0")}\0`);
    const importsOffset = 28;
    const symbolsOffset = importsOffset + 4 * chained.length;
    fixups = Buffer.alloc(symbolsOffset + names.length);
    fixups.writeUInt32LE(importsOffset, 8);
    fixups.writeUInt32LE(symbolsOffset, 12);
    fixups.writeUInt32LE(chained.length, 16);
    fixups.writeUInt32LE(1, 20); // DYLD_CHAINED_IMPORT
    let nameOff = 1;
    chained.forEach((c, i) => {
      fixups.writeUInt32LE(((nameOff << 9) | (c.ordinal & 0xff)) >>> 0, importsOffset + 4 * i);
      nameOff += Buffer.byteLength(c.name) + 1;
    });
    names.copy(fixups, symbolsOffset);
  }
  const fixupsOff = align(stroff + strtab.length, 8);
  const total = fixups ? fixupsOff + fixups.length : stroff + strtab.length;
  const b = Buffer.alloc(total);
  let flags = 0;
  if (pie) flags |= 0x200000;
  if (stackExec) flags |= 0x20000;
  b.writeUInt32LE(0xfeedfacf, 0);
  b.writeUInt32LE(cputype, 4);
  b.writeUInt32LE(0, 8);
  b.writeUInt32LE(2, 12); // MH_EXECUTE
  b.writeUInt32LE(chained ? 3 : 2, 16); // ncmds
  b.writeUInt32LE(sizeofcmds, 20);
  b.writeUInt32LE(flags, 24);
  // LC_SEGMENT_64 "__TEXT"
  let o = 32;
  b.writeUInt32LE(0x19, o);
  b.writeUInt32LE(segSize, o + 4);
  b.write("__TEXT", o + 8, "latin1");
  b.writeUInt32LE(7, o + 56); // maxprot
  b.writeUInt32LE(wx ? 7 : 5, o + 60); // initprot
  // LC_SYMTAB
  o += segSize;
  b.writeUInt32LE(0x2, o);
  b.writeUInt32LE(symtabCmdSize, o + 4);
  b.writeUInt32LE(symoff, o + 8);
  b.writeUInt32LE(nsyms, o + 12);
  b.writeUInt32LE(stroff, o + 16);
  b.writeUInt32LE(strtab.length, o + 20);
  if (fixups) {
    o += symtabCmdSize;
    b.writeUInt32LE(0x80000034, o); // LC_DYLD_CHAINED_FIXUPS
    b.writeUInt32LE(chainedCmdSize, o + 4);
    b.writeUInt32LE(fixupsOff, o + 8);
    b.writeUInt32LE(fixups.length, o + 12);
    fixups.copy(b, fixupsOff);
  }
  let strx = 1;
  imports.forEach((name, i) => {
    const s = symoff + 16 * i;
    b.writeUInt32LE(strx, s);
    b[s + 4] = 0x01; // N_EXT | N_UNDF
    strx += Buffer.byteLength(name) + 1;
  });
  strtab.copy(b, stroff);
  return b;
}

// Universal binary wrapping the given slices: [{ cputype, cpusubtype, data }].
export function buildFat(slices) {
  let offset = 0x1000;
  const placed = slices.map((s) => {
    const p = { ...s, offset };
    offset = align(offset + s.data.length, 0x1000);
    return p;
  });
  const b = Buffer.alloc(offset);
  b.writeUInt32BE(0xcafebabe, 0);
  b.writeUInt32BE(slices.length, 4);
  placed.forEach((s, i) => {
    const o = 8 + 20 * i;
    b.writeUInt32BE(s.cputype, o);
    b.writeUInt32BE(s.cpusubtype ?? 0, o + 4);
    b.writeUInt32BE(s.offset, o + 8);
    b.writeUInt32BE(s.data.length, o + 12);
    b.writeUInt32BE(12, o + 16);
    s.data.copy(b, s.offset);
  });
  return b;
}

/**
 * PE32+ executable with one section and an import of KERNEL32!<imports>.
 */
export function buildPe({ aslr = true, nx = true, cfg = false, imports = ["WinExec"] } = {}) {
  const b = Buffer.alloc(0x400);
  b.writeUInt16LE(0x5a4d, 0);
  b.writeUInt32LE(0x40, 0x3c);
  b.writeUInt32LE(0x00004550, 0x40);
  const coff = 0x44;
  b.writeUInt16LE(0x8664, coff);
  b.writeUInt16LE(1, coff + 2); // sections
  b.writeUInt16LE(240, coff + 16); // optional header size
  b.writeUInt16LE(0x22, coff + 18); // executable, large-address-aware
  const opt = coff + 20;
  b.writeUInt16LE(0x20b, opt);
  let dll = 0;
  if (aslr) dll |= 0x40;
  if (nx) dll |= 0x100;
  if (cfg) dll |= 0x4000;
  b.writeUInt16LE(dll, opt + 70);
  b.writeUInt32LE(16, opt + 108); // NumberOfRvaAndSizes
  b.writeUInt32LE(0x1000, opt + 112 + 8); // import directory RVA
  b.writeUInt32LE(40, opt + 112 + 12);
  const sect = opt + 240;
  b.write(".rdata", sect, "latin1");
  b.writeUInt32LE(0x200, sect + 8); // VirtualSize
  b.writeUInt32LE(0x1000, sect + 12); // VirtualAddress
  b.writeUInt32LE(0x200, sect + 16); // SizeOfRawData
  b.writeUInt32LE(0x200, sect + 20); // PointerToRawData
  b.writeUInt32LE(0x40000040, sect + 36); // initialized data, readable
  const raw = (rva) => 0x200 + (rva - 0x1000);
  // Import descriptor → thunks at 0x1040, DLL name at 0x1080, names from 0x1090.
  b.writeUInt32LE(0x1040, raw(0x1000));
  b.writeUInt32LE(0x1080, raw(0x1000) + 12);
  b.writeUInt32LE(0x1040, raw(0x1000) + 16);
  b.write("KERNEL32.dll\0", raw(0x1080), "latin1");
  let nameRva = 0x1090;
  imports.forEach((name, i) => {
    b.writeBigUInt64LE(BigInt(nameRva), raw(0x1040) + 8 * i);
    b.write(`${name}\0`, raw(nameRva) + 2, "latin1");
    nameRva += 2 + name.length + 1 + 1;
  });
  return b;
}
