// PE (Windows) parser — header mitigations (ASLR, NX/DEP, CFG), Authenticode
// presence, and imported functions from the import directory.

import { cstring } from "./source.js";

const MACHINES = { 0x14c: "x86", 0x8664: "x86_64", 0xaa64: "arm64", 0x1c0: "arm" };
const DLL = { HIGH_ENTROPY_VA: 0x20, DYNAMIC_BASE: 0x40, NX_COMPAT: 0x100, GUARD_CF: 0x4000 };

export function parsePe(src) {
  const dos = src.read(0, 64);
  if (dos.length < 64 || dos.readUInt16LE(0) !== 0x5a4d) throw new Error("not a PE file");
  const peOff = dos.readUInt32LE(0x3c);
  const nt = src.read(peOff, 24 + 240);
  if (nt.length < 24 || nt.readUInt32LE(0) !== 0x00004550) throw new Error("missing PE signature");

  const machine = nt.readUInt16LE(4);
  const nsects = Math.min(nt.readUInt16LE(6), 96);
  const optSize = nt.readUInt16LE(20);
  const characteristics = nt.readUInt16LE(22);
  const opt = src.read(peOff + 24, optSize);
  const is64 = opt.length >= 2 && opt.readUInt16LE(0) === 0x20b;
  const dllChars = opt.length >= 72 ? opt.readUInt16LE(70) : 0;
  const dirBase = is64 ? 112 : 96;
  const dir = (i) =>
    opt.length >= dirBase + (i + 1) * 8
      ? { rva: opt.readUInt32LE(dirBase + i * 8), size: opt.readUInt32LE(dirBase + i * 8 + 4) }
      : { rva: 0, size: 0 };

  const sects = [];
  const st = src.read(peOff + 24 + optSize, nsects * 40);
  for (let i = 0; i + 40 <= st.length && i < nsects * 40; i += 40) {
    sects.push({
      name: cstring(st, i, 8),
      vsize: st.readUInt32LE(i + 8),
      va: st.readUInt32LE(i + 12),
      rawSize: st.readUInt32LE(i + 16),
      rawPtr: st.readUInt32LE(i + 20),
      chars: st.readUInt32LE(i + 36),
    });
  }
  const rvaToOff = (rva) => {
    const s = sects.find((x) => rva >= x.va && rva < x.va + Math.max(x.vsize, x.rawSize));
    return s ? s.rawPtr + (rva - s.va) : null;
  };
  const readStr = (rva) => {
    const off = rvaToOff(rva);
    return off === null ? "" : cstring(src.read(off, 512), 0);
  };

  const libraries = [];
  const imports = new Set();
  const imp = dir(1);
  if (imp.rva) {
    let off = rvaToOff(imp.rva);
    for (let n = 0; off !== null && n < 4096; n++, off += 20) {
      const d = src.read(off, 20);
      if (d.length < 20) break;
      const thunkRva = d.readUInt32LE(0) || d.readUInt32LE(16);
      const nameRva = d.readUInt32LE(12);
      if (!thunkRva && !nameRva) break;
      libraries.push(readStr(nameRva));
      let toff = rvaToOff(thunkRva);
      const step = is64 ? 8 : 4;
      for (let k = 0; toff !== null && k < 65536; k++, toff += step) {
        const t = src.read(toff, step);
        if (t.length < step) break;
        const v = is64 ? t.readBigUInt64LE(0) : BigInt(t.readUInt32LE(0));
        if (v === 0n) break;
        const ordinal = is64 ? v >> 63n : v >> 31n;
        if (ordinal) continue;
        const name = readStr(Number(v & 0x7fffffffn) + 2);
        if (name) imports.add(name);
      }
    }
  }

  const sec = dir(4); // certificate table (file offset, not RVA)
  return {
    format: "pe",
    arch: MACHINES[machine] ?? `machine-0x${machine.toString(16)}`,
    bits: is64 ? 64 : 32,
    filetype: characteristics & 0x2000 ? "dll" : "executable",
    isExecutable: !(characteristics & 0x2000),
    aslr: Boolean(dllChars & DLL.DYNAMIC_BASE),
    highEntropyVa: Boolean(dllChars & DLL.HIGH_ENTROPY_VA),
    nx: Boolean(dllChars & DLL.NX_COMPAT),
    cfg: Boolean(dllChars & DLL.GUARD_CF),
    signed: sec.rva !== 0 && sec.size > 0,
    libraries,
    imports: [...imports].sort(),
    // IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE
    wxSegments: sects.filter((s) => (s.chars & 0xa0000000) === 0xa0000000).map((s) => s.name),
  };
}
