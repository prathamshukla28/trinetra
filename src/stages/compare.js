// Compare stage — diff two teardowns ("what changed between v1 and v2").
//
// Procedures/units: added, removed, and (for native targets, via per-function
// pseudocode hashes) changed. Findings: a per-category count table so you can
// see which weakness classes grew (regressions) or shrank (fixes).

import { canonical } from "./audit.js";

function names(inspection) {
  return new Set(inspection.units.map((u) => u.name));
}

function categorize(findings) {
  const counts = {};
  for (const f of findings) {
    const c = canonical(f);
    counts[c] = (counts[c] || 0) + 1;
  }
  return counts;
}

export function diffTeardowns(a, b) {
  const aNames = names(a.inspection);
  const bNames = names(b.inspection);

  const added = [...bNames].filter((n) => !aNames.has(n)).sort();
  const removed = [...aNames].filter((n) => !bNames.has(n)).sort();
  const common = [...aNames].filter((n) => bNames.has(n));

  // Changed functions — only detectable when both sides carry per-function
  // pseudocode hashes (native targets).
  const ah = a.inspection.fnHashes || {};
  const bh = b.inspection.fnHashes || {};
  const hashable = Boolean(a.inspection.fnHashes && b.inspection.fnHashes);
  const changed = hashable ? common.filter((n) => ah[n] !== bh[n]).sort() : [];

  const aCounts = categorize(a.findings);
  const bCounts = categorize(b.findings);
  const categories = [...new Set([...Object.keys(aCounts), ...Object.keys(bCounts)])].sort();
  const findingRows = categories.map((c) => ({
    category: c,
    a: aCounts[c] || 0,
    b: bCounts[c] || 0,
    delta: (bCounts[c] || 0) - (aCounts[c] || 0),
  }));

  return {
    aName: a.name,
    bName: b.name,
    hashable,
    procedures: { added, removed, changed, unchanged: common.length - changed.length },
    findingRows,
    totals: { a: a.findings.length, b: b.findings.length },
  };
}
