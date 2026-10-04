// Turn findings into a 0–100 score and an A+..F letter grade.
//
// Each check carries a weight. A pass earns full weight, a warn earns half,
// a fail earns none. Info checks don't count. The score is the percentage of
// the achievable weight that was earned — so a site is judged only on the
// checks that actually apply to it.

import { STATUS } from "./checks.js";

export function score(findings) {
  let earned = 0;
  let possible = 0;
  for (const f of findings) {
    if (f.status === STATUS.INFO || f.weight === 0) continue;
    possible += f.weight;
    if (f.status === STATUS.PASS) earned += f.weight;
    else if (f.status === STATUS.WARN) earned += f.weight / 2;
  }
  const pct = possible === 0 ? 100 : Math.round((earned / possible) * 100);
  return { percent: pct, earned, possible };
}

export function letter(percent) {
  if (percent >= 97) return "A+";
  if (percent >= 90) return "A";
  if (percent >= 80) return "B";
  if (percent >= 70) return "C";
  if (percent >= 60) return "D";
  if (percent >= 40) return "E";
  return "F";
}

export function summarize(findings) {
  const counts = { pass: 0, warn: 0, fail: 0, info: 0 };
  for (const f of findings) counts[f.status] = (counts[f.status] || 0) + 1;
  const s = score(findings);
  return { ...s, grade: letter(s.percent), counts };
}
