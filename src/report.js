// Render a scan result as colored text or JSON.

import { summarize } from "./grade.js";

const COLORS = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m", cyan: "\x1b[36m",
  gradeA: "\x1b[1;32m", gradeB: "\x1b[1;36m", gradeC: "\x1b[1;33m", gradeF: "\x1b[1;97;41m",
};

function useColor(stream) {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR) return true;
  return Boolean(stream && stream.isTTY);
}

const MARK = {
  pass: ["✓", "green"], warn: ["!", "yellow"], fail: ["✗", "red"], info: ["·", "dim"],
};

function gradeColor(grade) {
  if (grade.startsWith("A")) return "gradeA";
  if (grade === "B") return "gradeB";
  if (grade === "C" || grade === "D") return "gradeC";
  return "gradeF";
}

export function renderText(result, { color = true } = {}) {
  const c = (name, text) => (color && COLORS[name] ? `${COLORS[name]}${text}${COLORS.reset}` : text);
  const sum = summarize(result.findings);
  const lines = [];

  lines.push("");
  lines.push(`${c("bold", "rampart")}  ${result.finalUrl}`);
  if (result.chain && result.chain.length > 1) {
    lines.push(c("dim", `  redirects: ${result.chain.map((h) => h.status).join(" → ")}`));
  }
  if (result.tls && result.tls.protocol) {
    const t = result.tls;
    lines.push(c("dim", `  tls: ${t.protocol}${t.issuer ? `, issued by ${t.issuer}` : ""}`));
  }

  const grade = `  ${sum.grade}  `;
  lines.push("");
  lines.push(`  ${c(gradeColor(sum.grade), grade)}  ${c("bold", `${sum.percent}/100`)}  ` +
    c("dim", `(${sum.counts.pass || 0} pass · ${sum.counts.warn || 0} warn · ${sum.counts.fail || 0} fail)`));
  lines.push("");

  // order: fails, warns, passes, info
  const rank = { fail: 0, warn: 1, pass: 2, info: 3 };
  const sorted = [...result.findings].sort((a, b) => rank[a.status] - rank[b.status] || b.weight - a.weight);
  for (const f of sorted) {
    const [sym, col] = MARK[f.status];
    lines.push(`  ${c(col, sym)} ${c("bold", f.title)}`);
    if (f.detail) lines.push(`      ${c("dim", f.detail)}`);
    if (f.fix && (f.status === "fail" || f.status === "warn")) {
      lines.push(`      ${c("cyan", "→ " + f.fix)}`);
    }
  }
  lines.push("");
  return lines.join("\n");
}

export function renderJson(result) {
  const sum = summarize(result.findings);
  return JSON.stringify({
    tool: "rampart",
    version: "0.1.0",
    target: result.input,
    finalUrl: result.finalUrl,
    grade: sum.grade,
    score: sum.percent,
    counts: sum.counts,
    tls: result.tls,
    redirectChain: result.chain,
    findings: result.findings,
  }, null, 2);
}

export { useColor, summarize };
