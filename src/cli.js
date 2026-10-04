#!/usr/bin/env node
// rampart — grade a website's HTTP security headers, cookies and TLS config.

import { runChecks } from "./checks.js";
import { scanTarget } from "./fetch.js";
import { renderJson, renderText, summarize, useColor } from "./report.js";

const USAGE = `\
rampart — grade a website's HTTP security posture

USAGE:
  rampart <URL...> [OPTIONS]

ARGUMENTS:
  URL                 one or more targets (https:// assumed if no scheme)

OPTIONS:
  -f, --format <text|json>   output format (default: text)
  -t, --timeout <MS>         request timeout (default: 10000)
      --no-http-probe        skip the extra http:// redirect check
      --max-redirects <N>    redirects to follow (default: 5)
      --fail-under <GRADE>   exit 1 if any target scores below this grade (A..F)
      --no-color             disable colours
  -h, --help                 show this help
  -V, --version              print version

EXAMPLES:
  rampart example.com
  rampart https://example.com -f json
  rampart a.com b.com --fail-under B      # for CI

Scans are plain GET requests to the URL you give — point it at sites you own
or are authorized to assess.
`;

const GRADE_ORDER = ["F", "E", "D", "C", "B", "A", "A+"];

function parseArgs(argv) {
  const args = {
    urls: [], format: "text", timeout: 10000, noHttpProbe: false,
    maxRedirects: 5, failUnder: null, color: undefined,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    switch (a) {
      case "-f": case "--format": args.format = next(); break;
      case "-t": case "--timeout": args.timeout = parseInt(next(), 10); break;
      case "--no-http-probe": args.noHttpProbe = true; break;
      case "--max-redirects": args.maxRedirects = parseInt(next(), 10); break;
      case "--fail-under": args.failUnder = next().toUpperCase(); break;
      case "--no-color": args.color = false; break;
      case "-h": case "--help": process.stdout.write(USAGE); process.exit(0); break;
      case "-V": case "--version": process.stdout.write("rampart 0.1.0\n"); process.exit(0); break;
      default:
        if (a.startsWith("-")) throw new Error(`unknown option '${a}'`);
        args.urls.push(a);
    }
  }
  if (args.urls.length === 0) throw new Error("no URL given (try `rampart --help`)");
  if (!["text", "json"].includes(args.format)) throw new Error(`unknown format '${args.format}'`);
  if (args.failUnder && !GRADE_ORDER.includes(args.failUnder) && args.failUnder !== "A+") {
    throw new Error(`--fail-under must be one of A+, A, B, C, D, E, F`);
  }
  return args;
}

function gradeBelow(grade, threshold) {
  const norm = (g) => GRADE_ORDER.indexOf(g === "A+" ? "A+" : g);
  return norm(grade) < norm(threshold);
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`rampart: ${e.message}\n`);
    process.exit(2);
  }

  const color = args.color === undefined ? useColor(process.stdout) : args.color;
  const results = [];
  let gradeFailed = false;
  let scanErrored = false;

  for (const url of args.urls) {
    try {
      const target = await scanTarget(url, {
        timeout: args.timeout,
        maxRedirects: args.maxRedirects,
        noHttpProbe: args.noHttpProbe,
      });
      target.findings = runChecks(target);
      results.push(target);
      if (args.failUnder) {
        const { grade } = summarize(target.findings);
        if (gradeBelow(grade, args.failUnder)) gradeFailed = true;
      }
    } catch (e) {
      if (args.format === "json") {
        results.push({ input: url, error: e.message, findings: [] });
      } else {
        process.stderr.write(`rampart: ${url}: ${e.message}\n`);
      }
      scanErrored = true;
    }
  }

  if (args.format === "json") {
    const out = results.map((r) => (r.error ? r : JSON.parse(renderJson(r))));
    process.stdout.write(JSON.stringify(out.length === 1 ? out[0] : out, null, 2) + "\n");
  } else {
    for (const r of results) {
      if (r.findings && r.findings.length) process.stdout.write(renderText(r, { color }));
    }
  }

  // 2 if a scan failed outright, 1 if a grade is below --fail-under, else 0.
  if (scanErrored) process.exit(2);
  process.exit(gradeFailed ? 1 : 0);
}

main().catch((e) => {
  process.stderr.write(`rampart: ${e.stack || e.message}\n`);
  process.exit(2);
});
