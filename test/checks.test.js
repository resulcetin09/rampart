import assert from "node:assert/strict";
import { test } from "node:test";

import { parseCookie, parseHsts, runChecks, STATUS } from "../src/checks.js";
import { letter, score, summarize } from "../src/grade.js";

function byId(findings, id) {
  return findings.find((f) => f.id === id);
}

test("parseHsts reads directives", () => {
  const h = parseHsts("max-age=31536000; includeSubDomains; preload");
  assert.equal(h.maxAge, 31536000);
  assert.equal(h.includeSubDomains, true);
  assert.equal(h.preload, true);
  assert.equal(parseHsts(""), null);
});

test("parseCookie reads flags", () => {
  const c = parseCookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax");
  assert.equal(c.name, "sid");
  assert.equal(c.secure, true);
  assert.equal(c.httpOnly, true);
  assert.equal(c.sameSite, "lax");
  const weak = parseCookie("tracking=1; Path=/");
  assert.equal(weak.secure, false);
  assert.equal(weak.sameSite, null);
});

test("a fully hardened site scores A/A+", () => {
  const target = {
    isHttps: true, startedHttp: true, redirectedToHttps: true,
    headers: {
      "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "geolocation=(), camera=()",
    },
    setCookies: ["sid=abc; Secure; HttpOnly; SameSite=Lax"],
    tls: { protocol: "TLSv1.3", authorized: true, daysToExpiry: 200 },
  };
  const findings = runChecks(target);
  const sum = summarize(findings);
  assert.ok(sum.percent >= 95, `expected >=95, got ${sum.percent}`);
  assert.ok(sum.grade.startsWith("A"));
  assert.equal(sum.counts.fail || 0, 0);
});

test("a bare site fails the important checks", () => {
  const target = {
    isHttps: true, startedHttp: true, redirectedToHttps: false,
    headers: {}, setCookies: ["sid=abc"],
    tls: { protocol: "TLSv1.3", authorized: true, daysToExpiry: 200 },
  };
  const findings = runChecks(target);
  assert.equal(byId(findings, "hsts").status, STATUS.FAIL);
  assert.equal(byId(findings, "csp").status, STATUS.FAIL);
  assert.equal(byId(findings, "framing").status, STATUS.FAIL);
  assert.equal(byId(findings, "cookies").status, STATUS.FAIL);
  assert.equal(byId(findings, "https-redirect").status, STATUS.FAIL);
  assert.ok(summarize(findings).percent < 50);
});

test("weak CSP warns rather than fails", () => {
  const findings = runChecks({
    isHttps: true, headers: { "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'" },
    setCookies: [], tls: null,
  });
  assert.equal(byId(findings, "csp").status, STATUS.WARN);
});

test("expired certificate fails", () => {
  const findings = runChecks({
    isHttps: true, headers: {}, setCookies: [],
    tls: { protocol: "TLSv1.2", authorized: true, daysToExpiry: -3 },
  });
  const expiry = byId(findings, "tls-expiry");
  assert.equal(expiry.status, STATUS.FAIL);
  assert.match(expiry.detail, /Expired/);
});

test("old TLS version fails", () => {
  const findings = runChecks({
    isHttps: true, headers: {}, setCookies: [],
    tls: { protocol: "TLSv1", authorized: true, daysToExpiry: 100 },
  });
  assert.equal(byId(findings, "tls-version").status, STATUS.FAIL);
});

test("untrusted cert fails trust check", () => {
  const findings = runChecks({
    isHttps: true, headers: {}, setCookies: [],
    tls: { protocol: "TLSv1.3", authorized: false, authorizationError: "SELF_SIGNED_CERT_IN_CHAIN", daysToExpiry: 100 },
  });
  assert.equal(byId(findings, "tls-trust").status, STATUS.FAIL);
});

test("version disclosure warns", () => {
  const findings = runChecks({
    isHttps: true, headers: { server: "Apache/2.4.49", "x-powered-by": "PHP/8.1.0" },
    setCookies: [], tls: null,
  });
  assert.equal(byId(findings, "disclosure").status, STATUS.WARN);
});

test("score ignores info checks", () => {
  const findings = [
    { id: "a", status: "pass", weight: 10 },
    { id: "b", status: "info", weight: 0 },
    { id: "c", status: "fail", weight: 10 },
  ];
  const s = score(findings);
  assert.equal(s.possible, 20);
  assert.equal(s.earned, 10);
  assert.equal(s.percent, 50);
});

test("letter grade boundaries", () => {
  assert.equal(letter(100), "A+");
  assert.equal(letter(90), "A");
  assert.equal(letter(80), "B");
  assert.equal(letter(70), "C");
  assert.equal(letter(10), "F");
});
