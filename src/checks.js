// The security checks themselves — pure functions over a normalized response,
// so they can be unit-tested with no network. Each check returns a Finding.
//
// A Finding is: { id, title, status, weight, detail, fix }
//   status: "pass" | "warn" | "fail" | "info"
//   weight: how much this check contributes to the score (0 for info)

/** @typedef {{id:string,title:string,status:string,weight:number,detail:string,fix:string}} Finding */

export const STATUS = Object.freeze({ PASS: "pass", WARN: "warn", FAIL: "fail", INFO: "info" });

// Header lookups are case-insensitive; callers pass a lowercased-key map.
function get(headers, name) {
  return headers[name.toLowerCase()];
}

function finding(id, title, status, weight, detail, fix) {
  return { id, title, status, weight, detail, fix: fix || "" };
}

/** Parse a Strict-Transport-Security header value into its directives. */
export function parseHsts(value) {
  if (!value) return null;
  const out = { maxAge: null, includeSubDomains: false, preload: false };
  for (const part of value.split(";").map((s) => s.trim().toLowerCase())) {
    if (part.startsWith("max-age=")) {
      const n = parseInt(part.slice(8), 10);
      if (!Number.isNaN(n)) out.maxAge = n;
    } else if (part === "includesubdomains") out.includeSubDomains = true;
    else if (part === "preload") out.preload = true;
  }
  return out;
}

/** Parse one Set-Cookie line into { name, secure, httpOnly, sameSite }. */
export function parseCookie(line) {
  const parts = line.split(";").map((s) => s.trim());
  const name = parts[0].split("=")[0];
  const attrs = parts.slice(1).map((s) => s.toLowerCase());
  let sameSite = null;
  for (const a of attrs) {
    if (a.startsWith("samesite=")) sameSite = a.slice(9);
  }
  return {
    name,
    secure: attrs.includes("secure"),
    httpOnly: attrs.includes("httponly"),
    sameSite,
  };
}

const HSTS_MIN = 15552000; // 180 days, the commonly recommended minimum

function checkHsts(headers, isHttps) {
  const raw = get(headers, "strict-transport-security");
  if (!isHttps) {
    return finding("hsts", "HTTP Strict Transport Security", STATUS.INFO, 0,
      "Target is not HTTPS; HSTS does not apply.", "");
  }
  if (!raw) {
    return finding("hsts", "HTTP Strict Transport Security", STATUS.FAIL, 15,
      "No Strict-Transport-Security header. Browsers may be downgraded to HTTP by an on-path attacker.",
      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains");
  }
  const h = parseHsts(raw);
  if (!h.maxAge || h.maxAge < HSTS_MIN) {
    return finding("hsts", "HTTP Strict Transport Security", STATUS.WARN, 15,
      `max-age is ${h.maxAge ?? "missing"} (recommended ≥ ${HSTS_MIN}).`,
      "Raise max-age to at least 31536000 (1 year) and add includeSubDomains.");
  }
  if (!h.includeSubDomains) {
    return finding("hsts", "HTTP Strict Transport Security", STATUS.WARN, 15,
      `max-age ${h.maxAge} is good, but includeSubDomains is missing.`,
      "Add includeSubDomains so subdomains are protected too.");
  }
  return finding("hsts", "HTTP Strict Transport Security", STATUS.PASS, 15,
    `max-age ${h.maxAge}${h.includeSubDomains ? ", includeSubDomains" : ""}${h.preload ? ", preload" : ""}.`, "");
}

function checkCsp(headers) {
  const raw = get(headers, "content-security-policy");
  if (!raw) {
    return finding("csp", "Content Security Policy", STATUS.FAIL, 20,
      "No Content-Security-Policy header — the strongest defense against XSS and data injection is absent.",
      "Add a Content-Security-Policy starting from default-src 'self' and tighten from there.");
  }
  const lower = raw.toLowerCase();
  const issues = [];
  if (lower.includes("unsafe-inline")) issues.push("'unsafe-inline'");
  if (lower.includes("unsafe-eval")) issues.push("'unsafe-eval'");
  const hasDefault = lower.includes("default-src");
  const allowsWildcard = /(?:default|script)-src[^;]*\*(?![.\w])/.test(lower);
  if (issues.length || allowsWildcard || !hasDefault) {
    const detail = [
      issues.length ? `weakened by ${issues.join(" and ")}` : null,
      allowsWildcard ? "allows a wildcard source" : null,
      !hasDefault ? "no default-src fallback" : null,
    ].filter(Boolean).join("; ");
    return finding("csp", "Content Security Policy", STATUS.WARN, 20,
      `CSP present but ${detail}.`,
      "Remove 'unsafe-inline'/'unsafe-eval' (use nonces or hashes), avoid '*', and set a default-src.");
  }
  return finding("csp", "Content Security Policy", STATUS.PASS, 20,
    "CSP present with default-src and no unsafe-inline/unsafe-eval.", "");
}

function checkContentTypeOptions(headers) {
  const raw = (get(headers, "x-content-type-options") || "").toLowerCase();
  if (raw === "nosniff") {
    return finding("xcto", "X-Content-Type-Options", STATUS.PASS, 8, "nosniff is set.", "");
  }
  return finding("xcto", "X-Content-Type-Options", STATUS.FAIL, 8,
    "Missing — browsers may MIME-sniff responses, enabling some XSS vectors.",
    "Add: X-Content-Type-Options: nosniff");
}

function checkFraming(headers) {
  const xfo = (get(headers, "x-frame-options") || "").toLowerCase();
  const csp = (get(headers, "content-security-policy") || "").toLowerCase();
  const cspFrame = csp.includes("frame-ancestors");
  if (cspFrame || xfo === "deny" || xfo === "sameorigin") {
    const how = cspFrame ? "CSP frame-ancestors" : `X-Frame-Options: ${xfo}`;
    return finding("framing", "Clickjacking protection", STATUS.PASS, 10, `Protected via ${how}.`, "");
  }
  return finding("framing", "Clickjacking protection", STATUS.FAIL, 10,
    "No frame-ancestors in CSP and no X-Frame-Options — the page can be framed for clickjacking.",
    "Add: Content-Security-Policy: frame-ancestors 'none' (or X-Frame-Options: DENY).");
}

function checkReferrerPolicy(headers) {
  const raw = (get(headers, "referrer-policy") || "").toLowerCase();
  const strong = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];
  if (strong.some((v) => raw.includes(v))) {
    return finding("referrer", "Referrer-Policy", STATUS.PASS, 6, `Set to ${raw}.`, "");
  }
  if (raw) {
    return finding("referrer", "Referrer-Policy", STATUS.WARN, 6,
      `Set to "${raw}", which may leak full URLs cross-origin.`,
      "Prefer strict-origin-when-cross-origin or no-referrer.");
  }
  return finding("referrer", "Referrer-Policy", STATUS.WARN, 6,
    "Missing — full URLs may leak to third parties via the Referer header.",
    "Add: Referrer-Policy: strict-origin-when-cross-origin");
}

function checkPermissionsPolicy(headers) {
  const raw = get(headers, "permissions-policy");
  if (raw) {
    return finding("permissions", "Permissions-Policy", STATUS.PASS, 4, "Present.", "");
  }
  return finding("permissions", "Permissions-Policy", STATUS.WARN, 4,
    "Missing — powerful features (camera, geolocation, …) are not restricted at the header level.",
    "Add a Permissions-Policy, e.g. geolocation=(), camera=(), microphone=().");
}

function checkCookies(setCookies) {
  if (!setCookies || setCookies.length === 0) {
    return finding("cookies", "Cookie flags", STATUS.INFO, 0, "No cookies set on this response.", "");
  }
  const bad = [];
  for (const line of setCookies) {
    const c = parseCookie(line);
    const missing = [];
    if (!c.secure) missing.push("Secure");
    if (!c.httpOnly) missing.push("HttpOnly");
    if (!c.sameSite) missing.push("SameSite");
    if (missing.length) bad.push(`${c.name} (missing ${missing.join(", ")})`);
  }
  if (bad.length === 0) {
    return finding("cookies", "Cookie flags", STATUS.PASS, 10,
      `All ${setCookies.length} cookie(s) have Secure, HttpOnly and SameSite.`, "");
  }
  return finding("cookies", "Cookie flags", STATUS.FAIL, 10,
    `Weak cookies: ${bad.join("; ")}.`,
    "Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.");
}

function checkVersionDisclosure(headers) {
  const hints = [];
  const server = get(headers, "server");
  const powered = get(headers, "x-powered-by");
  const hasVersion = (v) => v && /\d+\.\d+/.test(v);
  if (hasVersion(server)) hints.push(`Server: ${server}`);
  if (powered) hints.push(`X-Powered-By: ${powered}`);
  if (hints.length === 0) {
    return finding("disclosure", "Software version disclosure", STATUS.PASS, 5,
      "No obvious software versions advertised.", "");
  }
  return finding("disclosure", "Software version disclosure", STATUS.WARN, 5,
    `Advertises: ${hints.join("; ")} — tells attackers exactly what to target.`,
    "Suppress version strings (e.g. server_tokens off; remove X-Powered-By).");
}

function checkHttpsRedirect(redirectedToHttps, startedHttp) {
  if (!startedHttp) {
    return finding("https-redirect", "HTTP → HTTPS redirect", STATUS.INFO, 0,
      "Target was requested over HTTPS directly.", "");
  }
  if (redirectedToHttps) {
    return finding("https-redirect", "HTTP → HTTPS redirect", STATUS.PASS, 12,
      "Plain HTTP redirects to HTTPS.", "");
  }
  return finding("https-redirect", "HTTP → HTTPS redirect", STATUS.FAIL, 12,
    "Plain HTTP is served without redirecting to HTTPS — traffic can be read on the wire.",
    "Redirect all HTTP traffic to HTTPS with a 301.");
}

// TLS findings come from the socket, not headers.
function checkTls(tls) {
  const out = [];
  if (!tls) return out;

  if (tls.protocol) {
    const old = tls.protocol === "TLSv1" || tls.protocol === "TLSv1.1" || tls.protocol === "SSLv3";
    out.push(finding("tls-version", "TLS protocol version",
      old ? STATUS.FAIL : STATUS.PASS, 12,
      `Negotiated ${tls.protocol}.`,
      old ? "Disable TLS 1.0/1.1; require TLS 1.2 or 1.3." : ""));
  }
  if (typeof tls.daysToExpiry === "number") {
    let status = STATUS.PASS;
    let fix = "";
    if (tls.daysToExpiry < 0) { status = STATUS.FAIL; fix = "Certificate has expired — renew immediately."; }
    else if (tls.daysToExpiry < 15) { status = STATUS.FAIL; fix = "Renew the certificate now; it expires very soon."; }
    else if (tls.daysToExpiry < 30) { status = STATUS.WARN; fix = "Certificate expires soon; schedule renewal."; }
    out.push(finding("tls-expiry", "Certificate expiry", status, 10,
      tls.daysToExpiry < 0
        ? `Expired ${Math.abs(tls.daysToExpiry)} day(s) ago.`
        : `Valid for ${tls.daysToExpiry} more day(s).`,
      fix));
  }
  if (tls.authorized === false) {
    out.push(finding("tls-trust", "Certificate trust", STATUS.FAIL, 12,
      `Certificate did not validate: ${tls.authorizationError || "unknown error"}.`,
      "Install a certificate from a trusted CA that matches the hostname."));
  } else if (tls.authorized === true) {
    out.push(finding("tls-trust", "Certificate trust", STATUS.PASS, 12,
      "Certificate chain validates and matches the hostname.", ""));
  }
  return out;
}

/**
 * Run every check against a normalized target.
 * @param {{
 *   isHttps:boolean, startedHttp:boolean, redirectedToHttps:boolean,
 *   headers:Record<string,string>, setCookies:string[], tls?:object
 * }} target
 * @returns {Finding[]}
 */
export function runChecks(target) {
  const { headers = {}, setCookies = [], tls = null, isHttps = true } = target;
  const findings = [
    checkHttpsRedirect(target.redirectedToHttps, target.startedHttp),
    ...checkTls(tls),
    checkHsts(headers, isHttps),
    checkCsp(headers),
    checkFraming(headers),
    checkContentTypeOptions(headers),
    checkReferrerPolicy(headers),
    checkPermissionsPolicy(headers),
    checkCookies(setCookies),
    checkVersionDisclosure(headers),
  ];
  return findings;
}
