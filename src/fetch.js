// Network layer: fetch a URL over HTTP(S), follow redirects, and pull TLS
// details off the socket. Uses only Node's built-in http/https/tls modules.

import http from "node:http";
import https from "node:https";

const USER_AGENT = "rampart/0.1 (+https://github.com/resulcetin09/rampart)";

function normalizeUrl(input) {
  let url = input.trim();
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  return new URL(url);
}

function lower(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === "set-cookie") continue; // kept separately
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
  }
  return out;
}

/** One request, no redirect following. Resolves with response metadata. */
function requestOnce(url, { timeout = 10000, insecure = false } = {}) {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const mod = isHttps ? https : http;
    const options = {
      method: "GET",
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      headers: { "User-Agent": USER_AGENT, Accept: "*/*", Connection: "close" },
      timeout,
      // We want to SEE invalid certs, not fail on them, so we can report them.
      rejectUnauthorized: false,
      servername: url.hostname,
    };
    const req = mod.request(options, (res) => {
      let tls = null;
      if (isHttps && res.socket) {
        const s = res.socket;
        const cert = s.getPeerCertificate ? s.getPeerCertificate() : null;
        let daysToExpiry = null;
        if (cert && cert.valid_to) {
          const exp = new Date(cert.valid_to).getTime();
          daysToExpiry = Math.floor((exp - Date.now()) / 86400000);
        }
        tls = {
          protocol: s.getProtocol ? s.getProtocol() : null,
          authorized: s.authorized === undefined ? null : s.authorized,
          authorizationError: s.authorizationError ? String(s.authorizationError) : null,
          daysToExpiry,
          subject: cert && cert.subject ? cert.subject.CN : null,
          issuer: cert && cert.issuer ? cert.issuer.O : null,
        };
      }
      // Drain the body so the socket can close; we only need headers.
      res.resume();
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          location: res.headers.location || null,
          headers: lower(res.headers),
          setCookies: res.headers["set-cookie"] || [],
          tls,
          isHttps,
          finalUrl: url,
        });
      });
    });
    req.on("timeout", () => req.destroy(new Error("request timed out")));
    req.on("error", reject);
    req.end();
  });
}

/**
 * Fetch a target, following up to `maxRedirects` redirects.
 * Returns the normalized object `runChecks` expects.
 */
export async function scanTarget(input, opts = {}) {
  const maxRedirects = opts.maxRedirects ?? 5;
  let url = normalizeUrl(input);
  const startedHttp = url.protocol === "http:";
  let redirectedToHttps = false;
  const chain = [];

  let res;
  for (let i = 0; i <= maxRedirects; i++) {
    res = await requestOnce(url, opts);
    chain.push({ url: url.href, status: res.status, location: res.location });
    if (res.status >= 300 && res.status < 400 && res.location) {
      const next = new URL(res.location, url);
      if (url.protocol === "http:" && next.protocol === "https:") redirectedToHttps = true;
      url = next;
      continue;
    }
    break;
  }

  // If the user gave https:// (or a bare host), separately probe http:// to
  // learn whether plain HTTP redirects — otherwise we can't grade that.
  let httpProbe = { startedHttp, redirectedToHttps };
  if (!startedHttp && !opts.noHttpProbe) {
    httpProbe = await probeHttpRedirect(normalizeUrl(input).hostname, opts);
  }

  return {
    input,
    finalUrl: url.href,
    chain,
    status: res.status,
    headers: res.headers,
    setCookies: res.setCookies,
    tls: res.tls,
    isHttps: url.protocol === "https:",
    startedHttp: httpProbe.startedHttp,
    redirectedToHttps: httpProbe.redirectedToHttps,
  };
}

async function probeHttpRedirect(hostname, opts) {
  try {
    const res = await requestOnce(new URL(`http://${hostname}/`), { ...opts, timeout: 6000 });
    let redirectedToHttps = false;
    if (res.status >= 300 && res.status < 400 && res.location) {
      const next = new URL(res.location, `http://${hostname}/`);
      redirectedToHttps = next.protocol === "https:";
    }
    return { startedHttp: true, redirectedToHttps };
  } catch {
    // No HTTP service, or it refused the connection — can't judge the redirect.
    return { startedHttp: false, redirectedToHttps: false };
  }
}

export { normalizeUrl };
