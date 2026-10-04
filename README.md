<p align="center">
  <img src="assets/logo.svg" alt="rampart" width="440">
</p>

<p align="center">
  <b>Grade your web security headers &amp; TLS — and fix what's wrong.</b><br>
  Point it at a URL and get a letter grade, a prioritized list of problems, and the
  exact header to add for each one. Zero dependencies — just Node.
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-it-checks">What it checks</a> ·
  <a href="#ci">CI</a> ·
  <a href="#how-grading-works">Grading</a>
</p>

---

Half of web hardening is a handful of HTTP response headers — HSTS, a real
Content-Security-Policy, `nosniff`, frame protection, sane cookie flags — plus a
TLS config that isn't quietly about to expire. They're easy to get right and
easy to forget. **Rampart tells you where you stand and what to change**, in one
command.

```
rampart  https://example.com/
  tls: TLSv1.3, issued by Sectigo Limited

    B    82/100  (9 pass · 2 warn · 1 fail)

  ✗ Cookie flags
      Weak cookies: session (missing HttpOnly).
      → Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.
  ! Content Security Policy
      CSP present but weakened by 'unsafe-inline'.
      → Remove 'unsafe-inline'/'unsafe-eval' (use nonces or hashes), avoid '*'.
  ✓ HTTP Strict Transport Security
      max-age 31536000, includeSubDomains, preload.
  ✓ Certificate expiry
      Valid for 56 more day(s).
```

Every failing or warning check comes with a concrete fix — not just "add a CSP",
but the directive to start from.

## Why rampart

* **No install footprint.** Pure Node standard library (`http`, `https`, `tls`) —
  **zero npm dependencies**. Clone and run, or `npx` it in CI.
* **Actionable, not just a score.** Each finding names the problem *and* the
  remediation. The report is sorted worst-first so you fix what matters.
* **Checks TLS too, not only headers.** Protocol version, certificate trust, and
  **days until the certificate expires** — the silent outage waiting to happen.
* **Honest grading.** A site is scored only on the checks that apply to it, so
  the grade reflects real posture, not boilerplate.
* **CI-ready.** `--fail-under B` turns a passing grade into a build gate.

## Install

Needs Node 18+.

```bash
git clone https://github.com/resulcetin09/rampart
cd rampart
npm link        # puts `rampart` on your PATH (no deps to install)
```

Or run without installing:

```bash
node src/cli.js example.com
# or, once published:  npx rampart-scan example.com
```

## Quick start

```bash
rampart example.com                 # grade one site
rampart a.com b.com c.com           # several at once
rampart https://example.com -f json # machine-readable
rampart example.com --fail-under B  # exit 1 if below a B (for CI)
```

## What it checks

| Check | What a good result looks like | Weight |
|---|---|---|
| **HTTP → HTTPS redirect** | plain HTTP 301s to HTTPS | 12 |
| **TLS protocol version** | TLS 1.2 or 1.3 (not 1.0/1.1) | 12 |
| **Certificate trust** | chain validates, hostname matches | 12 |
| **Certificate expiry** | comfortably in the future (warns < 30 days) | 10 |
| **HSTS** | `max-age ≥ 180d; includeSubDomains` | 15 |
| **Content-Security-Policy** | present, `default-src`, no `unsafe-inline/eval`, no `*` | 20 |
| **Clickjacking protection** | CSP `frame-ancestors` or `X-Frame-Options` | 10 |
| **Cookie flags** | `Secure` + `HttpOnly` + `SameSite` on every cookie | 10 |
| **X-Content-Type-Options** | `nosniff` | 8 |
| **Referrer-Policy** | `strict-origin-when-cross-origin` or stricter | 6 |
| **Permissions-Policy** | present | 4 |
| **Version disclosure** | no `Server`/`X-Powered-By` version strings | 5 |

Checks that don't apply (e.g. HSTS on a plain-HTTP target) are reported as
**info** and excluded from the score.

## CI

Fail a pipeline when a site's posture slips:

```yaml
# .github/workflows/headers.yml
name: security-headers
on: [push, schedule]
jobs:
  rampart:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: node src/cli.js https://your-site.example --fail-under B
```

Exit codes: `0` all good, `1` a grade fell below `--fail-under`, `2` a scan
failed (DNS/connection error).

## How grading works

Each check has a weight. A **pass** earns the full weight, a **warn** earns
half, a **fail** earns none; **info** checks don't count. The score is the
percentage of *achievable* weight earned, then mapped to a letter:

```
A+ ≥ 97   A ≥ 90   B ≥ 80   C ≥ 70   D ≥ 60   E ≥ 40   F < 40
```

Because only applicable checks are counted, two different sites are judged on a
fair, like-for-like basis.

## How it works

```
 URL ─▶ fetch (follow redirects) ─▶ response headers + Set-Cookie + socket TLS ─▶ checks ─▶ grade ─▶ report
        + a probe of http:// to                                     (pure, testable      (weighted)   text/json
          see if it redirects                                        functions)
```

1. Rampart GETs the URL, following redirects, and records the header chain. It
   also probes `http://` separately to see whether plain HTTP redirects to HTTPS.
2. TLS details (protocol, trust, expiry) are read off the connection socket.
   Certificates are **inspected, not rejected** — an invalid cert becomes a
   finding, not a crash.
3. A set of **pure check functions** turn the normalized response into findings.
   These are what the test suite exercises, with no network needed.
4. Findings are scored and rendered.

## Development

```bash
node --test        # 11 tests, no network, no dependencies
```

The checks and grading are pure functions, so the whole suite runs offline.

## Scope & honesty

Rampart inspects the **response headers, cookies, and TLS** of the URL you give
it — it is a configuration grader, not a vulnerability scanner or a crawler. It
looks at one page per URL (plus the HTTP redirect probe), doesn't execute
JavaScript, and can't see runtime behavior or server-side issues. A high grade
means the headers are in good shape, not that the app is secure. Scan sites you
own or are authorized to assess.

## License

MIT © Resul Çetin. See [LICENSE](LICENSE).
