#!/usr/bin/env python3
"""webscan - a passive HTTP security header scanner.

Only scan sites you own or have written permission to test.
The tool sends one GET request per URL (plus one HTTP request for the
HTTPS-redirect check). It never sends payloads or crawls.
"""
import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

VERSION = "0.1.1"
UA = f"webscan/{VERSION} (passive header check)"
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PENALTY = {"info": 0, "low": 3, "medium": 8, "high": 15, "critical": 25}


def finding(rule, header, result, severity, observed, explanation, fix=""):
    return {
        "rule": rule,
        "header": header,
        "result": result,  # PASS, WARN, FAIL, INFO
        "severity": severity if result != "PASS" else "info",
        "observed": observed,
        "explanation": explanation,
        "fix": fix,
    }


def parse_csp(value):
    directives = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = bits[1:]
    return directives


# ---------------------------------------------------------------- rules
def check_hsts(ctx):
    v = ctx["headers"].get("strict-transport-security")
    if not ctx["final_url"].startswith("https://"):
        return finding("H01", "Strict-Transport-Security", "INFO", "info", None,
                       "Final response was not HTTPS, so HSTS does not apply.")
    if not v:
        return finding("H01", "Strict-Transport-Security", "FAIL", "high", None,
                       "Browsers are not told to always use HTTPS.",
                       "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    m = re.search(r"max-age=(\d+)", v, re.I)
    if not m or int(m.group(1)) < 15552000:
        return finding("H01", "Strict-Transport-Security", "WARN", "medium", v,
                       "max-age is missing or shorter than 180 days.",
                       "Use max-age=31536000 or higher.")
    return finding("H01", "Strict-Transport-Security", "PASS", "info", v, "HSTS is set with a long max-age.")


def check_csp(ctx):
    v = ctx["headers"].get("content-security-policy")
    if not v:
        return finding("H02", "Content-Security-Policy", "FAIL", "high", None,
                       "No CSP, so injected scripts are not restricted.",
                       "Add a policy such as: Content-Security-Policy: default-src 'self'")
    d = parse_csp(v)
    if "script-src" in d:
        script = d["script-src"]
    elif "default-src" in d:
        script = d["default-src"]
    else:
        return finding("H02", "Content-Security-Policy", "WARN", "medium", v,
                       "The policy has neither script-src nor default-src, so scripts are not restricted.",
                       "Add default-src 'self' (or a script-src directive).")
    # An empty source list means 'none' per the CSP spec, which is restrictive.
    bad = [s for s in script if s in ("'unsafe-inline'", "'unsafe-eval'", "*", "https:", "http:", "data:")]
    if bad:
        return finding("H02", "Content-Security-Policy", "WARN", "medium", v,
                       f"Script sources allow {', '.join(bad)}, which weakens the policy.",
                       "Remove unsafe-inline/unsafe-eval; use nonces or hashes.")
    return finding("H02", "Content-Security-Policy", "PASS", "info", v, "CSP is set without obvious weaknesses.")


def check_framing(ctx):
    xfo = ctx["headers"].get("x-frame-options", "")
    csp = ctx["headers"].get("content-security-policy", "")
    d = parse_csp(csp)
    if "frame-ancestors" in d:
        # CSP frame-ancestors takes precedence over X-Frame-Options in browsers.
        ancestors = d["frame-ancestors"]
        wide = [a for a in ancestors if a in ("*", "https:", "http:", "data:")]
        if wide:
            return finding("H03", "X-Frame-Options", "FAIL", "medium", "frame-ancestors " + " ".join(ancestors),
                           f"frame-ancestors allows {', '.join(wide)}, so any site can frame this page.",
                           "Use frame-ancestors 'none' or 'self'.")
        return finding("H03", "X-Frame-Options", "PASS", "info", "frame-ancestors " + " ".join(ancestors),
                       "Clickjacking protection is set via CSP frame-ancestors.")
    if xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        return finding("H03", "X-Frame-Options", "PASS", "info", xfo,
                       "Clickjacking protection is set.")
    return finding("H03", "X-Frame-Options", "FAIL", "medium", xfo or None,
                   "The page can be embedded in other sites (clickjacking risk).",
                   "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none')")


def check_nosniff(ctx):
    v = ctx["headers"].get("x-content-type-options", "")
    if v.strip().lower() == "nosniff":
        return finding("H04", "X-Content-Type-Options", "PASS", "info", v, "MIME sniffing is disabled.")
    return finding("H04", "X-Content-Type-Options", "FAIL", "medium", v or None,
                   "Browsers may guess content types and run unexpected content.",
                   "Add: X-Content-Type-Options: nosniff")


def check_referrer(ctx):
    v = ctx["headers"].get("referrer-policy")
    if not v:
        return finding("H05", "Referrer-Policy", "FAIL", "low", None,
                       "Full URLs may leak to other sites in the Referer header.",
                       "Add: Referrer-Policy: strict-origin-when-cross-origin")
    if v.strip().lower() == "unsafe-url":
        return finding("H05", "Referrer-Policy", "WARN", "low", v,
                       "unsafe-url sends full URLs everywhere.", "Use strict-origin-when-cross-origin.")
    return finding("H05", "Referrer-Policy", "PASS", "info", v, "Referrer policy is set.")


def check_permissions(ctx):
    v = ctx["headers"].get("permissions-policy")
    if v:
        return finding("H06", "Permissions-Policy", "PASS", "info", v, "Browser feature policy is set.")
    return finding("H06", "Permissions-Policy", "FAIL", "low", None,
                   "Powerful browser features are not explicitly restricted.",
                   "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()")


def check_cors(ctx):
    h = ctx["headers"]
    acao = h.get("access-control-allow-origin")
    creds = h.get("access-control-allow-credentials", "").lower() == "true"
    if acao == "*" and creds:
        return finding("H07", "Access-Control-Allow-Origin", "FAIL", "high", acao,
                       "Wildcard origin combined with credentials is a dangerous CORS setup.",
                       "Return a specific trusted origin instead of *.")
    if acao == "*":
        return finding("H07", "Access-Control-Allow-Origin", "INFO", "info", acao,
                       "Any origin can read this response. Fine for public data only.")
    return finding("H07", "Access-Control-Allow-Origin", "PASS", "info", acao,
                   "No permissive CORS policy detected.")


def check_coop(ctx):
    v = ctx["headers"].get("cross-origin-opener-policy")
    if v:
        return finding("H08", "Cross-Origin-Opener-Policy", "PASS", "info", v, "COOP is set.")
    return finding("H08", "Cross-Origin-Opener-Policy", "FAIL", "low", None,
                   "Cross-window isolation is not enabled.", "Add: Cross-Origin-Opener-Policy: same-origin")


def check_corp(ctx):
    v = ctx["headers"].get("cross-origin-resource-policy")
    if v:
        return finding("H09", "Cross-Origin-Resource-Policy", "PASS", "info", v, "CORP is set.")
    return finding("H09", "Cross-Origin-Resource-Policy", "FAIL", "low", None,
                   "Other sites may embed this site's resources.", "Add: Cross-Origin-Resource-Policy: same-origin")


def check_disclosure(ctx):
    h = ctx["headers"]
    server, powered = h.get("server", ""), h.get("x-powered-by", "")
    if powered or re.search(r"\d+\.\d+", server):
        obs = "; ".join(x for x in (f"Server: {server}" if server else "",
                                    f"X-Powered-By: {powered}" if powered else "") if x)
        return finding("H10", "Server / X-Powered-By", "WARN", "low", obs,
                       "Technology or version details help attackers pick known exploits.",
                       "Remove X-Powered-By and hide version numbers in Server.")
    return finding("H10", "Server / X-Powered-By", "PASS", "info", server or None,
                   "No version details disclosed.")


def check_cookies(ctx):
    cookies = ctx["cookies"]
    if not cookies:
        return finding("H11", "Set-Cookie", "PASS", "info", None, "No cookies set on this response.")
    problems = []
    for c in cookies:
        low = c.lower()
        name = c.split("=", 1)[0]
        missing = [a for a, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                   if k not in low]
        if missing:
            problems.append(f"{name} missing {', '.join(missing)}")
    if problems:
        return finding("H11", "Set-Cookie", "FAIL", "medium", "; ".join(problems),
                       "Cookies without these attributes are easier to steal or misuse.",
                       "Set Secure; HttpOnly; SameSite=Lax (or Strict) on cookies.")
    return finding("H11", "Set-Cookie", "PASS", "info", f"{len(cookies)} cookie(s)", "Cookie attributes look good.")


def check_https_redirect(ctx):
    r = ctx.get("http_redirect")
    if r is None:
        if ctx.get("http_error") == "TooManyRedirects":
            return finding("H12", "HTTPS redirect", "FAIL", "high", None,
                           "Plain HTTP requests get stuck in a redirect loop instead of reaching HTTPS.",
                           "Fix the port-80 redirect so it goes straight to the HTTPS URL (301).")
        return finding("H12", "HTTPS redirect", "INFO", "info", ctx.get("http_error"),
                       "Could not test the HTTP to HTTPS redirect (port 80 may simply be closed).")
    if r.startswith("https://"):
        return finding("H12", "HTTPS redirect", "PASS", "info", r, "HTTP requests are redirected to HTTPS.")
    return finding("H12", "HTTPS redirect", "FAIL", "high", r,
                   "The site answers over plain HTTP without redirecting.",
                   "Redirect all HTTP traffic to HTTPS (301).")


def check_xss(ctx):
    v = ctx["headers"].get("x-xss-protection")
    if v and v.strip() != "0":
        return finding("H13", "X-XSS-Protection", "INFO", "info", v,
                       "The legacy XSS filter is deprecated and can cause issues.", "Remove it or set it to 0.")
    return finding("H13", "X-XSS-Protection", "PASS", "info", v, "Legacy XSS filter is not enabled.")


RULES = [check_hsts, check_csp, check_framing, check_nosniff, check_referrer, check_permissions,
         check_cors, check_coop, check_corp, check_disclosure, check_cookies, check_https_redirect, check_xss]


# -------------------------------------------------------------- scanning
def normalize(url):
    url = url.strip()
    return url if "://" in url else "https://" + url


def grade(findings):
    score = 100 - sum(PENALTY[f["severity"]] for f in findings if f["result"] in ("FAIL", "WARN"))
    for letter, floor in (("A", 90), ("B", 80), ("C", 70), ("D", 60)):
        if score >= floor:
            return letter
    return "F"


def scan(url, opts):
    out = {"url": url, "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    # One Session per scan on purpose: requests.Session is not documented as
    # thread-safe, and a shared cookie jar would leak cookies between targets.
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.max_redirects = 5
    try:
        r = s.get(url, timeout=opts.timeout, verify=not opts.insecure, allow_redirects=True)
        ctx = {
            "headers": {k.lower(): v for k, v in r.headers.items()},
            "cookies": r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else [],
            "final_url": r.url,
        }
        if urlparse(url).scheme == "https":
            host = urlparse(url).netloc
            try:
                ctx["http_redirect"] = s.get("http://" + host, timeout=opts.timeout, verify=not opts.insecure,
                                             allow_redirects=True).url
            except requests.RequestException as e:
                ctx["http_redirect"] = None
                ctx["http_error"] = type(e).__name__
        else:
            ctx["http_redirect"] = r.url
        findings = [rule(ctx) for rule in RULES]
        ignored = set(opts.ignore)
        findings = [f for f in findings if f["rule"] not in ignored]
        out.update(status=r.status_code, final_url=r.url,
                   redirects=[h.url for h in r.history], grade=grade(findings), findings=findings)
    except (requests.RequestException, ValueError, UnicodeError) as e:
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        s.close()
    return out


# ------------------------------------------------------------- reporting
def render_table(results):
    lines = []
    for r in results:
        lines.append(f"\n{r['url']}")
        if "error" in r:
            lines.append(f"  ERROR: {r['error']}")
            continue
        lines.append(f"  Status {r['status']}  Final URL {r['final_url']}  Grade {r['grade']}")
        for f in r["findings"]:
            lines.append(f"  [{f['result']:<4}] {f['rule']} {f['header']:<30} {f['severity']:<7} {f['explanation']}")
            if f["fix"] and f["result"] in ("FAIL", "WARN"):
                lines.append(f"         fix: {f['fix']}")
    lines.append("\nNote: this checks response headers only. It is not a full security assessment.")
    return "\n".join(lines)


def render_markdown(results):
    lines = ["# Header scan report", ""]
    for r in results:
        lines.append(f"## {r['url']}")
        if "error" in r:
            lines += [f"Error: `{r['error']}`", ""]
            continue
        lines += [f"Status {r['status']} · Grade **{r['grade']}** · Final URL {r['final_url']}", "",
                  "| Result | Rule | Header | Severity | Finding | Fix |", "| --- | --- | --- | --- | --- | --- |"]
        for f in r["findings"]:
            lines.append(f"| {f['result']} | {f['rule']} | {f['header']} | {f['severity']} | "
                         f"{f['explanation']} | {f['fix']} |")
        lines.append("")
    lines.append("_This checks response headers only. It is not a full security assessment._")
    return "\n".join(lines)


def load_targets(args):
    targets = list(args.urls)
    if args.input:
        try:
            with open(args.input, encoding="utf-8") as fh:
                targets += [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
        except (OSError, UnicodeDecodeError) as e:
            print(f"webscan: cannot read --input file '{args.input}': {e}", file=sys.stderr)
            sys.exit(2)
    return [normalize(t) for t in targets]


def main(argv=None):
    p = argparse.ArgumentParser(description="Passive HTTP security header scanner. Scan only sites you are authorised to test.")
    p.add_argument("urls", nargs="*", help="URL(s) to scan")
    p.add_argument("-i", "--input", help="file with one URL per line")
    p.add_argument("-f", "--format", choices=["table", "json", "markdown"], default="table")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--workers", type=int, default=5)
    p.add_argument("--fail-on", choices=list(SEV), default="high",
                   help="exit 1 if a FAIL/WARN finding has at least this severity (default: high)")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE_ID", help="skip a rule, e.g. H06")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    args = p.parse_args(argv)

    targets = load_targets(args)
    if not targets:
        p.error("give at least one URL or --input file")

    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 20))) as ex:
        results = list(ex.map(lambda u: scan(u, args), targets))

    report = {"table": render_table, "markdown": render_markdown,
              "json": lambda r: json.dumps(r, indent=2)}[args.format](results)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report + "\n")
    else:
        print(report)

    threshold = SEV[args.fail_on]
    hit = any(f["result"] in ("FAIL", "WARN") and SEV[f["severity"]] >= threshold
              for r in results for f in r.get("findings", []))
    if hit:
        return 1
    return 2 if any("error" in r for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
