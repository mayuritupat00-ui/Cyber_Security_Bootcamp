# webscan: Automated Web Security Header Scanner

A small command-line tool, written in Python, that checks a website's HTTP security headers and cookie settings. It sends one request to each site, tests the response against 13 rules, explains every problem, suggests a fix, and grades the site from A to F.

> **Use responsibly.** Scan only websites you own or have written permission to test. The tool is passive (it only reads what a site already sends), but terms of service and local laws still apply.

## Features

- 13 checks covering security headers, cookies, and the HTTP-to-HTTPS redirect
- Severity for every finding (info, low, medium, high, critical) and a one-line fix
- Overall grade from A to F per site
- Three report formats: terminal table, JSON, Markdown
- Scan one site or a list of sites, with parallel scanning
- Exit codes that work in CI pipelines
- One failing URL never stops the rest of a batch
- Single dependency: `requests`

## Requirements

- Python 3.10 or newer
- Internet access to the sites you scan

## Installation

1. Put `webscan.py` and `requirements.txt` in a folder, for example `E:\webscan`.
2. Open a terminal in that folder.
3. Install the dependency:

```
pip install -r requirements.txt
```

On macOS or Linux use `python3` and `pip3` if the plain commands are not found. On Windows, `py` works instead of `python` if needed.

## Usage

Scan one site:

```
python webscan.py https://yoursite.com
```

Scan several sites from a file (one URL per line, lines starting with `#` are ignored):

```
python webscan.py -i urls.txt
```

Save a Markdown report:

```
python webscan.py https://yoursite.com -f markdown -o report.md
```

Fail a CI build on medium or worse problems and skip one rule:

```
python webscan.py https://yoursite.com --fail-on medium --ignore H06
```

If you leave out `https://`, the tool adds it.

### Options

| Option | Purpose | Default |
| --- | --- | --- |
| `urls` | One or more URLs to scan | none |
| `-i`, `--input` | File with one URL per line | none |
| `-f`, `--format` | `table`, `json`, or `markdown` | `table` |
| `-o`, `--output` | Write the report to a file | screen |
| `--timeout` | Seconds to wait per request | 10 |
| `--workers` | Number of parallel scans (max 20) | 5 |
| `--fail-on` | Lowest severity that makes the exit code 1 (`info`, `low`, `medium`, `high`, `critical`) | `high` |
| `--ignore` | Skip a rule by ID, can be repeated (for example `--ignore H06`) | none |
| `--insecure` | Do not verify TLS certificates (test servers only) | off |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No FAIL or WARN finding reached the `--fail-on` severity, and no scan errors |
| 1 | At least one FAIL or WARN finding reached the `--fail-on` severity |
| 2 | A scan error occurred (for example a timeout or DNS failure), or the `--input` file could not be read |

## What it checks

| Rule | Check | Fails or warns when | Default severity |
| --- | --- | --- | --- |
| H01 | `Strict-Transport-Security` | Missing, or max-age under 180 days | High / Medium |
| H02 | `Content-Security-Policy` | Missing, no script restrictions, or allows `unsafe-inline`, `unsafe-eval`, `*`, `https:`, `http:`, `data:` for scripts | High / Medium |
| H03 | Clickjacking protection | No `X-Frame-Options` (DENY or SAMEORIGIN) or CSP `frame-ancestors`, or `frame-ancestors` allows `*`, `https:`, `http:`, `data:` | Medium |
| H04 | `X-Content-Type-Options` | Not `nosniff` | Medium |
| H05 | `Referrer-Policy` | Missing or `unsafe-url` | Low |
| H06 | `Permissions-Policy` | Missing | Low |
| H07 | `Access-Control-Allow-Origin` | `*` together with credentials (plain `*` is info) | High |
| H08 | `Cross-Origin-Opener-Policy` | Missing | Low |
| H09 | `Cross-Origin-Resource-Policy` | Missing | Low |
| H10 | `Server` / `X-Powered-By` | Version details disclosed | Low |
| H11 | `Set-Cookie` | A cookie lacks `Secure`, `HttpOnly`, or `SameSite` | Medium |
| H12 | HTTP to HTTPS redirect | Plain HTTP is served without redirecting, or loops | High |
| H13 | `X-XSS-Protection` | Legacy filter enabled (informational) | Info |

A missing CORS header is normal, so H07 flags only dangerous combinations. A closed port 80 is reported as informational, not as a failure.

### Grading

The score starts at 100 and loses points for each FAIL or WARN: low 3, medium 8, high 15, critical 25. A is 90 or more, B 80+, C 70+, D 60+, otherwise F.

## Example output

```
https://example.com
  Status 200  Final URL https://example.com/  Grade F
  [FAIL] H01 Strict-Transport-Security      high    Browsers are not told to always use HTTPS.
         fix: Add: Strict-Transport-Security: max-age=31536000; includeSubDomains
  [PASS] H07 Access-Control-Allow-Origin    info    No permissive CORS policy detected.
  ...
```

JSON findings look like this:

```json
{
  "rule": "H04",
  "header": "X-Content-Type-Options",
  "result": "FAIL",
  "severity": "medium",
  "observed": null,
  "fix": "Add: X-Content-Type-Options: nosniff"
}
```

## How it works

1. Reads URLs from the command line and the optional input file.
2. Sends a GET request with a session, following up to 5 redirects, and records the headers and cookies. For HTTPS sites it also requests the plain-HTTP address to test the redirect.
3. Runs the 13 check functions against the response.
4. Grades the site and prints the report in the chosen format.
5. Returns the exit code.

Each scan uses its own session on purpose. A shared session is not documented as thread-safe, and a shared cookie jar would leak cookies between sites and hide missing cookie flags.

## Limitations

- Checks response headers only. It is not a full security assessment, and a good grade does not mean a site is secure.
- Only the first page response and the final redirect target are examined.
- No rate-limit option or automatic back-off on HTTP 429/503 yet.
- Rules are defined in the code rather than in an editable file.
- No automated test suite yet.

## Possible next steps

- Rules in a YAML or JSON file
- `--max-rate` and back-off on 429 or 503
- Compare two scans and show what changed
- Unit tests and a GitHub Actions workflow
- Certificate expiry and `security.txt` checks

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `python is not recognized` | Use `py webscan.py ...`, or reinstall Python with "Add Python to PATH" ticked |
| pip warns that a `Scripts` folder is not on PATH | Safe to ignore; the tool does not use those helper programs |
| `ConnectionError` or timeout for a site | Check the URL and your connection, or raise `--timeout` |
| SSL certificate error | The site's certificate is invalid or expired. Use `--insecure` only for test servers you control |
| `cannot read --input file` | Check the file path and that it is a plain text file |

## License

Add the license you prefer (for example MIT) before sharing this project publicly.
