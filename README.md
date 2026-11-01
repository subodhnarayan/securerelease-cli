# SecureRelease

**Review security findings and coverage before you ship.**

SecureRelease is a command-line tool that checks a website, an API and a source-code repository for common security problems, then gives you **one clear report** and a **pass/fail exit code** for your CI/CD pipeline.

It is one tool with one report. Under the hood it combines its own built-in **UI scanner** and **API scanner** with well-known open-source engines (Trivy, Gitleaks, Semgrep, OWASP ZAP) and normalizes everything into a single, easy-to-read format.

> **Status:** early release (v0.1). Use it on applications you own or are authorized to test. It is a readiness check, **not** a penetration test or a compliance certification.

---

## Contents

**New users:** start with the [simple user guide](docs/USER_GUIDE.html) or download its [PDF version](docs/USER_GUIDE.pdf). It covers installation, running scans, and reading reports in plain language.

1. [What can it do?](#what-can-it-do)
2. [Try it in 2 minutes (demo)](#try-it-in-2-minutes-demo)
3. [Install](#install)
4. [Quick start](#quick-start) (`.env` file or terminal flags)
5. [Scanning your own application](#scanning-your-own-application)
6. [Authenticated scans](#authenticated-scans)
7. [Understanding the report](#understanding-the-report)
8. [Using it in CI/CD](#using-it-in-cicd)
9. [Command reference](#command-reference)
10. [What each check does](#what-each-check-does)
11. [Safety model](#safety-model)
12. [Troubleshooting](#troubleshooting)
13. [Limitations](#limitations)
14. [Development](#development)

---

## What can it do?

| You want to… | Use | What you get |
| --- | --- | --- |
| Check a **website / web UI** | `securerelease ui-scan` | Security headers, CSP strength, cookies, forms, mixed content, exposed files, secrets in page code, and more |
| Check a **REST API** | `securerelease api-scan` | Coverage from your OpenAPI spec, missing authentication, CORS, error leaks, broken object-level authorization (BOLA/IDOR), fuzzing, rate limiting |
| Check a **code repository** | `securerelease scan --profile repository` | Vulnerable dependencies (Trivy), leaked secrets (Gitleaks), insecure code patterns (Semgrep) |
| Check **everything at once** | `securerelease scan --profile full` | UI + API + repository in one run and one report |
| Run a **deeper web/API scan** | `securerelease scan --profile dast` | Adds OWASP ZAP (needs Docker) |
| **Block a risky release** in CI | any command above | Exit code `0` (ok), `1` (blocking findings), `2` (scan error / missing coverage) |
| **Share results** | `--format html` | One self-contained HTML report you can email or attach to a ticket |

Key ideas:

- **Evidence-first.** Every finding shows the evidence behind it and how to fix it.
- **Honest results.** If a check could not run, it is reported as `NOT_TESTED` — never as a pass.
- **Safe by default.** Scans are read-only and passive. Anything that sends attack-like traffic requires an explicit `--authorized` flag.

---

## Try it in 2 minutes (demo)

No internet and no real target needed. The demo starts two intentionally vulnerable local apps (a UI and an API), scans them together with a sample vulnerable repository, writes an HTML report and opens it.

```bash
git clone <this-repository-url> securerelease-cli
cd securerelease-cli
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
./scripts/demo.sh
```

The report is saved to `reports/demo-report.html`. A non-zero exit code at the end is **expected** — the demo apps are deliberately insecure.

Things worth looking for in the demo report:

- **API:** one user can read another user's data (BOLA/IDOR); a "secured" admin endpoint answers without login; CORS reflects any origin with credentials; a bad ID leaks a stack trace; no rate limiting.
- **UI:** a password form that sends credentials over GET; a hard-coded API key in the page (shown masked); publicly readable `/.env` and source map; reflected input and an open redirect; no CSP.

> If Trivy, Gitleaks or Semgrep are not installed, their sections of the demo report show `NOT_TESTED`; the UI and API sections work regardless.
>
> The demo script uses macOS `open` (or `xdg-open` on Linux) to show the report. If neither exists, open `reports/demo-report.html` yourself.

---

## Install

### Requirements

| Requirement | Needed for | Notes |
| --- | --- | --- |
| Python 3.10+ | everything | `python3 --version` |
| `pip` | install | included with Python |
| [Trivy](https://trivy.dev/) | repository scans | optional |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | repository scans | optional |
| [Semgrep](https://semgrep.dev/docs/) | repository scans | optional |
| Docker | `dast` profile (OWASP ZAP) | optional |
| Playwright + Chromium | browser-rendered UI scans | optional |

The UI scanner, API scanner and website baseline work **without** any optional tool. A missing optional engine is reported as `NOT_TESTED` (and, by default, makes the command exit with code `2`), so a gap can never look like a clean result.

### Install from source

```bash
git clone <this-repository-url> securerelease-cli
cd securerelease-cli

python3 -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e .
```

### Optional extras

```bash
# Read YAML OpenAPI specs (JSON specs work without this)
python -m pip install -e ".[api]"

# Browser engine for JavaScript-heavy single-page apps
python -m pip install -e ".[ui]"
playwright install chromium

# Everything for development and tests
python -m pip install -e ".[dev]"
```

### Verify the installation

```bash
securerelease --version
securerelease doctor
```

`doctor` lists which optional engines are available on your machine:

```text
[AVAILABLE   ] trivy: Version: 0.76.1
[AVAILABLE   ] gitleaks: gitleaks version 8.30.1
[AVAILABLE   ] semgrep: 1.183.0
[AVAILABLE   ] zap: docker image present: ghcr.io/zaproxy/zaproxy:stable
[NOT INSTALLED] playwright: not installed
```

---

## Quick start

> Only scan systems you own or have **written permission** to test.

You can configure a scan in two ways. Both give the same results.

### Option A — a `.env` file (easiest: set it once, run with one command)

```bash
cp .env.example .env        # or: securerelease init   (asks you questions and writes .env for you)
```

Open `.env` and fill in your endpoints and, if needed, test credentials:

```bash
SECURERELEASE_UI_URL=https://staging.example.com
SECURERELEASE_API_URL=https://api.staging.example.com
SECURERELEASE_OPENAPI_SPEC=./openapi.json
SECURERELEASE_API_TOKEN=<token for test user A>
SECURERELEASE_API_TOKEN_B=<token for test user B>      # optional, for BOLA/IDOR checks
```

Then run:

```bash
securerelease run
```

`run` picks what to scan from what you configured (UI only, API only, repository only, or everything together), prints a short summary (secrets are never printed), and writes an HTML report to `reports/securerelease-report.html`. Every setting is documented inside [`.env.example`](.env.example). `.env` is git-ignored — never commit it.

| Command | What it does |
| --- | --- |
| `securerelease init` | Asks a few questions (secrets are typed hidden) and writes `.env` with owner-only permissions |
| `securerelease run` | Reads `./.env` and scans |
| `securerelease run --env-file staging.env` | Uses a different settings file |
| `securerelease run --profile ui` | Scans only the UI even if an API is configured |

### Option B — flags in the terminal

Flags always override the `.env` file, and a real environment variable overrides the file as well (order: **flag > environment variable > `.env` file**). You can mix both, for example `securerelease run --format json --no-fail-on-findings`. The `scan`, `ui-scan` and `api-scan` commands only read a settings file when you pass `--env-file`.

**Scan a website:**

```bash
securerelease ui-scan --url https://your-staging.example \
  --format html --output reports/ui.html
```

**Scan an API:**

```bash
securerelease api-scan --api-url https://api.your-staging.example \
  --openapi-spec ./openapi.json \
  --format html --output reports/api.html
```

**Scan a repository:**

```bash
securerelease scan --profile repository --source . \
  --format html --output reports/repo.html
```

**Scan everything together:**

```bash
securerelease scan --profile full \
  --url https://your-staging.example \
  --api-url https://api.your-staging.example --openapi-spec ./openapi.json \
  --source . \
  --format html --output reports/full.html
```

Add `--no-fail-on-findings` if you only want a report and don't want findings to produce a failing exit code.

### Scanning an app running on your own machine

Local and private addresses (and non-standard ports) are blocked by default so the tool can't be pointed at internal systems by accident. For an app you control, opt in explicitly (`--allow-private-targets`, or `SECURERELEASE_ALLOW_PRIVATE_TARGETS=true` in `.env`):

```bash
securerelease ui-scan --url http://localhost:3000 --allow-private-targets
```

Never use `--allow-private-targets` on untrusted URL lists or untrusted pull-request input. Likewise, only run `securerelease run` in a folder whose `.env` you trust.

---

## Scanning your own application

### Two safety tiers

| Tier | Flag | What it sends | Use on |
| --- | --- | --- | --- |
| **Passive** (default) | none | Only `GET` and `OPTIONS`, same site only, request-budgeted | Staging or production-like sites you're allowed to scan |
| **Active** | `--authorized` | Unauthorized-access replays, bounded fuzzing, a burst of 30 requests, reflected-input and open-redirect probes | **Only** systems you own, ideally staging or a local copy |

Writes are even more restricted: `POST`/`PUT`/`PATCH` are skipped unless you add `--allow-mutating` (disposable test data only). **`DELETE` is never sent.**

### API scanning tips

- **Give it your OpenAPI/Swagger spec** with `--openapi-spec` (file path or URL). Without it, the scanner tries `/openapi.json`, `/swagger.json` and `/v3/api-docs`; if none exist, only the base URL is probed and the report says so.
- **Check the coverage finding first.** `API-COVERAGE` tells you how many documented operations were actually probed, and why others were skipped.
- The request budget is `--max-requests` (default `300`).

### UI scanning tips

- The default engine is a lightweight same-site crawler (`--max-pages`, default `25`). It skips logout/delete-style links.
- For single-page apps that render in JavaScript, use the browser engine: `--ui-engine browser` (needs the `[ui]` extra). `--ui-engine auto` (the default) uses Playwright when installed and the crawler otherwise.
- **Check the coverage finding first.** `UI-COVERAGE` shows how many pages were analyzed.

---

## Authenticated scans

Credentials are read **only from environment variables**. You pass the *name* of the variable, never the secret itself, so nothing sensitive appears in your shell history, process list or report. Use **test accounts on staging**, never real users.

### Authenticated API

```bash
export API_TOKEN_A='<token for test user A>'
export API_TOKEN_B='<token for test user B>'    # optional: enables BOLA/IDOR testing

securerelease api-scan \
  --api-url https://api.your-staging.example \
  --openapi-spec ./openapi.json \
  --api-token-env API_TOKEN_A \
  --api-token-b-env API_TOKEN_B \
  --authorized \
  --format html --output reports/api-auth.html
```

| Input | What it enables |
| --- | --- |
| `--api-token-env` | Every operation is also sent *with* your credentials; checks for secured endpoints that answer without credentials |
| `--api-token-b-env` + `--authorized` | **BOLA/IDOR test:** replays object IDs between user A and user B |
| `--api-auth-header-env` | Custom header auth, for example `API_KEY='X-API-Key: abc123'` |

A bare token is sent as `Authorization: Bearer <token>`. Include the scheme yourself for other types, for example `Basic dXNlcjpwYXNz`.

### Authenticated UI

Pick one of three ways:

```bash
# 1. Scripted login (the first form that has a password field)
export APP_USER='tester@example.com'
export APP_PASSWORD='********'
securerelease ui-scan --url https://staging.example \
  --ui-login-url https://staging.example/login \
  --ui-user-env APP_USER --ui-pass-env APP_PASSWORD

# 2. A Playwright storage-state file (saved logged-in session)
securerelease ui-scan --url https://staging.example --ui-storage-state auth.json

# 3. A header or cookie
export APP_COOKIE='Cookie: session=abc123'
securerelease ui-scan --url https://staging.example --ui-auth-header-env APP_COOKIE
```

---

## Understanding the report

### Formats

| `--format` | Best for |
| --- | --- |
| `text` (default) | Reading in the terminal |
| `html` | Sharing with people: one self-contained file, no external resources |
| `markdown` | Pasting into tickets or pull requests |
| `json` | Dashboards and automation |
| `sarif` | GitHub code scanning and other security tooling |

Use `--output <file>` to write to a file instead of the terminal.

### The HTML report

- A **verdict banner**: *Action needed* (a high-impact finding exists), *Incomplete coverage* (checks could not run), or *No blocking findings in the checks that ran*.
- Counts by status and severity.
- Findings **grouped by scanner**, worst first, each expandable to show evidence and remediation.
- Status filter buttons and a search box.
- Notes, tool versions and a limitations statement.

All scanned content is HTML-escaped, so a hostile page cannot inject markup into your report.

### Finding statuses

| Status | Meaning |
| --- | --- |
| `PASS` | The defined check passed. This applies only to that specific check. |
| `WARN` | A concern that needs review. |
| `FAIL` | The check observed a condition that meets its failure criteria. |
| `NOT_TESTED` | The check did not run or had too little evidence. **Not a pass.** |
| `ERROR` | A scanner failed to run or its output could not be read. |

Severities are `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` and `INFO`.

---

## Using it in CI/CD

SecureRelease returns an exit code your pipeline can act on:

| Exit code | Meaning |
| --- | --- |
| `0` | No finding met the blocking threshold and nothing failed to run |
| `1` | At least one `WARN`/`FAIL` finding matched `--fail-on` (default: `critical,high`) |
| `2` | A scan error, a requested engine is missing, or a target was rejected or unreachable |

```bash
# Block the build on high-impact findings
securerelease scan --profile full --url "$STAGING_URL" --api-url "$STAGING_API" \
  --openapi-spec openapi.json --source . --format json --output securerelease.json

# Report only (never fail on findings; scan errors still return 2)
securerelease ui-scan --url "$STAGING_URL" --no-fail-on-findings --format html --output ui.html

# Stricter gate
securerelease api-scan --api-url "$STAGING_API" --fail-on critical,high,medium

# Upload to GitHub code scanning
securerelease scan --profile repository --source . --format sarif --output results.sarif
```

Store tokens in your CI system's secret store and expose them as environment variables for the job.

---

## Command reference

```text
securerelease run       Scan using .env (or flags); the profile is inferred from the configured targets
securerelease init      Interactive setup that creates .env
securerelease scan      Run checks with any profile
securerelease ui-scan   Shortcut for: scan --profile ui
securerelease api-scan  Shortcut for: scan --profile api
securerelease doctor    Show which optional engines are available (--json for machines)
securerelease --version
```

### Settings file keys

| `.env` key | Same as flag |
| --- | --- |
| `SECURERELEASE_UI_URL` / `_API_URL` / `_SOURCE` / `_OPENAPI_SPEC` | `--url` / `--api-url` / `--source` / `--openapi-spec` |
| `SECURERELEASE_API_TOKEN` / `_API_TOKEN_B` / `_API_AUTH_HEADER` | `--api-token-env` / `--api-token-b-env` / `--api-auth-header-env` (values are read from the file, never printed) |
| `SECURERELEASE_UI_LOGIN_URL` / `_UI_USERNAME` / `_UI_PASSWORD` | `--ui-login-url` / `--ui-user-env` / `--ui-pass-env` |
| `SECURERELEASE_UI_AUTH_HEADER` / `_UI_STORAGE_STATE` | `--ui-auth-header-env` / `--ui-storage-state` |
| `SECURERELEASE_AUTHORIZED` / `_ALLOW_PRIVATE_TARGETS` / `_ALLOW_MUTATING` | `--authorized` / `--allow-private-targets` / `--allow-mutating` |
| `SECURERELEASE_UI_ENGINE` / `_MAX_PAGES` / `_MAX_REQUESTS` / `_PROFILE` | `--ui-engine` / `--max-pages` / `--max-requests` / `--profile` |
| `SECURERELEASE_FORMAT` / `_OUTPUT` / `_FAIL_ON` / `_NO_FAIL_ON_FINDINGS` | `--format` / `--output` / `--fail-on` / `--no-fail-on-findings` |

### Profiles

| Profile | Runs |
| --- | --- |
| `baseline` | Light website/API HTTP observations (headers, cookies, CORS, HTTPS) |
| `ui` | UI scanner (needs `--url`) |
| `api` | API scanner (needs `--api-url`) |
| `repository` | Trivy + Gitleaks + Semgrep (`--source`, defaults to `.`) |
| `full` | Baseline + UI + API + repository, for whichever of `--url`, `--api-url` and `--source` you provide (at least one) |
| `dast` | Baseline + OWASP ZAP via Docker (`--zap-mode baseline\|active`, `--zap-minutes`) |

### Common options

| Option | Purpose |
| --- | --- |
| `--url` / `--api-url` / `--source` | The website, API base URL, and repository folder to scan |
| `--openapi-spec` | OpenAPI/Swagger file or URL |
| `--api-token-env`, `--api-token-b-env`, `--api-auth-header-env` | API credentials (environment variable **names**) |
| `--ui-engine` | `auto` (default), `crawler`, or `browser` |
| `--ui-login-url`, `--ui-user-env`, `--ui-pass-env` | Scripted UI login |
| `--ui-storage-state`, `--ui-auth-header-env` | Other UI authentication methods |
| `--max-pages` | UI pages to visit (default `25`) |
| `--max-requests` | Request budget per target (default `300`) |
| `--authorized` | Enable active tests — only for systems you own |
| `--allow-mutating` | Let the API scanner send POST/PUT/PATCH |
| `--allow-private-targets` | Allow localhost / private networks |
| `--format`, `--output` | Report format and destination |
| `--fail-on`, `--no-fail-on-findings` | CI blocking rules |

Run `securerelease scan --help` for the complete list.

---

## What each check does

Every check collects evidence from real requests, applies a rule, and records the result together with the evidence.

### UI scanner

| Area | How it decides |
| --- | --- |
| Security headers | Looks for CSP, HSTS (HTTPS only), `nosniff`, Referrer-Policy and frame protection on every page |
| CSP strength | Flags `unsafe-inline` without nonce/hash, `unsafe-eval`, wildcards and missing `object-src` |
| Cookies | Missing `Secure`, `HttpOnly` or `SameSite` (cookie values are never recorded) |
| Mixed content | `http://` scripts, styles or frames on HTTPS pages (fail); images (warn) |
| Forms | Password sent over HTTP or GET (fail); POST forms with no CSRF-style token (warn) |
| Third-party scripts | External scripts/styles without a Subresource Integrity `integrity` attribute |
| Secrets in page code | Patterns for cloud keys, tokens, private keys and `api_key = "…"` — shown **masked** |
| Exposed files | `/.env`, `/.git/HEAD`, actuator, `phpinfo` and similar, confirmed by **content signature** (avoids single-page-app false positives) |
| Source maps | Public `.map` files that reveal source code |
| Storage / comments / redirects | Token-like web-storage keys (browser engine), sensitive HTML comments, redirect-style URL parameters |
| *Active (`--authorized`)* | Reflected-input and open-redirect probes using GET on discovered parameters |

### API scanner

| Area | How it decides |
| --- | --- |
| Coverage | Operations in the spec vs. operations actually probed, with skip reasons |
| Unauthenticated access | Operations the spec marks as secured must reject anonymous calls (`401`/`403`) |
| CORS | A fake `Origin` is sent; reflecting it together with credentials is a failure |
| Error disclosure | Stack traces, debug pages and server errors on valid requests |
| Methods | `Allow` header compared with the spec; `TRACE` is flagged |
| *BOLA/IDOR (`--authorized`, two tokens)* | Object IDs are replayed between users; another user's object returned unchanged is a failure |
| *Fuzzing (`--authorized`)* | Eight payload types in path/query parameters, compared with a normal-request baseline |
| *Rate limit (`--authorized`)* | A burst of 30 requests; looks for `429` or rate-limit headers |

### Repository scanning

Trivy (dependencies and configuration), Gitleaks (secrets in the working tree) and Semgrep (insecure code patterns, `--config auto` may need network access).

---

## Safety model

- **Same-site only.** The UI and API scanners never request another origin.
- **Target policy.** Private/local addresses and non-standard ports are blocked unless you opt in with `--allow-private-targets`.
- **Request budget** and **capped response sizes** on every target.
- **No automatic redirects** — redirects are observed, not followed.
- **No writes by default**; `DELETE` is never sent.
- **Secrets stay secret.** Credentials come from environment variables, are redacted from stored responses, and are masked in reports.
- **Active tests are opt-in** with `--authorized`.
- Certificate verification is **never disabled**.

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `CERTIFICATE_VERIFY_FAILED … self-signed certificate in certificate chain` | A corporate proxy re-signs HTTPS traffic. Point to a CA bundle that includes it:<br>`security find-certificate -a -p /Library/Keychains/System.keychain /System/Library/Keychains/SystemRootCertificates.keychain > ~/ca-bundle.pem`<br>`export SECURERELEASE_CA_BUNDLE=~/ca-bundle.pem` (`SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` also work) |
| `HTTP-CONNECTIVITY … ReadTimeout` | The target didn't answer from your network. The report shows the first error; confirm with `curl -i <url>`. |
| `TARGET-POLICY` / "did not satisfy the safety policy" | The target is local/private or uses a non-standard port. Add `--allow-private-targets` (or `SECURERELEASE_ALLOW_PRIVATE_TARGETS=true`) if you own it. |
| `No target is configured` when running `securerelease run` | `.env` is missing or has no `SECURERELEASE_UI_URL`, `SECURERELEASE_API_URL` or `SECURERELEASE_SOURCE`. Run `securerelease init` or copy `.env.example` to `.env`. Run the command from the folder that contains `.env`, or pass `--env-file`. |
| `TOOL-…-MISSING` and exit code `2` | A requested engine isn't installed. Install it (see `securerelease doctor`) or choose a profile that doesn't need it. |
| `API-SPEC-LOAD` error | The spec file/URL couldn't be read. Check the path, or install `[api]` to read YAML specs. |
| Very few pages or operations scanned | Read the `UI-COVERAGE` / `API-COVERAGE` finding; raise `--max-pages` / `--max-requests`, give an OpenAPI spec, or use `--ui-engine browser`. |
| Authenticated scan shows all secured operations rejected | The token is expired or belongs to a different environment. |

---

## Limitations

- It is a **readiness check**, not a penetration test, compliance certification or proof that an application is secure. A clean report means only that the listed checks found nothing.
- Checks are heuristics; **verify findings manually** (for example `curl -i https://site/.env`).
- Coverage is limited to what was crawled or documented. Single-page apps need the browser engine.
- Not yet covered: multi-step logins and MFA, role-matrix authorization testing, Git-history secret scanning, cloud inventory, AI/LLM-specific tests, and a web dashboard.
- It is a local CLI, not a hardened multi-tenant scanning service. Run optional engines in a sandbox in CI and don't point the tool at untrusted repositories in privileged environments.
- Scanner output can contain sensitive metadata; review reports before sharing them widely.

Planned next: role-based authorization tests, CI templates for GitHub Actions / GitLab CI / Jenkins, a coverage matrix, and a dashboard that reuses the same core. See [docs/ARCHITECTURE_AND_ROADMAP.md](docs/ARCHITECTURE_AND_ROADMAP.md).

---

## Development

GitHub Actions runs tests on Python 3.10-3.13 and builds source and wheel distributions. The workflow also checks that the HTML report template is included in the installed package.

### Uploading this project to GitHub

Create an empty GitHub repository (without an initial README or license), then run from this project folder:

```bash
# If Git is not initialized yet:
git init -b main

# Set your own commit identity if it is not configured:
git config user.name "Your Name"
git config user.email "your-github-email@example.com"

git add .
git status
git commit -m "Prepare SecureRelease 0.1 demo" \
  -m "Co-authored-by: subodhnarayansah@gmail.com"
git remote add origin https://github.com/subodhnarayan/securerelease-cli.git
git push -u origin main
```

Replace the repository URL in these instructions and the installation examples with your actual GitHub URL. Review staged files before committing: do not upload credentials, authenticated session files or real scan reports. Local environments, generated reports and common credential files are git-ignored.

The intentionally vulnerable fixtures include **fake test credentials and insecure code**, solely for repeatable demonstrations. GitHub scanners may flag them; verify that alerts refer to the documented fixtures rather than dismissing alerts elsewhere. Never deploy these fixtures.

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

Project layout:

```text
src/securerelease/
  cli.py               command-line interface and exit-code policy
  orchestrator.py      profiles and scan orchestration
  models.py            common Finding / ScanReport model
  reports.py           text, Markdown, JSON, HTML and SARIF output
  templates/report.html  HTML report template (edit to change branding)
  auth.py              environment-based credentials and redaction
  config.py            flag > environment > .env resolution for `run`
  envfile.py           small .env parser
  wizard.py            `securerelease init` interactive setup
  scanners/
    safe_http.py       guarded HTTP client shared by the UI and API scanners
    api_scanner.py     OpenAPI-driven API scanner
    openapi.py         OpenAPI 3.x / Swagger 2.0 reader
    ui_scanner.py      UI scanner orchestration and probes
    ui_crawler.py      same-site crawler
    ui_browser.py      optional Playwright engine
    ui_checks.py       UI analyzers
    http_baseline.py   website baseline and target validation
    trivy.py gitleaks.py semgrep.py zap.py   external engine adapters
tests/                 unit and live-server tests, plus intentionally vulnerable fixtures
scripts/demo.sh        one-command demo
```

The fixtures under `tests/fixtures/` are **intentionally vulnerable. Never deploy them.**

## License

MIT — see [LICENSE](LICENSE).
