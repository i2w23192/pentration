# allscan

A modular security reconnaissance / scanning tool with an interactive
**terminal UI** (built on [`rich`](https://github.com/Textualize/rich) and
[`textual`](https://github.com/Textualize/textual)) and a scriptable CLI, for
**authorized** security testing.

allscan ties together passive & active subdomain discovery, port/service
scanning, web enumeration, HTML/header/TLS analysis, and informational CVE
correlation — then presents everything as severity-ranked findings you can
browse, export (JSON / Markdown / HTML), and diff against previous runs.

> ⚠️ **Authorized use only.** Scanning systems you do not own or do not have
> explicit written permission to test may be illegal. allscan **refuses to
> run** until authorization is confirmed (an interactive prompt in the TUI, or
> the `--i-have-authorization` flag for automation). It rate-limits all
> activity and writes a full audit log of every outbound action.

---

## Features

| Module | What it does |
| --- | --- |
| **Network/Host Discovery** (`netdiscover`) | ICMP ping sweep across a CIDR (defaults to the /24 of the resolved target), read-only ARP neighbour listing, and traceroute hop listing. Shells out to standard tools and degrades gracefully when ICMP/raw sockets are unavailable. |
| **Subdomain Discovery** (`recon`) | Passive: crt.sh certificate transparency, DNS records (A/AAAA/MX/TXT/NS/CNAME/SOA), reverse PTR. Active: async wordlist brute force, AXFR zone-transfer attempts. Flags wildcard DNS and filters its noise. |
| **DNS Deep-Dive** (`dnsx`) | Full record dump (SOA, NS, CAA, DNSKEY, DS, TXT, SRV service probes), DNSSEC presence/validation check (DNSKEY + AD flag), and informational DNS cache-snooping detection. Flags missing CAA and unsigned zones. |
| **Email Security** (`email`) | SPF, DKIM (common-selector probe) and DMARC presence + basic validity. Flags missing records, permissive SPF (`+all`/`?all`) and monitor-only DMARC (`p=none`). |
| **Port/Service Scan** (`scan`) | Wraps `nmap` (top-1000 by default, full 65535 optional, `-sV` version detection, optional `-O` OS detection). Falls back to a built-in concurrent connect scanner + banner grabber when nmap is unavailable or skipped. Flags sensitive exposed services (Redis, Mongo, Docker API, …). |
| **Web Enumeration** (`web`) | HTTP/HTTPS probing of every discovered host (status, title, tech fingerprint), plus content brute forcing for sensitive paths (`.git/`, `.env`, backups, config files, actuators, admin panels) and directory-listing detection. |
| **API & Tech Fingerprinting** (`fingerprint`) | Probes common API/doc endpoints (`/api`, `/graphql`, swagger/openapi), CMS detection with version (WordPress, Drupal, Joomla, Magento, …), and server-side framework / front-end library fingerprinting. Version-bearing hits feed CVE correlation. |
| **HTML/Header Analysis** (`headers`) | Security-header audit (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), verbose-header and cookie-flag checks, and HTML source analysis (exposed comments, credential-shaped strings, internal paths, outdated JS libraries, risky inline JS). |
| **SSL/TLS Deep Audit** (`tls`) | Protocol support matrix (SSLv3 / TLS 1.0–1.3 accepted?), full certificate-chain validation against the system trust store, and certificate-expiry warnings. Flags deprecated protocols. |
| **Cloud Exposure** (`cloud`) | Detects cloud-storage bucket references (S3, Azure Blob, GCS) in subdomains/HTML and classifies each as publicly listable / private / absent with a single bucket-root request (no object access). Flags cloud metadata-endpoint references (SSRF sinks) — reference only, never probed. |
| **WAF/CDN & Rate-limit Detection** (`waf`) | Fingerprints WAFs/CDNs (Cloudflare, Akamai, CloudFront, Fastly, Sucuri, Imperva, F5, ModSecurity, …) from headers/cookies, and observes rate-limiting (HTTP 429) over a small, bounded request burst. |
| **Active Probing** (`active`) | *Opt-in (`--active`), detection-only.* Sends benign-marker requests to **confirm** weaknesses — reflected input (XSS sink), open redirect, error-based SQL-injection signature, confirmed directory listing — never to exploit. Scope-enforced, rate-limited, concurrency-capped, with a kill switch and auto-stop. Each finding: `{type, location, severity, evidence, confidence, note:"manual validation required"}`. |
| **CVE Correlation** (`vulns`) | Matches detected service/library versions against the **NVD** and **CIRCL CVE Search** APIs (merged + deduped) and lists known CVEs with CVSS severity — *informational listing only, no PoC or exploit code*. Also flags common misconfigs (anonymous FTP, directory listing, sensitive open ports). |
| **Exploit-Reference Enrichment** (`exploitrefs`) | For each correlated CVE, adds decision-useful **references and risk signals**: CISA **KEV** (exploited-in-the-wild) status, **EPSS** score/percentile, and ExploitDB / Metasploit reference links (plus concrete EDB-IDs when pointed at a local ExploitDB `files_exploits.csv`). *References and intelligence only — no exploit code is downloaded, embedded, or run, and no exploitation is performed.* |
| **Compliance Checklist** (`compliance`) | Runs last and rolls up all findings into a pass/fail/warn checklist against common baselines (OWASP Secure Headers, basic TLS hygiene, email auth, DNS hygiene, exposure hygiene). Rendered as a dedicated section in the report. |
| **Reporting** (`report`) | Structured JSON per run, auto-generated Markdown & HTML summaries (severity-tagged, colour-coded, with the compliance checklist), and a diff mode comparing two runs for the same target. |

All modules are **detection-only**: they identify and report issues and never
exploit them — no bucket writes, no auth bypass, no SSRF probing, no access of
discovered credentials or endpoints. The authorization gate applies to every
module.

Every finding carries a category, a severity (`info` / `low` / `medium` /
`high`), a target, a description, and structured evidence.

---

## Install

```bash
# from the project root
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # or: pip install -e .

# optional but recommended for the port scanner:
sudo apt install nmap                     # Debian/Ubuntu
brew install nmap                         # macOS
```

Python 3.9+ is required. If `nmap` is absent, allscan automatically uses its
built-in connect/banner scanner.

---

## Usage

### Interactive TUI

Launch with no target (or with a target to pre-fill the prompt):

```bash
allscan                 # or: python -m allscan
allscan example.com     # pre-fills the target field
```

### Headless / scripting

Mirror every TUI option as a flag. Authorization must be confirmed explicitly:

```bash
# run everything (equivalent to the TUI's Allscan option):
allscan example.com --i-have-authorization --all

allscan example.com --i-have-authorization \
    --modules recon,scan,web,headers,vulns \
    --threads 20 --rate-limit 10 \
    --output-dir ./results

# a fast web-only pass, skipping nmap:
allscan 203.0.113.10 --i-have-authorization --modules web,headers --skip-nmap

# full port range + OS detection (needs root for -O):
sudo allscan example.com --i-have-authorization --full-ports --os-detection

# full chain minus a couple of modules, with a PDF report:
allscan example.com --i-have-authorization --all --skip-active --skip web --pdf

# many targets from a file (host/IP/CIDR per line): per-target reports + aggregate
allscan --targets-file scope.txt --i-have-authorization --all
```

Management subcommands:

```bash
allscan list --output-dir ./results           # list past runs
allscan diff OLD_RUN.json NEW_RUN.json         # diff two saved runs
```

### CLI flags

| Flag | Meaning |
| --- | --- |
| `--domain` / `--ip` / positional | Target (domain or IP) |
| `--targets-file FILE` | Run the chain per line (host/IP/CIDR); per-target reports + aggregate |
| `--all` | Run every module with defaults |
| `--modules a,b,c` | Which modules to run (default: all) |
| `--skip m1,m2` / `--skip-web` / `--skip-scan` … | Drop modules from the full chain / `--all` |
| `--cve-source nvd,circl` | CVE data sources to query |
| `--exploitdb-csv FILE` | Local ExploitDB CSV for concrete EDB-ID references |
| `--pdf` | Also write a PDF report (needs `reportlab`) |
| `--full-ports` | Scan all 65535 ports |
| `--skip-nmap` | Use the built-in scanner instead of nmap |
| `--os-detection` | nmap `-O` OS detection (needs root) |
| `--threads N` | Concurrent workers |
| `--rate-limit R` | Max requests/second against the target (`0` = unlimited) |
| `--timeout S` | Per-request timeout |
| `--output-dir DIR` | Where reports + `audit.log` are written |
| `--config FILE` | YAML config file (see `config.example.yaml`) |
| `--wordlist-subdomains` / `--wordlist-web` | Custom wordlists |
| `--nvd-api-key` | NVD API key for higher CVE rate limits |
| `--i-have-authorization` | **Required** to run headless |
| `--no-tui` / `--json-only` | Force headless / write JSON only |
| `--active` | Enable **active probing** (detection-only; sends requests) |
| `--scope-allow HOSTS` | Comma-separated extra in-scope hosts/domains/CIDRs |
| `--scope-deny HOSTS` | Comma-separated always-blocked hosts/domains/CIDRs (wins) |
| `--allow-production` | Acknowledge a production target, silence the warning |
| `--active-max-concurrency N` | Active-only worker cap (default 8) |
| `--active-stop-after-errors N` | Auto-stop active probing after N consecutive errors |

Configuration precedence: built-in defaults → YAML config → CLI flags / TUI.

---

## Active probing (detection mode)

By default allscan is **passive** — it observes. The opt-in **active** profile
(`--active`, or the toggle on the TUI settings screen) additionally sends
requests to *confirm* weaknesses, using benign markers and response/error/timing
signatures. It is **detection-only**: it identifies and reports, and never
exploits — no data extraction, no shell, no state change.

```bash
# passive run (default)
allscan example.com --i-have-authorization --all

# active, detection-only, with an explicit scope
allscan example.com --i-have-authorization --all --active \
    --scope-allow "api.example.com,10.0.0.0/24" \
    --scope-deny  "payments.example.com"
```

Checks in this phase: reflected input (XSS sink), open redirect, error-based
SQL-injection signature, and confirmed directory listing. Each active finding is
`{type, location, severity, evidence, confidence, note:"manual validation required"}`.

**Hard safety controls (always on for active mode):**

- Gated behind the authorization confirmation **and** the explicit `--active` flag.
- **Scope-enforced** — every request's host is checked against the target + an
  allowlist, minus a denylist (denylist wins). Out-of-scope hosts are blocked
  and logged; nothing is sent to them.
- **Rate-limited and concurrency-capped**, with a conservative active-only cap.
- **Kill switch / cancel** — the TUI Stop key and `Ctrl+C` halt probing and save
  partial results; an **automatic stop condition** halts after a configurable
  run of consecutive request errors.
- **Non-destructive by default** with a **production-target warning**
  (acknowledge with `--allow-production`).
- Every active request (and every scope block) is written to the audit log.

> Active markers are inert: alphanumeric reflect tokens, a single quote for
> error-based SQL signatures, and a non-resolvable `.invalid` redirect target.
> No payload changes server state. Findings still require manual validation.

---

## The terminal UI

The TUI walks through a short flow; all screens work with arrow keys, `Tab`,
`Enter`, and `Space`. Key bindings are shown in the footer of every screen.

**1. Welcome / target entry** — enter a domain or IP and tick the required
*"I have authorization to test this target"* box. The scan cannot start until
both are valid. Press **`A`** (or the **Allscan (run everything)** button) to
confirm target + authorization once and run *all* modules back-to-back with
default settings — skipping the checklist and settings screens. This is the
menu-driven equivalent of the `--all` CLI flag.

```
╭─ allscan — security recon for authorized testing ─────────────────────────╮
│  Scanning systems without explicit authorization may be illegal.          │
│  [A] Allscan (run everything)   [P] Past scans   [Esc] Quit               │
│  ───────────────────────────────────────────────────────────────────     │
│  Target (domain or IP):                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ example.com                                                         │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│  [x] I have authorization to test this target                            │
│   ( ▶ Allscan (run everything) )  ( Configure & Scan → )  ( Past )  ( Quit )│
╰───────────────────────────────────────────────────────────────────────────╯
```

The **Allscan** run chains Subdomain Discovery → Port/Service Scan → Web
Enumeration → HTML/Header Analysis → CVE Correlation automatically, shows the
same live per-module status + findings counter + activity log, and ends on the
same results screen with JSON/Markdown/HTML export.

**2. Module checklist** — a `SelectionList`: ↑/↓ to move, `Space` to toggle,
`a` = all, `n` = none.

```
  Select modules  (↑/↓ move · space toggle · a=all · n=none · enter=continue)
  ┌───────────────────────────────────────────────────────────────────────┐
  │ [X] Network/Host Discovery      [X] SSL/TLS Deep Audit                  │
  │ [X] Subdomain Discovery         [X] Cloud Exposure                      │
  │ [X] DNS Deep-Dive               [X] WAF/CDN & Rate-limit Detection      │
  │ [X] Email Security (SPF/…)      [X] CVE Correlation                     │
  │ [X] Port/Service Scan           [X] Compliance Checklist                │
  │ [X] Web Enumeration             [X] Active Probing (detection)          │
  │ [X] API & Tech Fingerprinting                                           │
  │ [X] HTML/Header Analysis                                                │
  └───────────────────────────────────────────────────────────────────────┘
  (Active Probing only sends requests when --active / the settings toggle is on.)
```

**3. Settings** — full-port toggle, skip-nmap, OS detection, thread count,
rate limit, timeout, output directory.

**4. Live scan** — a status row per module (queued → running → done), a
live-updating findings counter, and a scrolling activity log. `Ctrl+C` or `s`
stops gracefully and still saves partial results.

```
  Scanning 127.0.0.1   (modules: web, headers)
  ┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓   ╭─ Live counter ─╮
  ┃ Module                 ┃ Status    ┃   │                │
  ┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩   │       12       │
  │ Web Enumeration        │ ✓ done    │   │    findings    │
  │ HTML/Header Analysis   │ ▶ running │   │                │
  └────────────────────────┴───────────┘   ╰────────────────╯
  ╭─ Activity log ───────────────────────────────────────────╮
  │ web      http://127.0.0.1 -> 200 Test Site               │
  │ headers  Missing content-security-policy header          │
  ╰──────────────────────────────────────────────────────────╯
```

**5. Results** — findings in a scrollable table, colour-coded by severity,
with an expandable detail pane showing description + evidence. Export with
`j` (JSON), `m` (Markdown), `h` (HTML); `r` starts a new scan; `p` opens past
scans.

**6. Past scans + diff** — lists previous runs from the output directory.
`Enter` reopens a run in the results view; `Space` marks two runs of the same
target and `d` shows a diff (new / resolved findings).

### Example findings (real run against a local test server)

```
INFO    web      http://127.0.0.1 [200] Test Site
INFO    web      http://127.0.0.1 tech: SimpleHTTP/0.6 Python/3.13
MEDIUM  headers  Missing content-security-policy header
LOW     headers  Verbose header server: SimpleHTTP/0.6 Python/3.13
LOW     html     Interesting HTML comment
MEDIUM  html     Outdated library: jquery 1.7.2
HIGH    html     Risky inline JS: Hardcoded credential in inline script
```

---

## Output & audit trail

Each run writes to the output directory:

- `allscan_<target>_<timestamp>.json` — structured results (source of truth)
- `allscan_<target>_<timestamp>.md` — Markdown summary
- `allscan_<target>_<timestamp>.html` — standalone HTML report
- `audit.log` — append-only JSONL of every outbound action (DNS query, HTTP
  request, nmap invocation, NVD query …) with timestamps, for a full audit
  trail

---

## Project layout

```
allscan/
├── __init__.py        package metadata
├── __main__.py        `python -m allscan`
├── main.py            CLI entry point + headless rich runner
├── tui.py             textual terminal UI (all screens)
├── engine.py          scan orchestration + cancellation
├── base.py            Module interface + ModuleContext + registry
├── config.py          defaults, YAML loading, Config dataclass
├── models.py          Finding / ScanResult / Severity
├── utils.py           rate limiter, audit log, validation, secret scan
├── netdiscover.py     ping sweep / ARP / traceroute host discovery
├── recon.py           subdomain & asset discovery
├── dnsx.py            DNS deep-dive (records, DNSSEC, cache snooping)
├── email_sec.py       SPF / DKIM / DMARC posture (registry name: email)
├── scan.py            port/service scanning (nmap wrapper + fallback)
├── web.py             web enumeration & content discovery
├── fingerprint.py     API endpoint / CMS / framework fingerprinting
├── headers.py         HTML source + security header analysis
├── tls.py             SSL/TLS deep audit (protocol matrix, chain, expiry)
├── cloud.py           cloud bucket + metadata-endpoint exposure
├── waf.py             WAF/CDN fingerprint + rate-limit observation
├── scope.py           scope enforcement (allow/deny, out-of-scope blocking)
├── active.py          active probing (detection-only; gated behind --active)
├── vulns.py           CVE correlation (NVD + CIRCL)
├── exploitrefs.py     exploit REFERENCES + KEV/EPSS enrichment (no payloads)
├── compliance.py      baseline pass/fail checklist roll-up
├── report.py          JSON/Markdown/HTML reporting + diff + aggregate
└── report_pdf.py      PDF report (ReportLab; exec summary + risk table)
tests/                 offline unit tests (no network)
requirements.txt
config.example.yaml
pyproject.toml
```

## Development

```bash
pip install -e ".[dev]"
pytest -q                 # offline test suite (no network access needed)
```

The engine is UI-agnostic: modules implement a tiny `Module.run(ctx)` contract
and emit `Finding` objects. Cancellation is cooperative via a shared token, so
both the CLI (`Ctrl+C`) and the TUI (Stop key) halt cleanly and preserve
partial results.

---

## Responsible use

allscan is intended for security professionals testing their own
infrastructure or systems they are explicitly authorized to assess
(penetration tests, bug-bounty programs with in-scope assets, CTFs, lab
environments). It deliberately:

- requires an authorization confirmation before any module runs,
- rate-limits outbound activity to avoid hammering targets,
- logs every action for an audit trail,
- lists CVEs **informationally only** and ships **no** proof-of-concept or
  exploit code.

You are responsible for ensuring you have permission to test any target.

## License

MIT
