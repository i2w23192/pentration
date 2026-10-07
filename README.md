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
| **Subdomain Discovery** (`recon`) | Passive: crt.sh certificate transparency, DNS records (A/AAAA/MX/TXT/NS/CNAME/SOA), reverse PTR. Active: async wordlist brute force, AXFR zone-transfer attempts. Flags wildcard DNS and filters its noise. |
| **Port/Service Scan** (`scan`) | Wraps `nmap` (top-1000 by default, full 65535 optional, `-sV` version detection, optional `-O` OS detection). Falls back to a built-in concurrent connect scanner + banner grabber when nmap is unavailable or skipped. Flags sensitive exposed services (Redis, Mongo, Docker API, …). |
| **Web Enumeration** (`web`) | HTTP/HTTPS probing of every discovered host (status, title, tech fingerprint), plus content brute forcing for sensitive paths (`.git/`, `.env`, backups, config files, actuators, admin panels) and directory-listing detection. |
| **HTML/Header Analysis** (`headers`) | Security-header audit (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), verbose-header and cookie-flag checks, TLS protocol/cipher/cert inspection, and HTML source analysis (exposed comments, credential-shaped strings, internal paths, outdated JS libraries, risky inline JS). |
| **CVE Correlation** (`vulns`) | Matches detected service/library versions against the public **NVD CVE API** and lists known CVEs with CVSS severity — *informational listing only, no PoC or exploit code*. Also flags common misconfigs (anonymous FTP, directory listing, sensitive open ports). |
| **Reporting** (`report`) | Structured JSON per run, auto-generated Markdown & HTML summaries (severity-tagged, colour-coded), and a diff mode comparing two runs for the same target. |

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
allscan example.com --i-have-authorization \
    --modules recon,scan,web,headers,vulns \
    --threads 20 --rate-limit 10 \
    --output-dir ./results

# a fast web-only pass, skipping nmap:
allscan 203.0.113.10 --i-have-authorization --modules web,headers --skip-nmap

# full port range + OS detection (needs root for -O):
sudo allscan example.com --i-have-authorization --full-ports --os-detection
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
| `--modules a,b,c` | Which modules to run (default: all) |
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

Configuration precedence: built-in defaults → YAML config → CLI flags / TUI.

---

## The terminal UI

The TUI walks through a short flow; all screens work with arrow keys, `Tab`,
`Enter`, and `Space`. Key bindings are shown in the footer of every screen.

**1. Welcome / target entry** — enter a domain or IP and tick the required
*"I have authorization to test this target"* box. The scan cannot start until
both are valid.

```
╭─ allscan — security recon for authorized testing ─────────────────────────╮
│  Scanning systems without explicit authorization may be illegal.          │
│  ───────────────────────────────────────────────────────────────────     │
│  Target (domain or IP):                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ example.com                                                         │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│  [x] I have authorization to test this target                            │
│   ( Configure & Scan → )  ( Past scans )  ( Quit )                       │
╰───────────────────────────────────────────────────────────────────────────╯
```

**2. Module checklist** — a `SelectionList`: ↑/↓ to move, `Space` to toggle,
`a` = all, `n` = none.

```
  Select modules  (↑/↓ move · space toggle · a=all · n=none · enter=continue)
  ┌───────────────────────────────────────────────────────────────────────┐
  │ [X] Subdomain Discovery                                                 │
  │ [X] Port/Service Scan                                                   │
  │ [ ] Web Enumeration                                                     │
  │ [X] HTML/Header Analysis                                                │
  │ [X] CVE Correlation                                                     │
  └───────────────────────────────────────────────────────────────────────┘
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
├── recon.py           subdomain & asset discovery
├── scan.py            port/service scanning (nmap wrapper + fallback)
├── web.py             web enumeration & content discovery
├── headers.py         HTML source + security header + TLS analysis
├── vulns.py           informational CVE correlation (NVD)
└── report.py          JSON/Markdown/HTML reporting + diff
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
