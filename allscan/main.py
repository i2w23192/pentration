"""allscan command-line entry point.

Running ``allscan`` with no target launches the interactive TUI. Passing a
target plus ``--i-have-authorization`` runs headlessly (for scripting/CI),
mirroring every TUI option as a flag. A rich live display shows progress; on
completion results are written to the output directory and a summary printed.

Authorization is hard-required: the tool refuses to run any module unless the
operator confirms authorization (TUI prompt, or the ``--i-have-authorization``
flag for automation).
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path
from typing import Optional

from allscan import __version__
from allscan.config import DEFAULTS, MODULE_LABELS, Config
from allscan.engine import MODULE_ORDER, Engine
from allscan.models import ScanResult, Severity
from allscan.utils import validate_target

AUTHORIZATION_NOTICE = """\
╭───────────────────────────────────────────────────────────────────────────╮
│  allscan — AUTHORIZED SECURITY TESTING ONLY                                 │
│                                                                             │
│  Scanning systems you do not own or lack explicit written permission to     │
│  test may be illegal. By proceeding you confirm you are authorized to test  │
│  the specified target. allscan rate-limits and logs all activity.           │
╰───────────────────────────────────────────────────────────────────────────╯
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="allscan",
        description="Modular security recon/scanning tool for authorized testing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"allscan {__version__}")

    tgt = p.add_mutually_exclusive_group()
    tgt.add_argument("--domain", help="Target domain (e.g. example.com)")
    tgt.add_argument("--ip", help="Target IP address")
    p.add_argument("target", nargs="?", help="Target domain or IP (positional)")
    p.add_argument("--targets-file", metavar="FILE",
                   help="File with one host/IP/CIDR per line; runs the chain per "
                        "target with per-target reports + an aggregate summary")

    p.add_argument(
        "--modules",
        help="Comma-separated modules to run: "
        + ",".join(MODULE_LABELS.keys())
        + " (default: all)",
    )
    p.add_argument("--all", dest="run_all", action="store_true",
                   help="Run every module (recon→scan→web→headers→vulns) with defaults")
    p.add_argument("--full-ports", action="store_true", help="Scan all 65535 ports")
    p.add_argument("--skip-nmap", action="store_true", help="Skip nmap; use built-in scanner")
    p.add_argument("--os-detection", action="store_true", help="nmap OS detection (-O, needs root)")
    p.add_argument("--threads", type=int, help="Concurrent workers")
    p.add_argument("--rate-limit", type=float, help="Max requests/second (0 = unlimited)")
    p.add_argument("--timeout", type=float, help="Per-request timeout (seconds)")
    p.add_argument("--output-dir", help="Directory for results and audit log")
    p.add_argument("--config", help="Path to a YAML config file")
    p.add_argument("--wordlist-subdomains", help="Custom subdomain wordlist path")
    p.add_argument("--wordlist-web", help="Custom web path wordlist")
    p.add_argument("--nvd-api-key", help="NVD API key (higher CVE rate limits)")
    p.add_argument("--cve-source", metavar="SRC",
                   help="Comma list of CVE sources: nvd,circl (default: nvd,circl)")
    p.add_argument("--exploitdb-csv", metavar="FILE",
                   help="Local ExploitDB files_exploits.csv to resolve EDB-ID references")
    p.add_argument("--pdf", action="store_true",
                   help="Also write a PDF report (requires reportlab)")
    # Skip flags — fold into the full chain / Allscan run.
    skip = p.add_argument_group("skip modules (use with the full chain / --all)")
    skip.add_argument("--skip", metavar="MODULES",
                      help="Comma list of modules to skip, e.g. --skip web,active")
    for _m in MODULE_ORDER:
        skip.add_argument(f"--skip-{_m}", dest=f"skip_{_m}", action="store_true",
                          help=f"Skip the {_m} module")

    # --- active probing (detection-only) --------------------------------
    active = p.add_argument_group("active probing (detection-only; sends requests)")
    active.add_argument("--active", action="store_true",
                        help="Enable active probing: send benign requests to CONFIRM "
                             "weaknesses (never exploit). Requires authorization.")
    active.add_argument("--scope-allow", metavar="HOST",
                        help="Comma-separated extra in-scope hosts/domains/CIDRs")
    active.add_argument("--scope-deny", metavar="HOST",
                        help="Comma-separated always-blocked hosts/domains/CIDRs (wins)")
    active.add_argument("--allow-production", action="store_true",
                        help="Acknowledge the target is production and silence the warning")
    active.add_argument("--active-max-concurrency", type=int,
                        help="Active-only worker cap (default 8)")
    active.add_argument("--active-stop-after-errors", type=int,
                        help="Auto-stop active probing after N consecutive errors (default 25)")
    active.add_argument("--integrations", metavar="TOOLS",
                        help="Comma list of external scanners to wrap if installed: "
                             "subfinder,amass,httpx (passive), nuclei,nikto,sqlmap,masscan "
                             "(active — also need --active). Detection phase only.")

    p.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirm you are authorized to test the target (required for headless runs).",
    )
    p.add_argument("--no-tui", action="store_true", help="Force headless mode even with a TTY")
    p.add_argument("--json-only", action="store_true", help="Write only JSON (skip md/html)")
    p.add_argument("--project", metavar="NAME",
                   help="Run under an engagement project: applies its scope, enforces "
                        "its testing window for active work, ingests findings, saves the run")
    p.add_argument("--projects-dir", help="Engagement/project store directory")

    p.epilog = (
        "subcommands:\n"
        "  allscan list [--output-dir DIR]     list past runs\n"
        "  allscan diff OLD.json NEW.json      diff two saved runs\n"
    )
    p.formatter_class = argparse.RawDescriptionHelpFormatter
    return p


def build_diff_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="allscan diff", description="Diff two saved JSON runs.")
    p.add_argument("old", help="Path to older run JSON")
    p.add_argument("new", help="Path to newer run JSON")
    return p


def build_list_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="allscan list", description="List past runs.")
    p.add_argument("--output-dir", default=DEFAULTS["output_dir"])
    return p


def config_from_args(args) -> Config:
    base = Config.load(args.config)
    modules = None
    if getattr(args, "run_all", False):
        # --all forces the full chain regardless of config/--modules.
        modules = list(MODULE_ORDER)
    elif args.modules:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    # resolve the module set, then subtract any --skip / --skip-<module>
    if modules is None:
        modules = list(base.modules)
    skipped: set[str] = set()
    if getattr(args, "skip", None):
        skipped |= {m.strip() for m in args.skip.split(",") if m.strip()}
    for m in MODULE_ORDER:
        if getattr(args, f"skip_{m}", False):
            skipped.add(m)
    if skipped:
        modules = [m for m in modules if m not in skipped]

    scope_allow = ([s.strip() for s in args.scope_allow.split(",") if s.strip()]
                   if getattr(args, "scope_allow", None) else None)
    scope_deny = ([s.strip() for s in args.scope_deny.split(",") if s.strip()]
                  if getattr(args, "scope_deny", None) else None)
    cve_sources = ([s.strip().lower() for s in args.cve_source.split(",") if s.strip()]
                   if getattr(args, "cve_source", None) else None)
    integrations = ([s.strip().lower() for s in args.integrations.split(",") if s.strip()]
                    if getattr(args, "integrations", None) else None)
    return base.apply_overrides(
        threads=args.threads,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        full_ports=True if args.full_ports else None,
        skip_nmap=True if args.skip_nmap else None,
        os_detection=True if args.os_detection else None,
        modules=modules,
        output_dir=args.output_dir,
        wordlist_subdomains=args.wordlist_subdomains,
        wordlist_web=args.wordlist_web,
        nvd_api_key=args.nvd_api_key,
        active=True if getattr(args, "active", False) else None,
        scope_allow=scope_allow,
        scope_deny=scope_deny,
        allow_production=True if getattr(args, "allow_production", False) else None,
        active_max_concurrency=getattr(args, "active_max_concurrency", None),
        active_stop_after_errors=getattr(args, "active_stop_after_errors", None),
        cve_sources=cve_sources,
        exploitdb_csv=getattr(args, "exploitdb_csv", None),
        pdf=True if getattr(args, "pdf", False) else None,
        integrations=integrations,
    )


def resolve_target(args) -> Optional[str]:
    raw = args.domain or args.ip or args.target
    if not raw:
        return None
    ok, msg = validate_target(raw)
    if not ok:
        print(f"error: {msg}", file=sys.stderr)
        sys.exit(2)
    return msg  # normalized


# --------------------------------------------------------------------------- #
# headless runner (rich live display)
# --------------------------------------------------------------------------- #


def run_headless(target: str, config: Config) -> ScanResult:
    # Active-mode banner + production warning (detection-only, but it does send
    # requests, so make the operator aware before anything goes out).
    if getattr(config, "active", False):
        from allscan.scope import ScopeGuard

        guard = ScopeGuard(target, list(config.scope_allow), list(config.scope_deny))
        print("\n  [ACTIVE PROBING ENABLED] detection-only: benign markers confirm "
              "weaknesses, never exploit them.")
        print(f"  Scope: {target} (+{len(config.scope_allow)} allow / "
              f"{len(config.scope_deny)} deny). Out-of-scope hosts are blocked.")
        if guard.looks_production() and not config.allow_production:
            print("  ⚠  WARNING: target looks like PRODUCTION. Probing stays "
                  "non-destructive; pass --allow-production to acknowledge.\n")

    try:
        from rich.console import Console
        from rich.live import Live
        from rich.table import Table
        from rich.panel import Panel
        from rich.progress import SpinnerColumn, Progress, TextColumn
        _rich = True
    except Exception:
        _rich = False

    output_dir = config.output_path()
    audit_path = output_dir / "audit.log"

    statuses: dict[str, str] = {m: "queued" for m in config.modules}
    finding_count = {"n": 0}
    log_tail: list[str] = []
    lock = threading.Lock()

    def on_status(module, status):
        with lock:
            statuses[module] = status

    def on_finding(finding):
        with lock:
            finding_count["n"] += 1

    def on_log(module, message):
        with lock:
            log_tail.append(f"[{module}] {message}")
            del log_tail[:-12]

    engine = Engine(
        target,
        config,
        on_log=on_log,
        on_finding=on_finding,
        on_status=on_status,
        audit_path=audit_path,
    )

    # Ctrl+C -> graceful cancel
    def handle_sigint(signum, frame):
        engine.request_cancel()

    signal.signal(signal.SIGINT, handle_sigint)

    if not _rich:
        print(f"Scanning {target} …")
        return engine.run()

    console = Console()

    def render():
        table = Table.grid(expand=True)
        table.add_column(ratio=1)
        mod_table = Table(title=f"allscan · {target}", expand=True)
        mod_table.add_column("Module")
        mod_table.add_column("Status")
        icons = {"queued": "…", "running": "▶", "done": "✓",
                 "error": "✗", "cancelled": "⧉"}
        with lock:
            for m in config.modules:
                st = statuses.get(m, "queued")
                mod_table.add_row(MODULE_LABELS.get(m, m), f"{icons.get(st, '?')} {st}")
            logs = "\n".join(log_tail[-10:]) or "starting…"
            count = finding_count["n"]
        body = Table.grid(expand=True)
        body.add_row(mod_table)
        body.add_row(Panel(f"[bold]{count}[/] findings so far",
                           title="Live counter"))
        body.add_row(Panel(logs, title="Activity log"))
        return body

    result_holder: dict = {}

    def worker():
        result_holder["result"] = engine.run()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    with Live(render(), console=console, refresh_per_second=8) as live:
        while t.is_alive():
            live.update(render())
            t.join(timeout=0.2)
        live.update(render())

    return result_holder.get("result") or engine.result


def write_outputs(result: ScanResult, config: Config, json_only: bool) -> list[Path]:
    from allscan import report

    out = config.output_path()
    paths = [report.save_json(result, out)]
    if not json_only:
        paths.append(report.save_markdown(result, out))
        paths.append(report.save_html(result, out))
        svg = report.save_svg(result, out)
        if svg is not None:
            paths.append(svg)
        if getattr(config, "pdf", False):
            try:
                from allscan import report_pdf

                paths.append(report_pdf.save_pdf(result, out))
            except ImportError:
                print("  (PDF requested but ReportLab is not installed; "
                      "pip install reportlab)")
            except Exception as exc:  # pragma: no cover - defensive
                print(f"  (PDF generation failed: {exc})")
    return paths


def print_summary(result: ScanResult, paths: list[Path]) -> None:
    counts = result.counts_by_severity()
    print()
    print(f"Scan of {result.target} complete"
          + (" (PARTIAL — cancelled)" if result.partial else "")
          + f" — {len(result.findings)} findings in {result.duration:.1f}s")
    for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        print(f"  {sev.value:<7}: {counts[sev.value]}")
    print("\nSaved:")
    for p in paths:
        print(f"  {p}")


# --------------------------------------------------------------------------- #
def cmd_diff(args) -> int:
    from allscan import report

    old = report.load_json(Path(args.old))
    new = report.load_json(Path(args.new))
    d = report.diff_runs(old, new)
    print(report.diff_to_markdown(d))
    return 0


def cmd_list(args) -> int:
    from allscan import report

    runs = report.list_runs(Path(args.output_dir))
    if not runs:
        print("No past runs found.")
        return 0
    print(f"{'When':<21} {'Target':<30} {'Findings':>8}  File")
    for r in runs:
        flag = " (partial)" if r.partial else ""
        print(f"{r.when:<21} {r.target:<30} {r.finding_count:>8}  {r.path.name}{flag}")
    return 0


def read_targets_file(path: str, cap: int) -> list[str]:
    """Parse a targets file: one host/IP/CIDR per line (# comments allowed).

    CIDR lines are expanded to host addresses (bounded by ``cap``). Invalid
    lines are skipped with a warning.
    """
    import ipaddress

    targets: list[str] = []
    seen: set[str] = set()
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        print(f"error: could not read targets file: {exc}", file=sys.stderr)
        sys.exit(2)
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "/" in line:  # CIDR
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                print(f"  ! skipping invalid CIDR: {line}", file=sys.stderr)
                continue
            for host in net.hosts():
                h = str(host)
                if h not in seen:
                    seen.add(h)
                    targets.append(h)
                if len(targets) >= cap:
                    break
            continue
        ok, norm = validate_target(line)
        if not ok:
            print(f"  ! skipping invalid target: {line}", file=sys.stderr)
            continue
        if norm not in seen:
            seen.add(norm)
            targets.append(norm)
        if len(targets) >= cap:
            break
    return targets[:cap]


def run_multi(targets: list[str], config: Config, json_only: bool) -> int:
    from allscan import report

    print(AUTHORIZATION_NOTICE)
    print(f"  Multi-target run: {len(targets)} targets\n")
    results = []
    for i, tgt in enumerate(targets, start=1):
        print(f"\n===== [{i}/{len(targets)}] {tgt} =====")
        result = run_headless(tgt, config)
        paths = write_outputs(result, config, json_only)
        print_summary(result, paths)
        results.append((tgt, result))
    agg = report.save_aggregate(results, config.output_path())
    print(f"\nAggregate summary written: {agg}")
    print(f"  ({agg.with_suffix('.md').name} has the per-target table)")
    return 0


# --------------------------------------------------------------------------- #
# engagement / project subcommands (Phase 5)
# --------------------------------------------------------------------------- #

def _store(projects_dir: Optional[str]):
    from allscan.platform import ProjectStore
    return ProjectStore(projects_dir or DEFAULTS["projects_dir"])


def cmd_project(argv: list[str]) -> int:
    import argparse as _a
    p = _a.ArgumentParser(prog="allscan project")
    sub = p.add_subparsers(dest="sub", required=True)
    c = sub.add_parser("create"); c.add_argument("name"); c.add_argument("--client", default="")
    c.add_argument("--scope-allow"); c.add_argument("--scope-deny")
    c.add_argument("--roe"); c.add_argument("--window-start"); c.add_argument("--window-end")
    c.add_argument("--authorization"); c.add_argument("--projects-dir")
    s = sub.add_parser("show"); s.add_argument("name"); s.add_argument("--projects-dir")
    lst = sub.add_parser("list"); lst.add_argument("--projects-dir")
    args = p.parse_args(argv)
    store = _store(getattr(args, "projects_dir", None))

    if args.sub == "list":
        rows = store.list()
        if not rows:
            print("No projects.")
            return 0
        print(f"{'Project':<24} {'Client':<20} {'Runs':>5} {'Findings':>9}  Auth")
        for r in rows:
            print(f"{r['name']:<24} {r['client']:<20} {r['runs']:>5} {r['findings']:>9}  "
                  f"{'yes' if r['authorized'] else 'NO'}")
        return 0

    if args.sub == "create":
        if store.exists(args.name):
            print(f"error: project '{args.name}' already exists.", file=sys.stderr)
            return 2
        proj = store.create(args.name, args.client)
        if args.scope_allow or args.scope_deny:
            proj.set_scope(
                allow=[s.strip() for s in (args.scope_allow or "").split(",") if s.strip()] or None,
                deny=[s.strip() for s in (args.scope_deny or "").split(",") if s.strip()] or None)
        if args.roe:
            text = Path(args.roe).read_text() if Path(args.roe).is_file() else args.roe
            proj.set_roe(text)
        if args.window_start or args.window_end:
            proj.set_window(args.window_start, args.window_end)
        if args.authorization:
            try:
                proj.add_authorization(args.authorization)
            except FileNotFoundError:
                print(f"error: authorization file not found: {args.authorization}", file=sys.stderr)
                return 2
        proj.save()
        print(f"Created project '{args.name}'"
              + (" (authorization on file)" if proj.has_authorization
                 else " — WARNING: no authorization evidence stored yet"))
        return 0

    if args.sub == "show":
        if not store.exists(args.name):
            print(f"error: no such project '{args.name}'.", file=sys.stderr)
            return 2
        proj = store.load(args.name)
        d = proj.data
        print(f"Project: {d['name']}   Client: {d.get('client') or '—'}")
        print(f"  Scope allow: {d['scope']['allow'] or '—'}")
        print(f"  Scope deny : {d['scope']['deny'] or '—'}")
        w = d.get("window") or {}
        print(f"  Window     : {w.get('start') or '—'} .. {w.get('end') or '—'} "
              f"(active now: {'yes' if proj.within_window() else 'NO'})")
        print(f"  Authorized : {'yes' if proj.has_authorization else 'NO'} "
              f"({len(d['authorization'])} file(s))")
        print(f"  Evidence   : {len(d['evidence'])} item(s)")
        print(f"  Runs       : {len(d['runs'])}")
        by = proj.findings_by_status()
        print(f"  Findings   : {len(d['findings'])} "
              f"({', '.join(f'{k}={len(v)}' for k, v in by.items()) or '—'})")
        return 0
    return 0


def cmd_evidence(argv: list[str]) -> int:
    import argparse as _a
    p = _a.ArgumentParser(prog="allscan evidence")
    sub = p.add_subparsers(dest="sub", required=True)
    a = sub.add_parser("add"); a.add_argument("name"); a.add_argument("file")
    a.add_argument("--note", default=""); a.add_argument("--projects-dir")
    lst = sub.add_parser("list"); lst.add_argument("name"); lst.add_argument("--projects-dir")
    v = sub.add_parser("verify"); v.add_argument("name"); v.add_argument("--projects-dir")
    args = p.parse_args(argv)
    store = _store(getattr(args, "projects_dir", None))
    if not store.exists(args.name):
        print(f"error: no such project '{args.name}'.", file=sys.stderr)
        return 2
    proj = store.load(args.name)
    if args.sub == "add":
        try:
            rec = proj.add_evidence(args.file, args.note)
        except FileNotFoundError:
            print(f"error: file not found: {args.file}", file=sys.stderr)
            return 2
        proj.save()
        print(f"Stored {rec['id']}: {rec['name']}  sha256={rec['sha256']}  "
              f"({rec['size']} bytes) by {rec['added_by']}")
        return 0
    if args.sub == "list":
        for rec in proj.data["evidence"]:
            print(f"{rec['id']}  {rec['name']:<30} {rec['sha256'][:16]}…  "
                  f"{rec['size']:>8}B  {rec['added_by']}")
        if not proj.data["evidence"]:
            print("No evidence stored.")
        return 0
    if args.sub == "verify":
        results = proj.verify_evidence(); proj.save()
        for r in results:
            print(f"{r['id']}  {r['name']:<30} {'OK' if r['intact'] else 'TAMPERED/MISSING'}")
        return 0 if all(r["intact"] for r in results) else 1
    return 0


def cmd_findings(argv: list[str]) -> int:
    import argparse as _a
    p = _a.ArgumentParser(prog="allscan findings")
    sub = p.add_subparsers(dest="sub", required=True)
    lst = sub.add_parser("list"); lst.add_argument("name")
    lst.add_argument("--status"); lst.add_argument("--projects-dir")
    st = sub.add_parser("set-status"); st.add_argument("name")
    st.add_argument("fingerprint"); st.add_argument("status")
    st.add_argument("--note", default=""); st.add_argument("--projects-dir")
    args = p.parse_args(argv)
    store = _store(getattr(args, "projects_dir", None))
    if not store.exists(args.name):
        print(f"error: no such project '{args.name}'.", file=sys.stderr)
        return 2
    proj = store.load(args.name)
    if args.sub == "list":
        recs = list(proj.data["findings"].values())
        if args.status:
            recs = [r for r in recs if r["status"] == args.status]
        recs.sort(key=lambda r: (r["status"], r["title"]))
        print(f"{'Fingerprint':<18}{'Status':<15}{'Sev':<8}{'Category':<12}Title")
        for r in recs:
            print(f"{r['fingerprint']:<18}{r['status']:<15}{r['severity']:<8}"
                  f"{r['category']:<12}{r['title'][:60]}")
        if not recs:
            print("(no findings)")
        return 0
    if args.sub == "set-status":
        from allscan.platform import STATUSES
        if args.status not in STATUSES:
            print(f"error: status must be one of {', '.join(STATUSES)}", file=sys.stderr)
            return 2
        try:
            proj.set_finding_status(args.fingerprint, args.status, args.note)
        except KeyError:
            print(f"error: no finding {args.fingerprint}", file=sys.stderr)
            return 2
        proj.save()
        print(f"{args.fingerprint} -> {args.status}")
        return 0
    return 0


def cmd_retest(argv: list[str]) -> int:
    import argparse as _a
    p = _a.ArgumentParser(prog="allscan retest")
    p.add_argument("name")
    p.add_argument("--run", help="Path to a run JSON to retest against the ledger")
    p.add_argument("--projects-dir")
    args = p.parse_args(argv)
    store = _store(getattr(args, "projects_dir", None))
    if not store.exists(args.name):
        print(f"error: no such project '{args.name}'.", file=sys.stderr)
        return 2
    if not args.run:
        print("error: provide --run RUN.json (a fresh scan to compare).", file=sys.stderr)
        return 2
    from allscan import report
    proj = store.load(args.name)
    result = report.load_json(Path(args.run))
    rep = proj.retest(result, run_path=args.run)
    proj.save()
    c = rep["counts"]
    print(f"Retest {rep['run_id']} for {rep['target']}:")
    print(f"  fixed={c['fixed']}  not-fixed={c['not_fixed']}  "
          f"regressions={c['regressions']}  new={c['new']}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Dispatch management subcommands before the main (scan) parser so that a
    # positional target cannot be mistaken for a subcommand and vice versa.
    if argv and argv[0] == "diff":
        return cmd_diff(build_diff_parser().parse_args(argv[1:]))
    if argv and argv[0] == "list":
        return cmd_list(build_list_parser().parse_args(argv[1:]))
    if argv and argv[0] == "project":
        return cmd_project(argv[1:])
    if argv and argv[0] == "evidence":
        return cmd_evidence(argv[1:])
    if argv and argv[0] == "findings":
        return cmd_findings(argv[1:])
    if argv and argv[0] == "retest":
        return cmd_retest(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    target = resolve_target(args)
    config = config_from_args(args)

    # Engagement project: apply its scope, enforce its window for active work.
    project = None
    if getattr(args, "project", None):
        if getattr(args, "projects_dir", None):
            config.projects_dir = args.projects_dir
        store = _store(config.projects_dir)
        if not store.exists(args.project):
            print(f"error: no such project '{args.project}'. Create it with "
                  f"'allscan project create {args.project}'.", file=sys.stderr)
            return 2
        project = store.load(args.project)
        ps = project.data.get("scope", {})
        config.scope_allow = list(dict.fromkeys(list(config.scope_allow) + ps.get("allow", [])))
        config.scope_deny = list(dict.fromkeys(list(config.scope_deny) + ps.get("deny", [])))
        if config.active:
            if not project.has_authorization:
                print("  ⚠  project has no stored authorization evidence.")
            if not project.within_window():
                print("  ⚠  outside the project testing window — DISABLING active "
                      "probing for this run.")
                config.active = False

    # Multi-target file mode (headless, scripting) — requires authorization.
    if getattr(args, "targets_file", None):
        if not args.i_have_authorization:
            print(AUTHORIZATION_NOTICE)
            print("Refusing multi-target run without --i-have-authorization.",
                  file=sys.stderr)
            return 3
        targets = read_targets_file(args.targets_file, config.host_discovery_max)
        if not targets:
            print("error: no valid targets in the targets file.", file=sys.stderr)
            return 2
        return run_multi(targets, config, args.json_only)

    # Decide TUI vs headless.
    want_tui = (target is None) or (not args.no_tui and sys.stdin.isatty()
                                    and not args.i_have_authorization)

    if want_tui:
        try:
            from allscan.tui import run_tui
        except Exception as exc:
            print(f"TUI unavailable ({exc}). Install 'textual' or run headless with "
                  f"--i-have-authorization.", file=sys.stderr)
            return 1
        return run_tui(initial_target=target, config=config)

    # headless path requires explicit authorization
    if not args.i_have_authorization:
        print(AUTHORIZATION_NOTICE)
        print("Refusing to run headless without --i-have-authorization.", file=sys.stderr)
        return 3
    if not target:
        print("error: a target is required for headless mode.", file=sys.stderr)
        return 2

    print(AUTHORIZATION_NOTICE)
    result = run_headless(target, config)
    paths = write_outputs(result, config, args.json_only)
    print_summary(result, paths)
    if project is not None:
        info = project.ingest_run(result, run_path=str(paths[0]))
        project.save()
        print(f"\nProject '{project.name}': ingested {info['run_id']} "
              f"({info['new']} new, {info['updated']} updated findings).")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
