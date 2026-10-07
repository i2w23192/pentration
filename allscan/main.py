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

    p.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirm you are authorized to test the target (required for headless runs).",
    )
    p.add_argument("--no-tui", action="store_true", help="Force headless mode even with a TTY")
    p.add_argument("--json-only", action="store_true", help="Write only JSON (skip md/html)")

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
    scope_allow = ([s.strip() for s in args.scope_allow.split(",") if s.strip()]
                   if getattr(args, "scope_allow", None) else None)
    scope_deny = ([s.strip() for s in args.scope_deny.split(",") if s.strip()]
                  if getattr(args, "scope_deny", None) else None)
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


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Dispatch management subcommands before the main (scan) parser so that a
    # positional target cannot be mistaken for a subcommand and vice versa.
    if argv and argv[0] == "diff":
        return cmd_diff(build_diff_parser().parse_args(argv[1:]))
    if argv and argv[0] == "list":
        return cmd_list(build_list_parser().parse_args(argv[1:]))

    parser = build_parser()
    args = parser.parse_args(argv)

    target = resolve_target(args)
    config = config_from_args(args)

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
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
