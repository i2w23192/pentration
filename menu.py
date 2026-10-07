#!/usr/bin/env python3
"""allscan — simple interactive menu launcher.

Run this file and pick which scan(s) to run from a numbered menu:

    python menu.py

It's a plain text-menu alternative to the full TUI (`python -m allscan`):
choose a scan, enter a target, confirm authorization, and it runs with the
same engine, live display and JSON/Markdown/HTML reports.

AUTHORIZED USE ONLY — allscan refuses to run until you confirm you have
permission to test the target.
"""

from __future__ import annotations

import sys

# Make sure we can import the allscan package whether run from the repo root
# or elsewhere.
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from allscan.config import MODULE_LABELS, Config
from allscan.engine import MODULE_ORDER
from allscan.main import AUTHORIZATION_NOTICE, print_summary, run_headless, write_outputs
from allscan.utils import validate_target


def print_menu() -> None:
    print("\n" + "=" * 60)
    print("  allscan — authorized security recon / scanner")
    print("=" * 60)
    print("  Choose a scan to run:\n")
    print("   [0]  Run EVERYTHING  (all modules, in order)")
    for i, name in enumerate(MODULE_ORDER, start=1):
        print(f"  [{i:>2}]  {MODULE_LABELS.get(name, name)}")
    print("\n   [q]  Quit")
    print("-" * 60)
    print("  Tip: pick several with commas, e.g.  2,6,8")


def choose_modules() -> list[str] | None:
    """Return the selected module names, or None to quit."""
    while True:
        raw = input("\n> Your choice: ").strip().lower()
        if raw in ("q", "quit", "exit"):
            return None
        if raw == "":
            continue
        if raw == "0" or raw == "all":
            return list(MODULE_ORDER)
        # parse comma / space separated numbers
        tokens = [t for t in raw.replace(",", " ").split() if t]
        picked: list[str] = []
        ok = True
        for tok in tokens:
            if not tok.isdigit() or not (1 <= int(tok) <= len(MODULE_ORDER)):
                print(f"  ! '{tok}' is not a valid choice (1-{len(MODULE_ORDER)}, 0, or q).")
                ok = False
                break
            name = MODULE_ORDER[int(tok) - 1]
            if name not in picked:
                picked.append(name)
        if ok and picked:
            # keep canonical run order
            return [m for m in MODULE_ORDER if m in picked]


def prompt_target() -> str | None:
    """Prompt until a valid target is given, or None to go back/quit."""
    while True:
        raw = input("\n> Target domain or IP (or 'q' to quit): ").strip()
        if raw.lower() in ("q", "quit", "exit"):
            return None
        if not raw:
            continue
        ok, result = validate_target(raw)
        if ok:
            return result  # normalized
        print(f"  ! {result}")


def confirm_authorization(target: str) -> bool:
    print(AUTHORIZATION_NOTICE)
    print(f"  Target: {target}")
    answer = input(
        "  Type 'yes' to confirm you are AUTHORIZED to test this target: "
    ).strip().lower()
    return answer in ("yes", "y")


def main() -> int:
    print_menu()
    modules = choose_modules()
    if modules is None:
        print("Bye.")
        return 0

    labels = ", ".join(MODULE_LABELS.get(m, m) for m in modules)
    print(f"\n  Selected: {labels}")

    target = prompt_target()
    if target is None:
        print("Bye.")
        return 0

    if not confirm_authorization(target):
        print("\n  Authorization not confirmed — aborting. Nothing was scanned.")
        return 3

    # Build config with just the chosen modules (everything else default).
    config = Config.load()
    config.modules = modules

    print(f"\n  Starting scan of {target} … (Ctrl+C to stop and save partial results)\n")
    result = run_headless(target, config)
    paths = write_outputs(result, config, json_only=False)
    print_summary(result, paths)

    # offer another run
    again = input("\n> Run another scan? [y/N]: ").strip().lower()
    if again in ("y", "yes"):
        return main()
    print("Done.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted. Bye.")
        raise SystemExit(130)
