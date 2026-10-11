"""Entry point for the packaged (PyInstaller) build.

Thin wrapper: no arguments lands on the TUI welcome screen, which is already
the no-args default of the CLI.
"""

from allscan.main import run_cli

if __name__ == "__main__":
    raise SystemExit(run_cli())
