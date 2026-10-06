"""Interactive terminal UI for allscan, built on textual.

Screen flow:

    Welcome (target + authorization)  ->  Modules (checklist)  ->  Settings
         -> Scan (live progress)      ->  Results (grouped, exportable)
    Past Scans (list + diff) is reachable from the Welcome screen.

The scan itself runs on a background thread (textual worker) so the UI stays
responsive; progress and findings are pushed back onto the UI thread via
``call_from_thread``. Ctrl+C / the Stop binding cancel cooperatively and the
Results screen still shows (and can export) whatever partial data exists.

If textual is not installed, :func:`run_tui` raises ImportError and the caller
(main.py) falls back to the headless runner.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from allscan.config import MODULE_LABELS, Config
from allscan.engine import MODULE_ORDER, Engine
from allscan.models import Finding, ScanResult, Severity
from allscan.utils import validate_target

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Rule,
    SelectionList,
    Static,
    Switch,
)
from textual.widgets.selection_list import Selection


SEVERITY_STYLE = {
    "high": "bold white on red",
    "medium": "black on orange3",
    "low": "black on yellow",
    "info": "white on blue",
}
SEVERITY_COLOR = {
    "high": "red",
    "medium": "orange3",
    "low": "yellow",
    "info": "cyan",
}


# --------------------------------------------------------------------------- #
# Welcome / target entry
# --------------------------------------------------------------------------- #


class WelcomeScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.quit", "Quit"),
        Binding("p", "past_scans", "Past scans"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="welcome-box"):
            yield Static("[b]allscan[/b] — security recon for authorized testing",
                         id="title")
            yield Static(
                "[dim]Scanning systems without explicit authorization may be "
                "illegal. Confirm you have permission before running.[/dim]",
                id="subtitle",
            )
            yield Rule()
            yield Label("Target (domain or IP):")
            yield Input(placeholder="example.com", id="target-input")
            yield Static("", id="target-error")
            yield Checkbox(
                "I have authorization to test this target",
                id="auth-check",
            )
            with Horizontal(id="welcome-buttons"):
                yield Button("Configure & Scan →", variant="primary", id="start-btn")
                yield Button("Past scans", id="past-btn")
                yield Button("Quit", variant="error", id="quit-btn")
        yield Footer()

    def on_mount(self) -> None:
        if self.app.pending_target:  # type: ignore[attr-defined]
            self.query_one("#target-input", Input).value = self.app.pending_target  # type: ignore[attr-defined]

    def action_past_scans(self) -> None:
        self.app.push_screen(PastScansScreen())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit-btn":
            self.app.exit()
        elif event.button.id == "past-btn":
            self.action_past_scans()
        elif event.button.id == "start-btn":
            self._start()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._start()

    def _start(self) -> None:
        target_raw = self.query_one("#target-input", Input).value.strip()
        error = self.query_one("#target-error", Static)
        ok, msg = validate_target(target_raw)
        if not ok:
            error.update(f"[red]{msg}[/red]")
            return
        if not self.query_one("#auth-check", Checkbox).value:
            error.update("[red]You must confirm authorization before scanning.[/red]")
            return
        error.update("")
        self.app.target = msg  # type: ignore[attr-defined]
        self.app.authorized = True  # type: ignore[attr-defined]
        self.app.push_screen(ModulesScreen())


# --------------------------------------------------------------------------- #
# Module selection
# --------------------------------------------------------------------------- #


class ModulesScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("a", "select_all", "All"),
        Binding("n", "select_none", "None"),
        Binding("enter", "next", "Continue"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="modules-box"):
            yield Static("[b]Select modules[/b]  "
                         "[dim](↑/↓ move · space toggle · a=all · n=none · enter=continue)[/dim]")
            selected = set(self.app.config.modules)  # type: ignore[attr-defined]
            options = [
                Selection(MODULE_LABELS[m], m, m in selected)
                for m in MODULE_ORDER
            ]
            yield SelectionList(*options, id="module-list")
            with Horizontal(id="modules-buttons"):
                yield Button("← Back", id="back-btn")
                yield Button("Settings & Scan →", variant="primary", id="to-settings-btn")
        yield Footer()

    def action_select_all(self) -> None:
        self.query_one(SelectionList).select_all()

    def action_select_none(self) -> None:
        self.query_one(SelectionList).deselect_all()

    def action_next(self) -> None:
        self._continue()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-btn":
            self.app.pop_screen()
        elif event.button.id == "to-settings-btn":
            self._continue()

    def _continue(self) -> None:
        chosen = list(self.query_one(SelectionList).selected)
        if not chosen:
            self.notify("Select at least one module.", severity="error")
            return
        # keep canonical order
        self.app.config.modules = [m for m in MODULE_ORDER if m in chosen]  # type: ignore[attr-defined]
        self.app.push_screen(SettingsScreen())


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #


class SettingsScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        cfg: Config = self.app.config  # type: ignore[attr-defined]
        yield Header(show_clock=True)
        with VerticalScroll(id="settings-box"):
            yield Static("[b]Settings[/b]")
            yield Rule()
            with Horizontal(classes="setting-row"):
                yield Label("Full port range (1-65535)", classes="setting-label")
                yield Switch(value=cfg.full_ports, id="full-ports")
            with Horizontal(classes="setting-row"):
                yield Label("Skip nmap (built-in scanner)", classes="setting-label")
                yield Switch(value=cfg.skip_nmap, id="skip-nmap")
            with Horizontal(classes="setting-row"):
                yield Label("OS detection (nmap -O, needs root)", classes="setting-label")
                yield Switch(value=cfg.os_detection, id="os-detection")
            with Horizontal(classes="setting-row"):
                yield Label("Thread count", classes="setting-label")
                yield Input(value=str(cfg.threads), id="threads", type="integer")
            with Horizontal(classes="setting-row"):
                yield Label("Rate limit (req/sec, 0=unlimited)", classes="setting-label")
                yield Input(value=str(cfg.rate_limit), id="rate-limit", type="number")
            with Horizontal(classes="setting-row"):
                yield Label("Per-request timeout (sec)", classes="setting-label")
                yield Input(value=str(cfg.timeout), id="timeout", type="number")
            with Horizontal(classes="setting-row"):
                yield Label("Output directory", classes="setting-label")
                yield Input(value=cfg.output_dir, id="output-dir")
            with Horizontal(id="settings-buttons"):
                yield Button("← Back", id="back-btn")
                yield Button("Start scan ▶", variant="success", id="scan-btn")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-btn":
            self.app.pop_screen()
        elif event.button.id == "scan-btn":
            self._apply_and_scan()

    def _apply_and_scan(self) -> None:
        cfg: Config = self.app.config  # type: ignore[attr-defined]
        cfg.full_ports = self.query_one("#full-ports", Switch).value
        cfg.skip_nmap = self.query_one("#skip-nmap", Switch).value
        cfg.os_detection = self.query_one("#os-detection", Switch).value
        try:
            cfg.threads = max(1, int(self.query_one("#threads", Input).value or cfg.threads))
            cfg.rate_limit = float(self.query_one("#rate-limit", Input).value or cfg.rate_limit)
            cfg.timeout = float(self.query_one("#timeout", Input).value or cfg.timeout)
        except ValueError:
            self.notify("Numeric settings must be numbers.", severity="error")
            return
        cfg.output_dir = self.query_one("#output-dir", Input).value or cfg.output_dir
        self.app.push_screen(ScanScreen())


# --------------------------------------------------------------------------- #
# Live scan
# --------------------------------------------------------------------------- #


class ScanScreen(Screen):
    BINDINGS = [
        Binding("ctrl+c", "stop", "Stop"),
        Binding("s", "stop", "Stop"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.engine: Optional[Engine] = None
        self._count = 0
        self._stopped = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="scan-box"):
            yield Static("", id="scan-title")
            with Horizontal(id="scan-top"):
                yield DataTable(id="module-status", zebra_stripes=True)
                yield Static("", id="counter-panel")
            yield Label("Activity log:")
            yield RichLog(id="activity-log", highlight=True, markup=True, max_lines=500)
        yield Footer()

    def on_mount(self) -> None:
        cfg: Config = self.app.config  # type: ignore[attr-defined]
        target: str = self.app.target  # type: ignore[attr-defined]
        self.query_one("#scan-title", Static).update(
            f"[b]Scanning[/b] [cyan]{target}[/cyan]  "
            f"[dim](modules: {', '.join(cfg.modules)})[/dim]"
        )
        table = self.query_one("#module-status", DataTable)
        table.add_columns("Module", "Status")
        self._rows: dict[str, object] = {}
        for m in cfg.modules:
            key = table.add_row(MODULE_LABELS.get(m, m), "… queued")
            self._rows[m] = key
        self._update_counter()
        self.start_scan()

    # ------------------------------------------------------------------ #
    def _update_counter(self) -> None:
        self.query_one("#counter-panel", Static).update(
            f"\n [b]{self._count}[/b]\n findings\n\n"
            f" [dim]{'cancelling…' if self._stopped else 'running'}[/dim]"
        )

    def _set_status(self, module: str, status: str) -> None:
        icons = {"queued": "…", "running": "▶", "done": "✓",
                 "error": "✗", "cancelled": "⧉"}
        table = self.query_one("#module-status", DataTable)
        key = self._rows.get(module)
        if key is not None:
            table.update_cell(key, "Status", f"{icons.get(status, '?')} {status}")

    def _log(self, module: str, message: str) -> None:
        self.query_one("#activity-log", RichLog).write(
            f"[cyan]{module:<8}[/cyan] {message}"
        )

    # ------------------------------------------------------------------ #
    @work(thread=True, exclusive=True)
    def start_scan(self) -> None:
        cfg: Config = self.app.config  # type: ignore[attr-defined]
        target: str = self.app.target  # type: ignore[attr-defined]
        out = cfg.output_path()
        audit_path = out / "audit.log"

        def on_status(module, status):
            self.app.call_from_thread(self._set_status, module, status)

        def on_log(module, message):
            self.app.call_from_thread(self._log, module, message)

        def on_finding(finding: Finding):
            def bump():
                self._count += 1
                self._update_counter()
            self.app.call_from_thread(bump)

        self.engine = Engine(
            target, cfg,
            on_log=on_log, on_finding=on_finding, on_status=on_status,
            audit_path=audit_path,
        )
        result = self.engine.run()
        self.app.call_from_thread(self._finished, result)

    def _finished(self, result: ScanResult) -> None:
        self.app.last_result = result  # type: ignore[attr-defined]
        from allscan import report
        out = Path(self.app.config.output_dir)  # type: ignore[attr-defined]
        try:
            report.save_json(result, out)
        except Exception as exc:
            self.notify(f"Could not save JSON: {exc}", severity="error")
        self.app.switch_screen(ResultsScreen(result))

    def action_stop(self) -> None:
        if self.engine and not self._stopped:
            self._stopped = True
            self._update_counter()
            self._log("tui", "Stop requested — finishing current step, saving partial results…")
            self.engine.request_cancel()


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #


class ResultsScreen(Screen):
    BINDINGS = [
        Binding("j", "export_json", "Export JSON"),
        Binding("m", "export_md", "Export MD"),
        Binding("h", "export_html", "Export HTML"),
        Binding("r", "rescan", "New scan"),
        Binding("p", "past_scans", "Past scans"),
        Binding("escape", "app.quit", "Quit"),
    ]

    def __init__(self, result: ScanResult) -> None:
        super().__init__()
        self.result = result

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        counts = self.result.counts_by_severity()
        partial = " [red](partial — cancelled)[/red]" if self.result.partial else ""
        summary = "  ".join(
            f"[{SEVERITY_COLOR[s]}]{s.upper()}: {counts[s]}[/]"
            for s in ("high", "medium", "low", "info")
        )
        with Vertical(id="results-box"):
            yield Static(
                f"[b]Results — {self.result.target}[/b]{partial}  "
                f"[dim]{self.result.duration:.1f}s[/dim]",
                id="results-title",
            )
            yield Static(summary, id="results-summary")
            yield Static("[dim]keys: j=JSON m=Markdown h=HTML r=new scan "
                         "p=past scans esc=quit[/dim]")
            yield DataTable(id="findings-table", zebra_stripes=True, cursor_type="row")
            yield Static("", id="finding-detail")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Severity", "Category", "Target", "Finding")
        grouped = self.result.by_category()
        self._lookup: dict = {}
        # sort categories, then findings by severity within
        findings_sorted = sorted(
            self.result.findings,
            key=lambda f: (-f.severity.rank, f.category, f.title),
        )
        if not findings_sorted:
            self.query_one("#finding-detail", Static).update(
                "[dim]No findings recorded.[/dim]"
            )
        for f in findings_sorted:
            sev = f.severity.value
            key = table.add_row(
                f"[{SEVERITY_COLOR[sev]}]{sev.upper()}[/]",
                f.category,
                (f.target[:28] + "…") if len(f.target) > 29 else f.target,
                f.title[:70],
            )
            self._lookup[key] = f

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        f = self._lookup.get(event.row_key)
        if not f:
            return
        import json as _json
        detail = (
            f"[b]{f.title}[/b]\n"
            f"[{SEVERITY_COLOR[f.severity.value]}]{f.severity.value.upper()}[/] · "
            f"{f.category} · module={f.module} · target={f.target}\n\n"
            f"{f.description}\n"
        )
        if f.evidence:
            detail += "\n[dim]evidence:[/dim]\n" + _json.dumps(f.evidence, indent=2, default=str)
        self.query_one("#finding-detail", Static).update(detail)

    # exports
    def _export(self, kind: str) -> None:
        from allscan import report
        out = Path(self.app.config.output_dir)  # type: ignore[attr-defined]
        try:
            if kind == "json":
                path = report.save_json(self.result, out)
            elif kind == "md":
                path = report.save_markdown(self.result, out)
            else:
                path = report.save_html(self.result, out)
            self.notify(f"Exported: {path}")
        except Exception as exc:
            self.notify(f"Export failed: {exc}", severity="error")

    def action_export_json(self) -> None:
        self._export("json")

    def action_export_md(self) -> None:
        self._export("md")

    def action_export_html(self) -> None:
        self._export("html")

    def action_rescan(self) -> None:
        self.app.switch_screen(WelcomeScreen())

    def action_past_scans(self) -> None:
        self.app.push_screen(PastScansScreen())


# --------------------------------------------------------------------------- #
# Past scans + diff
# --------------------------------------------------------------------------- #


class PastScansScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("enter", "view", "View"),
        Binding("d", "diff", "Diff selected"),
        Binding("space", "mark", "Mark for diff"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._marked: list = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="past-box"):
            yield Static("[b]Past scans[/b]  "
                         "[dim](enter=view · space=mark two · d=diff marked · esc=back)[/dim]")
            yield DataTable(id="runs-table", zebra_stripes=True, cursor_type="row")
            yield Static("", id="past-status")
        yield Footer()

    def on_mount(self) -> None:
        from allscan import report
        table = self.query_one("#runs-table", DataTable)
        table.add_columns("", "When", "Target", "Findings", "File")
        out = Path(self.app.config.output_dir)  # type: ignore[attr-defined]
        self._runs = report.list_runs(out)
        self._row_to_run: dict = {}
        if not self._runs:
            self.query_one("#past-status", Static).update(
                f"[dim]No past runs in {out}/[/dim]"
            )
        for r in self._runs:
            key = table.add_row("", r.when, r.target, str(r.finding_count), r.path.name)
            self._row_to_run[key] = r

    def _current_run(self):
        table = self.query_one("#runs-table", DataTable)
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        except Exception:
            return None
        return self._row_to_run.get(key), key

    def action_view(self) -> None:
        from allscan import report
        cur = self._current_run()
        if not cur or cur[0] is None:
            return
        run = cur[0]
        try:
            result = report.load_json(run.path)
        except Exception as exc:
            self.notify(f"Could not load run: {exc}", severity="error")
            return
        self.app.push_screen(ResultsScreen(result))

    def action_mark(self) -> None:
        cur = self._current_run()
        if not cur or cur[0] is None:
            return
        run, key = cur
        table = self.query_one("#runs-table", DataTable)
        if run in self._marked:
            self._marked.remove(run)
            table.update_cell(key, "", "")
        else:
            if len(self._marked) >= 2:
                oldest = self._marked.pop(0)
                for k, r in self._row_to_run.items():
                    if r is oldest:
                        table.update_cell(k, "", "")
            self._marked.append(run)
            table.update_cell(key, "", "✓")
        self.query_one("#past-status", Static).update(
            f"[dim]marked {len(self._marked)}/2 for diff[/dim]"
        )

    def action_diff(self) -> None:
        if len(self._marked) != 2:
            self.notify("Mark exactly two runs (space) to diff.", severity="warning")
            return
        if self._marked[0].target != self._marked[1].target:
            self.notify("Diff requires two runs of the same target.", severity="error")
            return
        # order by time: older first
        a, b = sorted(self._marked, key=lambda r: r.started_at)
        self.app.push_screen(DiffScreen(a.path, b.path))


class DiffScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def __init__(self, old_path: Path, new_path: Path) -> None:
        super().__init__()
        self.old_path = old_path
        self.new_path = new_path

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with VerticalScroll(id="diff-box"):
            yield Static("", id="diff-title")
            yield DataTable(id="diff-table", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        from allscan import report
        old = report.load_json(self.old_path)
        new = report.load_json(self.new_path)
        d = report.diff_runs(old, new)
        self.query_one("#diff-title", Static).update(
            f"[b]Diff — {d.target}[/b]  "
            f"[green]+{len(d.added)} new[/green]  "
            f"[red]-{len(d.removed)} resolved[/red]  "
            f"[dim]{len(d.unchanged)} unchanged[/dim]\n"
            f"[dim]{self.old_path.name}  →  {self.new_path.name}[/dim]"
        )
        table = self.query_one("#diff-table", DataTable)
        table.add_columns("Change", "Severity", "Category", "Finding")
        for f in d.added:
            table.add_row("[green]NEW[/green]",
                          f"[{SEVERITY_COLOR[f.severity.value]}]{f.severity.value.upper()}[/]",
                          f.category, f.title[:70])
        for f in d.removed:
            table.add_row("[red]GONE[/red]",
                          f"[{SEVERITY_COLOR[f.severity.value]}]{f.severity.value.upper()}[/]",
                          f.category, f.title[:70])
        if not d.added and not d.removed:
            table.add_row("—", "—", "—", "No differences")


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #


class AllscanApp(App):
    CSS = """
    Screen { align: center top; }
    #welcome-box, #modules-box, #settings-box, #scan-box, #results-box,
    #past-box, #diff-box {
        width: 90%;
        max-width: 120;
        margin: 1 2;
        padding: 1 2;
        border: round $primary;
    }
    #title { text-style: bold; color: $accent; }
    #subtitle { margin-bottom: 1; }
    #target-input { margin: 1 0; }
    #target-error { color: red; }
    #welcome-buttons, #modules-buttons, #settings-buttons { margin-top: 1; }
    Button { margin: 0 1; }
    .setting-row { height: 3; align: left middle; }
    .setting-label { width: 44; }
    #module-list { height: 12; border: round $primary-darken-2; }
    #scan-top { height: 12; }
    #module-status { width: 60%; }
    #counter-panel {
        width: 40%; content-align: center middle; text-align: center;
        border: round $success; color: $success;
    }
    #activity-log { height: 1fr; border: round $primary-darken-2; }
    #findings-table { height: 1fr; }
    #finding-detail {
        height: 14; border: round $primary-darken-2; padding: 0 1; overflow-y: auto;
    }
    #runs-table, #diff-table { height: 1fr; }
    """

    TITLE = "allscan"
    SUB_TITLE = "authorized security recon"

    def __init__(self, initial_target: Optional[str], config: Config) -> None:
        super().__init__()
        self.config = config
        self.pending_target = initial_target
        self.target: Optional[str] = None
        self.authorized = False
        self.last_result: Optional[ScanResult] = None

    def on_mount(self) -> None:
        self.push_screen(WelcomeScreen())


def run_tui(initial_target: Optional[str] = None, config: Optional[Config] = None) -> int:
    config = config or Config.load()
    app = AllscanApp(initial_target=initial_target, config=config)
    app.run()
    return 0
