"""Scan orchestration.

The :class:`Engine` wires together the config, rate limiter, audit log and the
selected modules, runs them in dependency order, and collects everything into
a single :class:`~allscan.models.ScanResult`.

It is UI-agnostic: the CLI runs it to completion; the TUI drives it on a
background thread and subscribes to the same ``on_*`` callbacks. Cancellation
is cooperative via :class:`~allscan.utils.CancelToken`, so Ctrl+C or a Stop
key yields a *partial* result with whatever was gathered so far.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Optional

from allscan.base import ModuleContext, get_registry
from allscan.config import Config
from allscan.models import Finding, ScanResult
from allscan.utils import AuditLog, CancelToken, RateLimiter, ScanCancelled

# Modules must run in this order because later ones consume earlier state
# (recon -> hosts, scan/web -> services/pages, vulns -> CVE correlation).
MODULE_ORDER = ["recon", "scan", "web", "headers", "vulns"]

StatusFn = Callable[[str, str], None]  # (module_name, status) status in {queued,running,done,error,cancelled}


class Engine:
    def __init__(
        self,
        target: str,
        config: Config,
        *,
        on_log: Optional[Callable[[str, str], None]] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
        on_status: Optional[StatusFn] = None,
        audit_path: Optional[Path] = None,
    ):
        self.target = target
        self.config = config
        self.on_log = on_log
        self.on_finding = on_finding
        self.on_status = on_status
        self.cancel = CancelToken()
        self.rate = RateLimiter(config.rate_limit)
        self.audit_path = audit_path
        self.result = ScanResult(target=target)

    # ------------------------------------------------------------------ #
    def selected_modules(self) -> list[str]:
        requested = set(self.config.modules)
        return [m for m in MODULE_ORDER if m in requested]

    def _status(self, module: str, status: str) -> None:
        if self.on_status:
            self.on_status(module, status)

    def _log(self, module: str, message: str) -> None:
        if self.on_log:
            self.on_log(module, message)

    def _finding(self, finding: Finding) -> None:
        # live callback only; the authoritative list is built from run() output
        if self.on_finding:
            self.on_finding(finding)

    # ------------------------------------------------------------------ #
    def run(self) -> ScanResult:
        registry = get_registry()
        order = self.selected_modules()
        shared_state: dict = {}

        with AuditLog(self.audit_path) as audit:
            audit.record("scan_start", self.target, config=self.config.to_dict())
            for name in order:
                self._status(name, "queued")

            for name in order:
                if self.cancel.cancelled():
                    self.result.partial = True
                    self._status(name, "cancelled")
                    continue
                module = registry[name]
                ctx = ModuleContext(
                    target=self.target,
                    config=self.config,
                    rate=self.rate,
                    audit=audit,
                    cancel=self.cancel,
                    state=shared_state,
                    _log=self._log,
                    _on_finding=self._finding,
                    _module_name=name,
                )
                self._status(name, "running")
                started = time.time()
                try:
                    findings = module.run(ctx)
                    self.result.extend(findings)
                    self.result.modules_run.append(name)
                    self._status(name, "done")
                    audit.record("module_done", self.target, module=name,
                                 findings=len(findings),
                                 elapsed=round(time.time() - started, 2))
                except ScanCancelled:
                    self.result.partial = True
                    self._status(name, "cancelled")
                    self._log(name, "Cancelled.")
                    audit.record("module_cancelled", self.target, module=name)
                except Exception as exc:  # keep going; one module shouldn't kill the run
                    self._status(name, "error")
                    self._log(name, f"ERROR: {exc}")
                    audit.record("module_error", self.target, module=name, error=str(exc))

            self.result.finished_at = time.time()
            self.result.meta = {
                "hosts": list((shared_state.get("hosts") or {}).keys()),
                "services": shared_state.get("services", []),
            }
            audit.record("scan_end", self.target, partial=self.result.partial,
                         findings=len(self.result.findings))
        return self.result

    def request_cancel(self) -> None:
        self.cancel.cancel()
