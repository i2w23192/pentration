"""Module interface and the context object threaded through every module.

Each backend (recon, scan, web, headers, vulns) subclasses :class:`Module` and
implements :meth:`run`. The orchestrator (:mod:`allscan.engine`) builds a
:class:`ModuleContext` and hands it to each module in turn, collecting the
findings they emit.

Keeping this contract tiny means the TUI, the CLI and tests can all drive
modules the same way.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from allscan.config import Config
from allscan.models import Finding
from allscan.utils import AuditLog, CancelToken, RateLimiter

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


@dataclass
class ModuleContext:
    """Everything a module needs to do its work, injected by the engine."""

    target: str
    config: Config
    rate: RateLimiter
    audit: AuditLog
    cancel: CancelToken
    # shared scratch space passed between modules (e.g. recon populates
    # state["hosts"], web/scan read it back).
    state: dict[str, Any] = field(default_factory=dict)
    # scope guard for the engagement; used to gate authenticated-request
    # secrets (cookie/auth/custom headers) to in-scope hosts only.
    scope: Any = None
    # callbacks wired to the live UI; both default to no-ops for headless use.
    _log: Optional[Callable[[str, str], None]] = None
    _on_finding: Optional[Callable[[Finding], None]] = None
    _module_name: str = ""

    def log(self, message: str) -> None:
        if self._log is not None:
            self._log(self._module_name, message)

    # ------------------------------------------------------------------ #
    # outbound HTTP
    # ------------------------------------------------------------------ #
    def _in_scope(self, url: str) -> bool:
        if self.scope is None:
            return False
        host = urlparse(url).hostname or ""
        try:
            return self.scope.check(host)
        except Exception:
            return False

    def http_get(self, url: str, **kwargs):
        return self.http_request("get", url, **kwargs)

    def http_post(self, url: str, **kwargs):
        return self.http_request("post", url, **kwargs)

    def http_request(self, method: str, url: str, *, headers=None, params=None,
                     data=None, files=None, allow_redirects=None, timeout=None,
                     action=None, **audit_fields):
        """Single outbound-HTTP path: applies the User-Agent, proxy, timeout,
        redirect/verify policy, and scope-gated auth, and performs rate limiting
        and auditing in one place. Per-call ``headers`` are always sent; the
        operator's custom headers, cookie and auth are attached only to in-scope
        hosts. Secrets are never written to the audit log."""
        if requests is None:
            raise RuntimeError("requests is not installed")
        cfg = self.config
        self.rate()
        self.audit.record(action or f"http_{method}", url, **audit_fields)

        final_headers = {"User-Agent": cfg.user_agent}
        if headers:
            final_headers.update(headers)
        if self._in_scope(url):
            for k, v in (getattr(cfg, "extra_headers", None) or {}).items():
                final_headers[k] = v
            if getattr(cfg, "cookie", None):
                final_headers.setdefault("Cookie", cfg.cookie)
            bearer = getattr(cfg, "auth_bearer", None)
            basic = getattr(cfg, "auth_basic", None)
            if bearer:
                final_headers.setdefault("Authorization", f"Bearer {bearer}")
            elif basic:
                token = base64.b64encode(basic.encode()).decode()
                final_headers.setdefault("Authorization", f"Basic {token}")

        req = {
            "headers": final_headers,
            "timeout": cfg.timeout if timeout is None else timeout,
            "allow_redirects": cfg.follow_redirects if allow_redirects is None else allow_redirects,
            "verify": cfg.verify_tls,
        }
        if params is not None:
            req["params"] = params
        if data is not None:
            req["data"] = data
        if files is not None:
            req["files"] = files
        if getattr(cfg, "proxy", None):
            req["proxies"] = {"http": cfg.proxy, "https": cfg.proxy}
        return requests.request(method, url, **req)

    def emit(self, finding: Finding) -> Finding:
        """Register a finding with the live UI and return it unchanged.

        Modules call ``findings.append(ctx.emit(Finding(...)))`` so the live
        counter updates immediately, while the full list is still returned
        from :meth:`Module.run` for the final result.
        """
        if not finding.module:
            finding.module = self._module_name
        if self._on_finding is not None:
            self._on_finding(finding)
        return finding


class Module:
    """Base class for all scan modules."""

    #: short machine name, also the config key
    name: str = ""
    #: human-readable label shown in the TUI
    label: str = ""

    def run(self, ctx: ModuleContext) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Module {self.name}>"


def get_registry() -> dict[str, "Module"]:
    """Return the canonical name -> module-instance registry.

    Imported lazily to avoid import cycles (modules import :mod:`base`).
    """
    from allscan.netdiscover import NetDiscoverModule
    from allscan.recon import ReconModule
    from allscan.dnsx import DnsxModule
    from allscan.whois_rdap import WhoisModule
    from allscan.asn import AsnModule
    from allscan.certs import CertsModule
    from allscan.email_sec import EmailModule
    from allscan.scan import ScanModule
    from allscan.web import WebModule
    from allscan.fingerprint import FingerprintModule
    from allscan.headers import HeadersModule
    from allscan.tls import TlsModule
    from allscan.cloud import CloudModule
    from allscan.waf import WafModule
    from allscan.integrations import IntegrationsModule
    from allscan.active import ActiveModule
    from allscan.vulns import VulnsModule
    from allscan.exploitrefs import ExploitRefsModule
    from allscan.vulnintel import VulnIntelModule
    from allscan.surface import SurfaceModule
    from allscan.threatmodel import ThreatModelModule
    from allscan.compliance import ComplianceModule

    instances = [
        NetDiscoverModule(),
        ReconModule(),
        DnsxModule(),
        WhoisModule(),
        AsnModule(),
        CertsModule(),
        EmailModule(),
        ScanModule(),
        WebModule(),
        FingerprintModule(),
        HeadersModule(),
        TlsModule(),
        CloudModule(),
        WafModule(),
        IntegrationsModule(),
        ActiveModule(),
        VulnsModule(),
        ExploitRefsModule(),
        VulnIntelModule(),
        SurfaceModule(),
        ThreatModelModule(),
        ComplianceModule(),
    ]
    return {m.name: m for m in instances}
