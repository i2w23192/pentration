"""Scope enforcement — a hard safety control for active probing.

Before allscan sends *any* active (request-to-confirm) probe, the destination
host is checked against an explicit scope:

* **In scope by default** — the engagement target and its subdomains, plus the
  target's resolved IP(s).
* **Allowlist** — extra hosts / domains / CIDRs explicitly permitted.
* **Denylist** — hosts / domains / CIDRs that are always blocked, even if they
  would otherwise match (denylist wins).

A host that is not in scope is *blocked* — the active modules must call
:meth:`ScopeGuard.check` and skip anything that returns ``False``. The guard
also classifies whether a host looks like production infrastructure so callers
can surface a warning.

Everything here is read-only policy evaluation; it performs no network I/O
except an optional one-shot DNS resolve of the target to seed its IP scope.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field


def _norm_host(value: str) -> str:
    value = (value or "").strip().lower()
    value = value.split("://", 1)[-1]
    value = value.split("/", 1)[0]
    value = value.split("@", 1)[-1]
    if value.startswith("[") and "]" in value:  # [ipv6]
        return value[1:value.index("]")]
    if value.count(":") == 1:  # host:port (not ipv6)
        host, _, port = value.partition(":")
        if port.isdigit():
            value = host
    return value.strip(".")


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    host: str


@dataclass
class ScopeGuard:
    target: str
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    _target_ips: set[str] = field(default_factory=set, init=False)
    _nets: list = field(default_factory=list, init=False)   # (kind, value) parsed allow
    _deny_nets: list = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self.target = _norm_host(self.target)
        # seed target IPs (best-effort; failure just means IP scope is empty)
        try:
            for info in socket.getaddrinfo(self.target, None):
                self._target_ips.add(info[4][0])
        except Exception:
            pass
        self._nets = [self._parse(x) for x in ([self.target] + list(self.allow))]
        self._deny_nets = [self._parse(x) for x in self.deny]

    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse(entry: str):
        entry = (entry or "").strip().lower()
        if not entry:
            return ("host", "")
        try:
            return ("net", ipaddress.ip_network(entry, strict=False))
        except ValueError:
            return ("host", _norm_host(entry))

    def _matches(self, parsed, host: str, ips: set[str]) -> bool:
        kind, value = parsed
        if kind == "net":
            for ip in ips:
                try:
                    if ipaddress.ip_address(ip) in value:
                        return True
                except ValueError:
                    continue
            return False
        if not value:
            return False
        # exact host or subdomain of an allowed domain
        return host == value or host.endswith("." + value)

    def _resolve(self, host: str) -> set[str]:
        ips: set[str] = set()
        try:
            ipaddress.ip_address(host)
            ips.add(host)
            return ips
        except ValueError:
            pass
        try:
            for info in socket.getaddrinfo(host, None):
                ips.add(info[4][0])
        except Exception:
            pass
        return ips

    # ------------------------------------------------------------------ #
    def decide(self, target: str) -> ScopeDecision:
        host = _norm_host(target)
        if not host:
            return ScopeDecision(False, "empty host", host)
        ips = self._resolve(host)
        # denylist always wins
        for d in self._deny_nets:
            if self._matches(d, host, ips):
                return ScopeDecision(False, f"host '{host}' is on the denylist", host)
        for a in self._nets:
            if self._matches(a, host, ips):
                return ScopeDecision(True, "in scope", host)
        return ScopeDecision(False, f"host '{host}' is out of scope", host)

    def check(self, target: str) -> bool:
        """Convenience boolean form of :meth:`decide`."""
        return self.decide(target).allowed

    # ------------------------------------------------------------------ #
    def looks_production(self) -> bool:
        """Heuristic: is the target likely production (not lab/local/private)?"""
        host = self.target
        lab_suffixes = (".test", ".local", ".localhost", ".example",
                        ".invalid", ".internal")
        if host in ("localhost", "127.0.0.1", "::1"):
            return False
        if any(host.endswith(s) for s in lab_suffixes):
            return False
        # any public (non-private) resolved IP => treat as production
        ips = self._target_ips or self._resolve(host)
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
                if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                    return True
            except ValueError:
                continue
        # If we could not resolve any IP, be cautious and assume production.
        return not ips
