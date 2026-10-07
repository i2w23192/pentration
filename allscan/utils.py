"""Cross-cutting helpers: rate limiting, audit logging, target validation.

These are intentionally dependency-light so every backend module can import
them without pulling in the TUI stack.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Callable, Iterable, Optional


# --------------------------------------------------------------------------- #
# Target validation
# --------------------------------------------------------------------------- #

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def normalize_target(value: str) -> str:
    """Strip scheme/path/port noise a user might paste in."""
    value = value.strip()
    value = re.sub(r"^[a-zA-Z]+://", "", value)  # drop scheme
    value = value.split("/", 1)[0]  # drop path
    value = value.split("?", 1)[0]
    # keep bracketed IPv6, otherwise trim a trailing :port
    if not value.startswith("[") and value.count(":") == 1:
        host, _, maybe_port = value.partition(":")
        if maybe_port.isdigit():
            value = host
    return value.strip().strip(".").lower()


def validate_target(value: str) -> tuple[bool, str]:
    """Return (ok, message). Message explains the failure when not ok."""
    norm = normalize_target(value)
    if not norm:
        return False, "Target is empty."
    if is_ip(norm) or is_domain(norm):
        return True, norm
    return (
        False,
        f"'{value}' is not a valid domain or IP address.",
    )


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #


class RateLimiter:
    """Simple thread-safe limiter: at most ``rate`` acquisitions per second.

    ``rate <= 0`` disables limiting entirely. The implementation is a minimal
    token-ish gate using a monotonic clock, shared across threads so that the
    whole tool honours one global budget against the target.
    """

    def __init__(self, rate: float):
        self.rate = float(rate)
        self._interval = 1.0 / self.rate if self.rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next_at = 0.0

    def acquire(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next_at - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._next_at = max(now, self._next_at) + self._interval

    def __call__(self) -> None:
        self.acquire()


# --------------------------------------------------------------------------- #
# Audit logging
# --------------------------------------------------------------------------- #


class AuditLog:
    """Append-only JSONL audit trail written alongside scan output.

    Every outbound action a module takes (DNS query, HTTP request, nmap
    invocation …) should be recorded here so a run is fully reconstructable
    after the fact — a requirement for responsible authorized testing.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._fh = None
        self._logger = logging.getLogger("allscan.audit")
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("a", encoding="utf-8")

    def record(self, action: str, target: str = "", **fields) -> None:
        entry = {
            "ts": time.time(),
            "action": action,
            "target": target,
            **fields,
        }
        line = json.dumps(entry, default=str)
        with self._lock:
            if self._fh is not None:
                self._fh.write(line + "\n")
                self._fh.flush()
        self._logger.debug("audit %s", line)

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# Progress / cancellation plumbing
# --------------------------------------------------------------------------- #

# A log callback receives (module_name, message) lines for the live TUI log.
LogFn = Callable[[str, str], None]
# A finding callback is called once per Finding as modules discover them.
from allscan.models import Finding  # noqa: E402  (placed late to avoid cycle)

FindingFn = Callable[[Finding], None]


class CancelToken:
    """Cooperative cancellation shared with every module.

    Modules must poll :meth:`cancelled` in their loops so Ctrl+C / a Stop key
    can halt work and let the orchestrator save partial results.
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise ScanCancelled()


class ScanCancelled(Exception):
    """Raised cooperatively when a scan is cancelled."""


# --------------------------------------------------------------------------- #
# Misc
# --------------------------------------------------------------------------- #


def chunked(seq: Iterable, size: int):
    buf = []
    for item in seq:
        buf.append(item)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def dedupe_preserve(seq: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


_SECRET_PATTERNS = [
    # (label, compiled regex). Patterns are intentionally conservative to keep
    # false positives low; they look for the shape of common credentials.
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Generic Private Key", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Generic API key assignment", re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token|password|passwd)\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]")),
    ("Bearer token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}")),
]


def scan_for_secrets(text: str) -> list[tuple[str, str]]:
    """Return a list of (label, matched_snippet) for secret-shaped substrings.

    Snippets are truncated so the audit/report never stores a full credential
    verbatim; enough is kept to let an analyst locate the source.
    """
    hits: list[tuple[str, str]] = []
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            snippet = m.group(0)
            if len(snippet) > 48:
                snippet = snippet[:20] + "…" + snippet[-8:]
            hits.append((label, snippet))
    # dedupe identical (label, snippet) pairs
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out
