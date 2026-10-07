"""Shared data models for allscan.

Everything a scan produces is represented as a :class:`Finding` and collected
into a :class:`ScanResult`. Both are plain dataclasses with ``to_dict`` /
``from_dict`` helpers so results round-trip cleanly through JSON — which is
what the reporting and diff features rely on.
"""

from __future__ import annotations

import dataclasses
import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


class Severity(enum.Enum):
    """Severity ranking for a finding. Order matters for sorting/coloring."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3}[self.value]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls(value.lower())

    def __lt__(self, other: "Severity") -> bool:  # enables sorting
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


# Logical grouping for the results screen. Kept as plain strings so new
# modules can introduce categories without touching an enum.
class Category:
    SUBDOMAIN = "subdomains"
    DNS = "dns"
    PORT = "ports"
    SERVICE = "services"
    WEB = "web"
    HEADER = "headers"
    HTML = "html"
    TLS = "tls"
    CVE = "cves"
    MISCONFIG = "misconfigs"

    ALL = (
        SUBDOMAIN,
        DNS,
        PORT,
        SERVICE,
        WEB,
        HEADER,
        HTML,
        TLS,
        CVE,
        MISCONFIG,
    )


@dataclass
class Finding:
    """A single observation produced by a module.

    ``evidence`` is free-form structured data (ports, headers, cert fields …);
    it is never interpreted by the core, only displayed and serialized.
    """

    category: str
    title: str
    severity: Severity = Severity.INFO
    target: str = ""
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    module: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity.value,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "module": self.module,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            id=data.get("id", uuid.uuid4().hex[:12]),
            category=data["category"],
            title=data["title"],
            severity=Severity.from_str(data.get("severity", "info")),
            target=data.get("target", ""),
            description=data.get("description", ""),
            evidence=data.get("evidence", {}) or {},
            module=data.get("module", ""),
            timestamp=data.get("timestamp", time.time()),
        )

    def dedupe_key(self) -> tuple:
        """Key used to collapse identical findings across modules/reruns."""
        return (self.category, self.target, self.title)


@dataclass
class ScanResult:
    """Everything one invocation of allscan produced, for one target."""

    target: str
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    modules_run: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    partial: bool = False  # set when a scan was cancelled mid-run
    meta: dict[str, Any] = field(default_factory=dict)

    # --- mutation helpers -------------------------------------------------
    def add(self, finding: Finding) -> Finding:
        """Add a finding, collapsing exact duplicates and keeping the max sev."""
        key = finding.dedupe_key()
        for existing in self.findings:
            if existing.dedupe_key() == key:
                if finding.severity.rank > existing.severity.rank:
                    existing.severity = finding.severity
                # merge evidence without clobbering
                for k, v in finding.evidence.items():
                    existing.evidence.setdefault(k, v)
                return existing
        self.findings.append(finding)
        return finding

    def extend(self, findings: list[Finding]) -> None:
        for f in findings:
            self.add(f)

    # --- queries ----------------------------------------------------------
    def by_category(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        for lst in out.values():
            lst.sort(key=lambda x: (-x.severity.rank, x.title))
        return out

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def duration(self) -> float:
        end = self.finished_at or time.time()
        return max(0.0, end - self.started_at)

    # --- serialization ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "allscan_version": _version(),
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "modules_run": self.modules_run,
            "partial": self.partial,
            "meta": self.meta,
            "severity_counts": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        r = cls(
            target=data["target"],
            started_at=data.get("started_at", time.time()),
            finished_at=data.get("finished_at"),
            modules_run=data.get("modules_run", []),
            partial=data.get("partial", False),
            meta=data.get("meta", {}) or {},
        )
        r.findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        return r


def _version() -> str:
    try:
        from allscan import __version__

        return __version__
    except Exception:  # pragma: no cover - defensive
        return "0"


def asdict(obj: Any) -> Any:
    """Thin wrapper so callers don't import dataclasses just for this."""
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    return obj
