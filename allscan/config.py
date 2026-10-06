"""Configuration handling for allscan.

Settings have three layers, highest priority last:

1. built-in defaults (:data:`DEFAULTS`)
2. a YAML config file (``--config`` or ``config.yaml`` in CWD)
3. CLI flags / TUI settings screen

The :class:`Config` dataclass is the single object threaded through every
module, so adding an option is a one-line change here.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - yaml is a declared dependency
    yaml = None


# Reasonable, deliberately polite defaults. Rate limit and thread count are
# tuned to avoid hammering a target out of the box.
DEFAULTS: dict[str, Any] = {
    "threads": 20,
    "rate_limit": 10.0,            # requests/sec, global budget
    "timeout": 8.0,               # seconds per network op
    "full_ports": False,          # scan all 65535 ports
    "skip_nmap": False,           # skip nmap, fall back to banner grabbing
    "os_detection": False,        # nmap -O (needs privileges)
    "modules": ["recon", "scan", "web", "headers", "vulns"],
    "output_dir": "allscan-results",
    "wordlist_subdomains": None,  # path; None -> built-in small list
    "wordlist_web": None,         # path; None -> built-in small list
    "user_agent": "allscan/1.0 (authorized security testing)",
    "nvd_api_key": None,          # optional NVD API key for higher rate limits
    "dns_resolvers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    "max_subdomains_bruteforce": 2000,
    "follow_redirects": True,
    "verify_tls": False,          # recon tools routinely hit self-signed hosts
}

MODULE_LABELS = {
    "recon": "Subdomain Discovery",
    "scan": "Port/Service Scan",
    "web": "Web Enumeration",
    "headers": "HTML/Header Analysis",
    "vulns": "CVE Correlation",
}


@dataclass
class Config:
    threads: int = DEFAULTS["threads"]
    rate_limit: float = DEFAULTS["rate_limit"]
    timeout: float = DEFAULTS["timeout"]
    full_ports: bool = DEFAULTS["full_ports"]
    skip_nmap: bool = DEFAULTS["skip_nmap"]
    os_detection: bool = DEFAULTS["os_detection"]
    modules: list[str] = field(default_factory=lambda: list(DEFAULTS["modules"]))
    output_dir: str = DEFAULTS["output_dir"]
    wordlist_subdomains: Optional[str] = DEFAULTS["wordlist_subdomains"]
    wordlist_web: Optional[str] = DEFAULTS["wordlist_web"]
    user_agent: str = DEFAULTS["user_agent"]
    nvd_api_key: Optional[str] = DEFAULTS["nvd_api_key"]
    dns_resolvers: list[str] = field(default_factory=lambda: list(DEFAULTS["dns_resolvers"]))
    max_subdomains_bruteforce: int = DEFAULTS["max_subdomains_bruteforce"]
    follow_redirects: bool = DEFAULTS["follow_redirects"]
    verify_tls: bool = DEFAULTS["verify_tls"]

    # --- construction helpers --------------------------------------------
    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        """Load defaults, overlaying a YAML file if present."""
        data = dict(DEFAULTS)
        cfg_path = _resolve_config_path(path)
        if cfg_path and cfg_path.exists():
            if yaml is None:
                raise RuntimeError(
                    "PyYAML is required to read a config file but is not installed."
                )
            loaded = yaml.safe_load(cfg_path.read_text()) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"Config file {cfg_path} must contain a mapping.")
            data.update({k: v for k, v in loaded.items() if k in DEFAULTS})
        return cls(**{k: data[k] for k in data if k in _field_names()})

    def apply_overrides(self, **overrides) -> "Config":
        """Return a copy with non-None overrides applied (CLI/TUI layer)."""
        clone = dataclasses.replace(self)
        for key, value in overrides.items():
            if value is None:
                continue
            if hasattr(clone, key):
                setattr(clone, key, value)
        return clone

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    def output_path(self) -> Path:
        p = Path(self.output_dir).expanduser()
        p.mkdir(parents=True, exist_ok=True)
        return p


def _field_names() -> set[str]:
    return {f.name for f in dataclasses.fields(Config)}


def _resolve_config_path(path: Optional[str]) -> Optional[Path]:
    if path:
        return Path(path).expanduser()
    for candidate in ("config.yaml", "config.yml"):
        p = Path(candidate)
        if p.exists():
            return p
    return None
