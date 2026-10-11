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
    "modules": [
        "netdiscover", "recon", "dnsx", "whois", "asn", "certs", "email",
        "scan", "web", "fingerprint", "headers", "tls", "cloud", "waf",
        "integrations", "active", "vulns", "exploitrefs", "vulnintel",
        "surface", "threatmodel", "compliance",
    ],
    "integrations": [],           # external scanner wrappers to enable (opt-in)
    "host_discovery_cidr": None,   # explicit CIDR for ping sweep; None -> /24 of target
    "host_discovery_max": 256,     # cap hosts swept in one run
    # --- active probing (detection-only; all off by default) ------------
    "active": False,               # master switch for active probing (--active)
    "scope_allow": [],             # extra in-scope hosts/domains/CIDRs
    "scope_deny": [],              # always-blocked hosts/domains/CIDRs (wins)
    "allow_production": False,     # silence the production-target warning
    "active_max_concurrency": 8,   # active-only worker cap (<= threads)
    "active_max_urls": 25,         # cap probed URLs per run
    "active_max_params": 6,        # cap probed params per URL
    "active_stop_after_errors": 25,  # auto-stop after N consecutive request errors
    "output_dir": "allscan-results",
    "wordlist_subdomains": None,  # path; None -> built-in small list
    "wordlist_web": None,         # path; None -> built-in small list
    "user_agent": "allscan/1.0 (authorized security testing)",
    "proxy": None,                # route all outbound HTTP through this proxy (http/https/socks5)
    "extra_headers": {},          # custom headers merged into in-scope requests
    "cookie": None,               # Cookie header for authenticated in-scope requests
    "auth_bearer": None,          # Authorization: Bearer <token> for in-scope requests
    "auth_basic": None,           # user:pass -> Authorization: Basic for in-scope requests
    "nvd_api_key": None,          # optional NVD API key for higher rate limits
    "cve_sources": ["nvd", "circl"],  # CVE data sources to query (nvd, circl)
    "exploitdb_csv": None,        # optional local ExploitDB files_exploits.csv for EDB-ID refs
    # --- vuln intelligence (business-impact scoring + FP management) ----
    "default_criticality": "medium",   # asset criticality when unspecified
    "asset_criticality": {},      # {host_substring: low|medium|high|critical}
    "suppress_fingerprints": [],  # finding fingerprints to mark as false-positive
    "pdf": False,                 # also emit a ReportLab PDF report
    "projects_dir": "allscan-projects",  # engagement/project store location
    "discord_webhook": None,      # send JSON+HTML reports to this Discord webhook
    "dns_resolvers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    "max_subdomains_bruteforce": 2000,
    "follow_redirects": True,
    "verify_tls": False,          # recon tools routinely hit self-signed hosts
}

MODULE_LABELS = {
    "netdiscover": "Network/Host Discovery",
    "recon": "Subdomain Discovery",
    "dnsx": "DNS Deep-Dive",
    "whois": "WHOIS / RDAP",
    "asn": "ASN / IP-range Discovery",
    "certs": "Certificate / CT-log Discovery",
    "email": "Email Security (SPF/DKIM/DMARC)",
    "scan": "Port/Service Scan",
    "web": "Web Enumeration",
    "fingerprint": "API & Tech Fingerprinting",
    "headers": "HTML/Header Analysis",
    "tls": "SSL/TLS Deep Audit",
    "cloud": "Cloud Exposure",
    "waf": "WAF/CDN & Rate-limit Detection",
    "integrations": "Scanner Integrations",
    "active": "Active Probing (detection)",
    "vulns": "CVE Correlation",
    "exploitrefs": "Exploit-Reference Enrichment",
    "vulnintel": "Vuln Intelligence & Risk Scoring",
    "surface": "Attack-Surface Mapping",
    "threatmodel": "Threat Model & Compliance Mapping",
    "compliance": "Compliance Checklist",
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
    proxy: Optional[str] = DEFAULTS["proxy"]
    extra_headers: dict = field(default_factory=lambda: dict(DEFAULTS["extra_headers"]))
    cookie: Optional[str] = DEFAULTS["cookie"]
    auth_bearer: Optional[str] = DEFAULTS["auth_bearer"]
    auth_basic: Optional[str] = DEFAULTS["auth_basic"]
    nvd_api_key: Optional[str] = DEFAULTS["nvd_api_key"]
    cve_sources: list[str] = field(default_factory=lambda: list(DEFAULTS["cve_sources"]))
    exploitdb_csv: Optional[str] = DEFAULTS["exploitdb_csv"]
    default_criticality: str = DEFAULTS["default_criticality"]
    asset_criticality: dict = field(default_factory=lambda: dict(DEFAULTS["asset_criticality"]))
    suppress_fingerprints: list[str] = field(default_factory=lambda: list(DEFAULTS["suppress_fingerprints"]))
    pdf: bool = DEFAULTS["pdf"]
    projects_dir: str = DEFAULTS["projects_dir"]
    discord_webhook: Optional[str] = DEFAULTS["discord_webhook"]
    dns_resolvers: list[str] = field(default_factory=lambda: list(DEFAULTS["dns_resolvers"]))
    max_subdomains_bruteforce: int = DEFAULTS["max_subdomains_bruteforce"]
    follow_redirects: bool = DEFAULTS["follow_redirects"]
    verify_tls: bool = DEFAULTS["verify_tls"]
    host_discovery_cidr: Optional[str] = DEFAULTS["host_discovery_cidr"]
    host_discovery_max: int = DEFAULTS["host_discovery_max"]
    active: bool = DEFAULTS["active"]
    scope_allow: list[str] = field(default_factory=lambda: list(DEFAULTS["scope_allow"]))
    scope_deny: list[str] = field(default_factory=lambda: list(DEFAULTS["scope_deny"]))
    allow_production: bool = DEFAULTS["allow_production"]
    active_max_concurrency: int = DEFAULTS["active_max_concurrency"]
    active_max_urls: int = DEFAULTS["active_max_urls"]
    active_max_params: int = DEFAULTS["active_max_params"]
    active_stop_after_errors: int = DEFAULTS["active_stop_after_errors"]
    integrations: list[str] = field(default_factory=lambda: list(DEFAULTS["integrations"]))

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
            try:
                loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise ValueError(f"Config file {cfg_path} is not valid YAML: {exc}") from exc
            if not isinstance(loaded, dict):
                raise ValueError(f"Config file {cfg_path} must contain a mapping.")
            data.update({k: v for k, v in loaded.items() if k in DEFAULTS})
        _coerce(data)
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

    #: fields whose values are secrets and must never be logged/printed
    SECRET_FIELDS = ("proxy", "cookie", "auth_bearer", "auth_basic",
                     "nvd_api_key", "discord_webhook", "extra_headers")

    def to_audit_dict(self) -> dict[str, Any]:
        """Config dump with secret values masked, for the audit log."""
        d = dataclasses.asdict(self)
        for key in self.SECRET_FIELDS:
            if d.get(key):
                d[key] = "***"
        return d

    def output_path(self) -> Path:
        """Return a writable output directory, falling back when the configured
        one can't be created (e.g. a relative dir under an unwritable CWD such
        as C:\\Windows\\System32). The resolved path is remembered so every
        later save uses the same place."""
        p = Path(self.output_dir).expanduser()
        candidates = [p]
        # fall back to the user's home, then the system temp dir
        name = p.name or "allscan-results"
        candidates.append(Path.home() / name)
        import tempfile
        candidates.append(Path(tempfile.gettempdir()) / name)
        last_err: Exception | None = None
        for cand in candidates:
            try:
                cand.mkdir(parents=True, exist_ok=True)
                # confirm we can actually write here
                probe = cand / ".allscan_write_test"
                probe.write_text("", encoding="utf-8")
                probe.unlink()
                self.output_dir = str(cand)  # persist the working location
                return cand
            except (PermissionError, OSError) as exc:
                last_err = exc
                continue
        # nothing worked — re-raise the last error with context
        raise PermissionError(
            f"Could not create a writable output directory (tried: "
            f"{', '.join(str(c) for c in candidates)})") from last_err


def _field_names() -> set[str]:
    return {f.name for f in dataclasses.fields(Config)}


_INT_FIELDS = ("threads", "host_discovery_max", "max_subdomains_bruteforce",
               "active_max_concurrency", "active_max_urls", "active_max_params",
               "active_stop_after_errors")
_FLOAT_FIELDS = ("rate_limit", "timeout")


def _coerce(data: dict) -> None:
    """Coerce numeric config values (e.g. from YAML strings); fall back to the
    default on a bad value rather than letting it blow up later."""
    for key in _INT_FIELDS:
        try:
            data[key] = int(data[key])
        except (TypeError, ValueError):
            data[key] = DEFAULTS[key]
    for key in _FLOAT_FIELDS:
        try:
            data[key] = float(data[key])
        except (TypeError, ValueError):
            data[key] = DEFAULTS[key]
    if not isinstance(data.get("modules"), list):
        data["modules"] = list(DEFAULTS["modules"])
    if not isinstance(data.get("extra_headers"), dict):
        data["extra_headers"] = {}


def _resolve_config_path(path: Optional[str]) -> Optional[Path]:
    if path:
        if path in ("example", "config.example.yaml"):
            from allscan.utils import resource_path
            return resource_path("config.example.yaml")
        return Path(path).expanduser()
    for candidate in ("config.yaml", "config.yml"):
        p = Path(candidate)
        if p.exists():
            return p
    return None
