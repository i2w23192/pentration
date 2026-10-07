"""Threat-model & compliance mapping (pure, data-driven).

Maps a finding to:

* **MITRE ATT&CK** — a tactic + technique (id/name),
* **STRIDE** — one or more threat categories,
* **Compliance references** — OWASP, CWE, NIST 800-53, CIS, PCI DSS pointers,
* a **risk cell** — (severity, likelihood) for a risk matrix, where likelihood
  is raised by KEV / high EPSS / active-confirmation / high confidence.

Everything here is a lookup over a finding's category, its ``evidence['type']``
(for active findings) and a few title keywords — no network, no side effects —
so it is trivially unit-testable and reused by both the module and the report.
"""

from __future__ import annotations

from typing import Any

from allscan.models import Category, Severity

# category -> (tactic, technique_id, technique_name)
_ATTACK_BY_CATEGORY = {
    Category.NETWORK: ("Reconnaissance", "T1595", "Active Scanning"),
    Category.SUBDOMAIN: ("Reconnaissance", "T1590.002", "Gather Victim Network Info: DNS"),
    Category.DNS: ("Reconnaissance", "T1590.002", "Gather Victim Network Info: DNS"),
    Category.WHOIS: ("Reconnaissance", "T1590", "Gather Victim Network Information"),
    Category.ASN: ("Reconnaissance", "T1590.005", "Gather Victim Network Info: IP Addresses"),
    Category.CERT: ("Reconnaissance", "T1596.003", "Search Open Technical DBs: Digital Certs"),
    Category.PORT: ("Reconnaissance", "T1595.001", "Active Scanning: Scanning IP Blocks"),
    Category.SERVICE: ("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    Category.WEB: ("Reconnaissance", "T1595.003", "Active Scanning: Wordlist Scanning"),
    Category.FINGERPRINT: ("Reconnaissance", "T1592.002", "Gather Victim Host Info: Software"),
    Category.HEADER: ("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    Category.HTML: ("Collection", "T1552.001", "Unsecured Credentials: Credentials in Files"),
    Category.TLS: ("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    Category.CLOUD: ("Collection", "T1530", "Data from Cloud Storage"),
    Category.WAF: ("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    Category.EMAIL: ("Reconnaissance", "T1589.002", "Gather Victim Identity Info: Email"),
    Category.CVE: ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    Category.EXPLOITREF: ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    Category.MISCONFIG: ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    Category.SURFACE: ("Reconnaissance", "T1590", "Gather Victim Network Information"),
}

# active finding type -> (tactic, technique_id, technique_name)
_ATTACK_BY_TYPE = {
    "sql-injection": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "reflected-input": ("Initial Access", "T1059.007", "Command & Scripting: JavaScript"),
    "open-redirect": ("Initial Access", "T1566.002", "Phishing: Spearphishing Link"),
    "cors-misconfig": ("Collection", "T1119", "Automated Collection"),
    "host-header-injection": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "directory-listing": ("Discovery", "T1083", "File and Directory Discovery"),
    "jwt-analysis": ("Credential Access", "T1552", "Unsecured Credentials"),
}

# keyword in title/type -> STRIDE letters
_STRIDE_RULES = [
    ("spf", "S"), ("dkim", "S"), ("dmarc", "S"), ("open redirect", "S"),
    ("open-redirect", "S"), ("host header", "ST"), ("host-header", "ST"),
    ("cors", "SI"), ("sql", "TID"), ("injection", "TI"), ("reflected", "T"),
    ("xss", "T"), ("csp", "T"), ("x-frame", "T"), ("clickjack", "T"),
    ("tls", "I"), ("cipher", "I"), ("certificate", "I"), ("secret", "I"),
    ("credential", "IE"), ("api key", "I"), ("token", "I"), ("bucket", "I"),
    ("directory listing", "I"), ("dnssec", "ST"), ("default login", "E"),
    ("anonymous ftp", "E"), ("jwt", "SE"), ("exposed", "I"),
]
_STRIDE_NAMES = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                 "I": "Information Disclosure", "D": "Denial of Service",
                 "E": "Elevation of Privilege"}

# category/keyword -> compliance references
_COMPLIANCE_BY_CATEGORY = {
    Category.HEADER: {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-693",
                      "nist": "SC-8/SI-10", "cis": "CIS 16", "pci": "PCI 6.5.10"},
    Category.TLS: {"owasp": "A02:2021 Cryptographic Failures", "cwe": "CWE-326/327",
                   "nist": "SC-8/SC-13", "cis": "CIS 3.10", "pci": "PCI 4.2.1"},
    Category.HTML: {"owasp": "A02:2021 Cryptographic Failures", "cwe": "CWE-312/798",
                    "nist": "IA-5", "cis": "CIS 3.11", "pci": "PCI 6.5.3"},
    Category.EMAIL: {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-290",
                     "nist": "SC-8 / 800-177", "cis": "CIS 9", "pci": "PCI 5"},
    Category.CVE: {"owasp": "A06:2021 Vulnerable & Outdated Components", "cwe": "CWE-1035",
                   "nist": "RA-5/SI-2", "cis": "CIS 7", "pci": "PCI 6.3.3"},
    Category.EXPLOITREF: {"owasp": "A06:2021 Vulnerable & Outdated Components",
                          "cwe": "CWE-1035", "nist": "RA-5/SI-2", "cis": "CIS 7", "pci": "PCI 6.3.3"},
    Category.CLOUD: {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-284",
                     "nist": "AC-3/AC-6", "cis": "CIS 3", "pci": "PCI 7"},
    Category.MISCONFIG: {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-16",
                         "nist": "CM-6", "cis": "CIS 4", "pci": "PCI 2.2"},
}
_COMPLIANCE_BY_TYPE = {
    "sql-injection": {"owasp": "A03:2021 Injection", "cwe": "CWE-89",
                      "nist": "SI-10", "cis": "CIS 16.11", "pci": "PCI 6.5.1"},
    "reflected-input": {"owasp": "A03:2021 Injection", "cwe": "CWE-79",
                        "nist": "SI-10", "cis": "CIS 16.11", "pci": "PCI 6.5.7"},
    "open-redirect": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-601",
                      "nist": "SC-7", "cis": "CIS 16", "pci": "PCI 6.5.8"},
    "cors-misconfig": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-942",
                       "nist": "AC-4", "cis": "CIS 16", "pci": "PCI 6.5.8"},
    "host-header-injection": {"owasp": "A03:2021 Injection", "cwe": "CWE-644",
                              "nist": "SI-10", "cis": "CIS 16", "pci": "PCI 6.5.1"},
    "directory-listing": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-548",
                          "nist": "CM-6", "cis": "CIS 4", "pci": "PCI 6.5.8"},
}


def _as_dict(finding) -> dict:
    return finding if isinstance(finding, dict) else finding.to_dict()


def attack(finding) -> dict[str, str]:
    fd = _as_dict(finding)
    ftype = (fd.get("evidence") or {}).get("type", "")
    if ftype in _ATTACK_BY_TYPE:
        t = _ATTACK_BY_TYPE[ftype]
    else:
        t = _ATTACK_BY_CATEGORY.get(fd.get("category", ""),
                                    ("Reconnaissance", "T1595", "Active Scanning"))
    return {"tactic": t[0], "technique_id": t[1], "technique": t[2]}


def stride(finding) -> list[str]:
    fd = _as_dict(finding)
    hay = (fd.get("title", "") + " " + str((fd.get("evidence") or {}).get("type", ""))
           + " " + fd.get("category", "")).lower()
    letters: set[str] = set()
    for kw, codes in _STRIDE_RULES:
        if kw in hay:
            letters.update(codes)
    return [_STRIDE_NAMES[c] for c in "STRIDE" if c in letters]


def compliance_refs(finding) -> dict[str, str]:
    fd = _as_dict(finding)
    ftype = (fd.get("evidence") or {}).get("type", "")
    if ftype in _COMPLIANCE_BY_TYPE:
        return dict(_COMPLIANCE_BY_TYPE[ftype])
    refs = dict(_COMPLIANCE_BY_CATEGORY.get(fd.get("category", ""), {}))
    # pull a CWE straight from CVE evidence if present
    return refs


def likelihood(finding) -> str:
    """Heuristic likelihood for the risk matrix: high / medium / low."""
    fd = _as_dict(finding)
    ev = fd.get("evidence") or {}
    conf = (fd.get("confidence") or "").lower()
    if ev.get("kev") is True:
        return "high"
    epss = ev.get("epss")
    if isinstance(epss, (int, float)) and epss >= 0.5:
        return "high"
    if conf == "high":
        return "high"
    if conf == "medium" or (isinstance(epss, (int, float)) and epss >= 0.1):
        return "medium"
    # a confirmed active finding is at least medium likelihood
    if fd.get("category") == Category.ACTIVE:
        return "medium"
    return "low"


def risk_cell(finding) -> tuple[str, str]:
    fd = _as_dict(finding)
    sev = fd.get("severity", "info")
    return sev, likelihood(finding)


def risk_matrix(findings) -> dict[str, dict[str, int]]:
    """Return counts[severity][likelihood]."""
    sevs = ["high", "medium", "low", "info"]
    likes = ["high", "medium", "low"]
    matrix = {s: {l: 0 for l in likes} for s in sevs}
    for f in findings:
        s, l = risk_cell(f)
        if s in matrix and l in matrix[s]:
            matrix[s][l] += 1
    return matrix


def summarize_mappings(findings) -> dict[str, Any]:
    """Aggregate ATT&CK techniques, STRIDE spread and compliance frameworks hit."""
    techniques: dict[str, dict] = {}
    stride_counts: dict[str, int] = {}
    frameworks: dict[str, set] = {}
    for f in findings:
        a = attack(f)
        key = a["technique_id"]
        entry = techniques.setdefault(key, {"technique_id": key,
                                            "technique": a["technique"],
                                            "tactic": a["tactic"], "count": 0})
        entry["count"] += 1
        for s in stride(f):
            stride_counts[s] = stride_counts.get(s, 0) + 1
        for fw, ref in compliance_refs(f).items():
            frameworks.setdefault(fw, set()).add(ref)
    return {
        "attack_techniques": sorted(techniques.values(), key=lambda x: -x["count"]),
        "stride": stride_counts,
        "compliance_frameworks": {k: sorted(v) for k, v in frameworks.items()},
    }
