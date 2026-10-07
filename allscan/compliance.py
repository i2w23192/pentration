"""Compliance / best-practice checklist roll-up.

Runs last in the chain and rolls up findings from every other module into a
pass / fail / warn checklist against common baselines:

* OWASP Secure Headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy) and cookie flags
* Basic TLS hygiene (no deprecated protocols, valid + unexpired chain)
* Email authentication (SPF / DMARC / DKIM, DMARC not monitor-only)
* DNS hygiene (DNSSEC, CAA, no zone transfer)
* Exposure hygiene (no exposed secrets, no public buckets, no directory
  listing, no anonymous FTP)

The checklist is emitted as findings (one per failed/warn item plus a summary)
and stashed in ``ctx.state['compliance']`` so the report generator can render a
dedicated section. The evaluation is a pure function, :func:`evaluate`, so the
report module can reuse it.
"""

from __future__ import annotations

from typing import Any

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity

PASS, FAIL, WARN, NA = "pass", "fail", "warn", "n/a"


def _has(findings, *, category=None, title_contains=None) -> bool:
    for f in findings:
        fd = f if isinstance(f, dict) else f.to_dict()
        if category and fd.get("category") != category:
            continue
        if title_contains:
            title = (fd.get("title") or "").lower()
            if title_contains.lower() not in title:
                continue
        return True
    return False


def evaluate(findings: list) -> list[dict[str, Any]]:
    """Pure roll-up: list of {id, name, baseline, status, detail}."""
    rows: list[dict[str, Any]] = []

    def row(id_, name, baseline, status, detail):
        rows.append({"id": id_, "name": name, "baseline": baseline,
                     "status": status, "detail": detail})

    # --- OWASP secure headers ---------------------------------------------
    header_map = {
        "Content-Security-Policy": "content-security-policy",
        "HSTS (Strict-Transport-Security)": "strict-transport-security",
        "X-Content-Type-Options": "x-content-type-options",
        "X-Frame-Options": "x-frame-options",
        "Referrer-Policy": "referrer-policy",
        "Permissions-Policy": "permissions-policy",
    }
    for name, header in header_map.items():
        missing = _has(findings, category=Category.HEADER,
                       title_contains=f"missing {header}")
        row(f"hdr_{header}", name, "OWASP Secure Headers",
            FAIL if missing else PASS,
            "Header missing on at least one endpoint." if missing else "Present.")

    cookie_issue = _has(findings, category=Category.HEADER, title_contains="cookie '")
    row("cookie_flags", "Cookie security flags (Secure/HttpOnly/SameSite)",
        "OWASP Session Mgmt", WARN if cookie_issue else PASS,
        "One or more cookies miss recommended flags." if cookie_issue else "OK / no cookies set.")

    # --- TLS hygiene -------------------------------------------------------
    deprecated_tls = _has(findings, category=Category.TLS, title_contains="deprecated protocol accepted") \
        or _has(findings, category=Category.TLS, title_contains="weak tls protocol")
    row("tls_protocols", "No deprecated TLS/SSL protocols", "TLS hygiene",
        FAIL if deprecated_tls else PASS,
        "A deprecated protocol is accepted." if deprecated_tls else "Only modern protocols.")

    chain_fail = _has(findings, category=Category.TLS, title_contains="fails validation") \
        or _has(findings, category=Category.TLS, title_contains="failed verification")
    row("tls_chain", "Valid certificate chain", "TLS hygiene",
        FAIL if chain_fail else PASS,
        "Certificate chain did not validate." if chain_fail else "Chain validates / not applicable.")

    expired = _has(findings, category=Category.TLS, title_contains="expires in -")
    row("tls_expiry", "Certificate not expired", "TLS hygiene",
        FAIL if expired else PASS,
        "A certificate is expired." if expired else "No expired certificate observed.")

    weak_cipher = _has(findings, category=Category.TLS, title_contains="weak cipher")
    row("tls_cipher", "No weak ciphers", "TLS hygiene",
        FAIL if weak_cipher else PASS,
        "A weak cipher was negotiated." if weak_cipher else "No weak cipher observed.")

    # --- Email authentication ---------------------------------------------
    spf_missing = _has(findings, category=Category.EMAIL, title_contains="missing spf")
    row("email_spf", "SPF record present", "Email auth",
        FAIL if spf_missing else PASS,
        "No SPF record." if spf_missing else "SPF present.")
    dmarc_missing = _has(findings, category=Category.EMAIL, title_contains="missing dmarc")
    row("email_dmarc", "DMARC record present", "Email auth",
        FAIL if dmarc_missing else PASS,
        "No DMARC record." if dmarc_missing else "DMARC present.")
    dmarc_none = _has(findings, category=Category.EMAIL, title_contains="p=none")
    row("email_dmarc_policy", "DMARC enforced (not p=none)", "Email auth",
        WARN if dmarc_none else PASS,
        "DMARC is monitor-only." if dmarc_none else "DMARC enforced or not applicable.")

    # --- DNS hygiene -------------------------------------------------------
    dnssec_off = _has(findings, category=Category.DNS, title_contains="dnssec not enabled")
    row("dns_dnssec", "DNSSEC enabled", "DNS hygiene",
        WARN if dnssec_off else PASS,
        "Zone is not DNSSEC-signed." if dnssec_off else "DNSSEC enabled or not applicable.")
    no_caa = _has(findings, category=Category.DNS, title_contains="no caa record")
    row("dns_caa", "CAA record present", "DNS hygiene",
        WARN if no_caa else PASS,
        "No CAA record restricting CA issuance." if no_caa else "CAA present or not applicable.")
    axfr = _has(findings, title_contains="zone transfer (axfr)")
    row("dns_axfr", "Zone transfer (AXFR) refused", "DNS hygiene",
        FAIL if axfr else PASS,
        "A nameserver allowed AXFR." if axfr else "No open zone transfer.")

    # --- Exposure hygiene --------------------------------------------------
    secrets = _has(findings, category=Category.HTML, title_contains="in page source") \
        or _has(findings, category=Category.HTML, title_contains="hardcoded credential")
    row("exp_secrets", "No secrets exposed in content", "Exposure hygiene",
        FAIL if secrets else PASS,
        "Credential-shaped data found in content." if secrets else "None found.")
    public_bucket = _has(findings, category=Category.CLOUD, title_contains="publicly listable")
    row("exp_bucket", "No public cloud buckets", "Exposure hygiene",
        FAIL if public_bucket else PASS,
        "A publicly listable bucket was found." if public_bucket else "None found.")
    dir_listing = _has(findings, title_contains="directory listing enabled")
    row("exp_dirlist", "Directory listing disabled", "Exposure hygiene",
        WARN if dir_listing else PASS,
        "Directory listing is enabled somewhere." if dir_listing else "Not observed.")
    anon_ftp = _has(findings, title_contains="anonymous ftp")
    row("exp_ftp", "No anonymous FTP", "Exposure hygiene",
        FAIL if anon_ftp else PASS,
        "Anonymous FTP login allowed." if anon_ftp else "Not observed.")

    return rows


def summarize(rows: list[dict]) -> dict[str, int]:
    out = {PASS: 0, FAIL: 0, WARN: 0}
    for r in rows:
        if r["status"] in out:
            out[r["status"]] += 1
    return out


class ComplianceModule(Module):
    name = "compliance"
    label = "Compliance Checklist"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        result = ctx.state.get("_result")
        prior = list(getattr(result, "findings", []) or [])
        rows = evaluate(prior)
        counts = summarize(rows)
        # stash for the report generator
        ctx.state["compliance"] = rows

        findings: list[Finding] = [
            ctx.emit(
                Finding(
                    category=Category.COMPLIANCE,
                    title=(f"Baseline checklist: {counts['pass']} pass / "
                           f"{counts['fail']} fail / {counts['warn']} warn"),
                    severity=(Severity.HIGH if counts["fail"]
                              else Severity.LOW if counts["warn"] else Severity.INFO),
                    target=ctx.target,
                    description="Roll-up of findings against OWASP header, TLS, email and "
                                "DNS/exposure baselines. See evidence for the full checklist.",
                    evidence={"summary": counts, "checklist": rows},
                    module=self.name,
                )
            )
        ]
        # one finding per failed/warn item for visibility in the results list
        for r in rows:
            if r["status"] == PASS:
                continue
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.COMPLIANCE,
                        title=f"[{r['status'].upper()}] {r['name']} ({r['baseline']})",
                        severity=Severity.MEDIUM if r["status"] == FAIL else Severity.LOW,
                        target=ctx.target,
                        description=r["detail"],
                        evidence={"check": r["id"], "baseline": r["baseline"],
                                  "status": r["status"]},
                        module=self.name,
                    )
                )
            )
        ctx.log(f"Compliance: {counts['pass']} pass, {counts['fail']} fail, "
                f"{counts['warn']} warn.")
        return findings
