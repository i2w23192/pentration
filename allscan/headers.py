"""HTML source analysis, HTTP security-header audit, and TLS inspection.

Operates on the pages the web module captured (``ctx.state['pages']``). If the
web module did not run, it fetches the target's root page itself so the module
is usable standalone.

Checks performed:

* **Security headers** — presence/configuration of CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
* **Verbose headers** — ``Server`` / ``X-Powered-By`` leaking version info.
* **Cookie flags** — Secure / HttpOnly / SameSite.
* **HTML source** — exposed comments, secret-shaped strings, internal paths,
  outdated library versions in ``<script src>``, risky inline JS patterns.
* **TLS** — certificate metadata and weak protocol/cipher detection.
"""

from __future__ import annotations

import datetime
import re
import socket
import ssl
from typing import Optional
from urllib.parse import urlparse

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity
from allscan.utils import scan_for_secrets

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


# header -> (severity if missing, human guidance)
SECURITY_HEADERS: dict[str, tuple[Severity, str]] = {
    "content-security-policy": (Severity.MEDIUM, "Mitigates XSS/data injection."),
    "strict-transport-security": (Severity.MEDIUM, "Enforces HTTPS (HSTS)."),
    "x-frame-options": (Severity.LOW, "Mitigates clickjacking."),
    "x-content-type-options": (Severity.LOW, "Stops MIME sniffing (nosniff)."),
    "referrer-policy": (Severity.LOW, "Controls referrer leakage."),
    "permissions-policy": (Severity.LOW, "Restricts powerful browser features."),
}

VERBOSE_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                   "x-aspnetmvc-version", "x-generator")

# outdated JS libs: name -> (last-known-risky-below version, note). Advisory
# only — a heuristic nudge, not an authoritative version oracle.
OUTDATED_LIBS: dict[str, tuple[str, str]] = {
    "jquery": ("3.5.0", "jQuery < 3.5.0 has known XSS issues (CVE-2020-11022/23)."),
    "angular": ("1.8.0", "AngularJS 1.x is end-of-life."),
    "bootstrap": ("3.4.1", "Bootstrap 3 is end-of-life; older 3.x had XSS."),
    "lodash": ("4.17.21", "lodash < 4.17.21 had prototype pollution CVEs."),
    "moment": ("2.29.4", "moment < 2.29.4 had ReDoS/path traversal CVEs."),
}

INLINE_JS_PATTERNS: list[tuple[str, Severity, str]] = [
    (r"eval\s*\(\s*(?:location|document|window|request|req|params|input)",
     Severity.HIGH, "eval() of apparently user-controlled input"),
    (r"document\.write\s*\(\s*(?:location|document\.URL|unescape)",
     Severity.MEDIUM, "document.write of untrusted data"),
    (r"innerHTML\s*=\s*(?:location|document\.URL|window\.name)",
     Severity.MEDIUM, "innerHTML assignment from untrusted source"),
    (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{3,}['\"]",
     Severity.HIGH, "Hardcoded credential in inline script"),
]


class HeadersModule(Module):
    name = "headers"
    label = "HTML/Header Analysis"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        pages = ctx.state.get("pages")
        if not pages:
            page = self._fetch_root(ctx)
            pages = {page["url"]: page} if page else {}

        for url, page in pages.items():
            ctx.cancel.raise_if_cancelled()
            headers = {k.lower(): v for k, v in (page.get("headers") or {}).items()}
            findings.extend(self._audit_headers(ctx, url, headers))
            findings.extend(self._audit_cookies(ctx, url, page.get("cookies") or []))
            findings.extend(self._analyze_html(ctx, url, page.get("body") or ""))

        # TLS checks run against the host directly
        findings.extend(self._tls_checks(ctx))
        return findings

    # ------------------------------------------------------------------ #
    def _fetch_root(self, ctx: ModuleContext) -> Optional[dict]:
        if requests is None:
            return None
        for scheme in ("https", "http"):
            url = f"{scheme}://{ctx.target}"
            ctx.rate()
            ctx.audit.record("http_get", url)
            try:
                resp = requests.get(
                    url,
                    timeout=ctx.config.timeout,
                    headers={"User-Agent": ctx.config.user_agent},
                    verify=ctx.config.verify_tls,
                )
            except Exception:
                continue
            return {
                "url": resp.url,
                "headers": dict(resp.headers),
                "body": resp.text or "",
                "cookies": [],
            }
        return None

    # ------------------------------------------------------------------ #
    def _audit_headers(self, ctx: ModuleContext, url: str, headers: dict) -> list[Finding]:
        findings: list[Finding] = []
        for header, (sev, note) in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.HEADER,
                            title=f"Missing {header} header",
                            severity=sev,
                            target=url,
                            description=note,
                            evidence={"header": header, "present": False},
                            module=self.name,
                        )
                    )
                )
        # HSTS present but weak
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 15552000:  # < ~180 days
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.HEADER,
                            title="Weak HSTS max-age",
                            severity=Severity.LOW,
                            target=url,
                            description="HSTS max-age is short; recommend >= 1 year.",
                            evidence={"value": hsts},
                            module=self.name,
                        )
                    )
                )
        # verbose headers
        for header in VERBOSE_HEADERS:
            val = headers.get(header)
            if val and re.search(r"\d", val):
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.HEADER,
                            title=f"Verbose header {header}: {val}",
                            severity=Severity.LOW,
                            target=url,
                            description="Header leaks product/version information.",
                            evidence={"header": header, "value": val},
                            module=self.name,
                        )
                    )
                )
        return findings

    def _audit_cookies(self, ctx: ModuleContext, url: str, cookies: list) -> list[Finding]:
        findings: list[Finding] = []
        is_https = url.lower().startswith("https")
        for c in cookies:
            problems = []
            if is_https and not c.get("secure"):
                problems.append("missing Secure")
            if not c.get("httponly"):
                problems.append("missing HttpOnly")
            if not c.get("samesite"):
                problems.append("missing SameSite")
            if problems:
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.HEADER,
                            title=f"Cookie '{c.get('name')}' flags: {', '.join(problems)}",
                            severity=Severity.LOW,
                            target=url,
                            description="Session cookies should set Secure, HttpOnly and SameSite.",
                            evidence={"cookie": c, "problems": problems},
                            module=self.name,
                        )
                    )
                )
        return findings

    # ------------------------------------------------------------------ #
    def _analyze_html(self, ctx: ModuleContext, url: str, body: str) -> list[Finding]:
        findings: list[Finding] = []
        if not body:
            return findings

        # 1. HTML comments (may leak internals)
        for comment in re.findall(r"<!--(.*?)-->", body, re.DOTALL)[:200]:
            text = comment.strip()
            lowered = text.lower()
            if not text:
                continue
            interesting = any(
                kw in lowered
                for kw in ("todo", "fixme", "password", "key", "secret", "token",
                           "api", "debug", "internal", "http://", "https://", "/admin",
                           "username", "db", "backup")
            )
            if interesting:
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.HTML,
                            title="Interesting HTML comment",
                            severity=Severity.LOW,
                            target=url,
                            description="A source comment may reveal internal detail.",
                            evidence={"comment": text[:300]},
                            module=self.name,
                        )
                    )
                )

        # 2. secret-shaped strings
        for label, snippet in scan_for_secrets(body):
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.HTML,
                        title=f"Possible {label} in page source",
                        severity=Severity.HIGH,
                        target=url,
                        description="A credential-shaped string was found in the response body.",
                        evidence={"type": label, "snippet": snippet},
                        module=self.name,
                    )
                )
            )

        # 3. exposed internal paths
        for path in set(re.findall(r"""['"](/(?:var|etc|home|usr|opt|srv)/[\w./\-]+)['"]""", body)):
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.HTML,
                        title=f"Internal filesystem path in source: {path}",
                        severity=Severity.LOW,
                        target=url,
                        description="An absolute server path is referenced in the page source.",
                        evidence={"path": path},
                        module=self.name,
                    )
                )
            )

        # 4. outdated libraries in <script src>
        for src in re.findall(r"""<script[^>]+src=['"]([^'"]+)['"]""", body, re.IGNORECASE):
            findings.extend(self._check_lib(ctx, url, src))

        # 5. risky inline JS
        for pattern, sev, desc in INLINE_JS_PATTERNS:
            if re.search(pattern, body):
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.HTML,
                            title=f"Risky inline JS: {desc}",
                            severity=sev,
                            target=url,
                            description="A potentially dangerous inline JavaScript pattern was found.",
                            evidence={"pattern": pattern},
                            module=self.name,
                        )
                    )
                )
        return findings

    def _check_lib(self, ctx: ModuleContext, url: str, src: str) -> list[Finding]:
        m = re.search(r"(jquery|angular|bootstrap|lodash|moment)[.\-/]?v?"
                      r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", src, re.IGNORECASE)
        if not m:
            return []
        lib = m.group(1).lower()
        ver = m.group(2)
        if lib not in OUTDATED_LIBS:
            return []
        min_ok, note = OUTDATED_LIBS[lib]
        if _version_lt(ver, min_ok):
            # record for CVE correlation too
            ctx.state.setdefault("services", []).append(
                {"host": url, "port": "", "product": lib, "version": ver}
            )
            return [
                ctx.emit(
                    Finding(
                        category=Category.HTML,
                        title=f"Outdated library: {lib} {ver}",
                        severity=Severity.MEDIUM,
                        target=url,
                        description=note,
                        evidence={"library": lib, "version": ver, "src": src,
                                  "recommended_min": min_ok},
                        module=self.name,
                    )
                )
            ]
        return []

    # ------------------------------------------------------------------ #
    def _tls_checks(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        host = urlparse(f"//{ctx.target}").path or ctx.target
        host = ctx.target
        port = 443
        ctx.rate()
        ctx.audit.record("tls_connect", host, port=port)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=ctx.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    # getpeercert returns {} without verification; grab what we can
                    version = ssock.version()
                    cipher = ssock.cipher()
        except Exception as exc:
            ctx.log(f"TLS inspection skipped for {host}:443 ({exc}).")
            return findings

        findings.append(
            ctx.emit(
                Finding(
                    category=Category.TLS,
                    title=f"TLS: {version}, cipher {cipher[0] if cipher else '?'}",
                    severity=Severity.INFO,
                    target=host,
                    description="Negotiated TLS protocol and cipher.",
                    evidence={"protocol": version, "cipher": cipher},
                    module=self.name,
                )
            )
        )
        # weak protocol
        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.TLS,
                        title=f"Weak TLS protocol supported: {version}",
                        severity=Severity.HIGH,
                        target=host,
                        description="Deprecated TLS/SSL protocol negotiated.",
                        evidence={"protocol": version},
                        module=self.name,
                    )
                )
            )
        # weak cipher heuristics
        if cipher and re.search(r"RC4|DES|MD5|NULL|EXPORT", cipher[0], re.IGNORECASE):
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.TLS,
                        title=f"Weak cipher negotiated: {cipher[0]}",
                        severity=Severity.HIGH,
                        target=host,
                        description="A cryptographically weak cipher suite was negotiated.",
                        evidence={"cipher": cipher},
                        module=self.name,
                    )
                )
            )
        # certificate expiry (needs verification enabled to populate cert)
        findings.extend(self._cert_expiry(ctx, host, port))
        return findings

    def _cert_expiry(self, ctx: ModuleContext, host: str, port: int) -> list[Finding]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=ctx.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
        except ssl.SSLCertVerificationError as exc:
            return [
                ctx.emit(
                    Finding(
                        category=Category.TLS,
                        title="TLS certificate failed verification",
                        severity=Severity.MEDIUM,
                        target=host,
                        description=f"Certificate did not validate: {exc.verify_message}",
                        evidence={"error": str(exc)},
                        module=self.name,
                    )
                )
            ]
        except Exception:
            return []
        if not cert:
            return []
        findings: list[Finding] = []
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (expires - datetime.datetime.utcnow()).days
                sev = Severity.INFO
                if days < 0:
                    sev = Severity.HIGH
                elif days < 14:
                    sev = Severity.MEDIUM
                elif days < 30:
                    sev = Severity.LOW
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.TLS,
                            title=f"Certificate expires in {days} days",
                            severity=sev,
                            target=host,
                            description="TLS certificate validity window.",
                            evidence={"not_after": not_after, "days_remaining": days,
                                      "subject": cert.get("subject"),
                                      "issuer": cert.get("issuer")},
                            module=self.name,
                        )
                    )
                )
            except ValueError:
                pass
        return findings


def _version_lt(a: str, b: str) -> bool:
    """Return True if version a < version b (numeric tuple compare)."""
    def parts(v: str):
        return [int(x) for x in re.findall(r"\d+", v)] or [0]
    pa, pb = parts(a), parts(b)
    length = max(len(pa), len(pb))
    pa += [0] * (length - len(pa))
    pb += [0] * (length - len(pb))
    return pa < pb
