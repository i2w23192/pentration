"""SSL/TLS deep audit.

Expands the quick TLS line the headers module emits into a full audit:

* **Protocol support matrix** — attempts a handshake forcing each of SSLv3,
  TLS 1.0, 1.1, 1.2 and 1.3 and records which the server accepts. Deprecated
  protocols (SSLv3 / TLS 1.0 / 1.1) are flagged.
* **Certificate chain validation** — a verifying handshake; reports whether the
  presented chain validates against the system trust store, and the chain
  depth / leaf subject + issuer.
* **Certificate expiry** — days remaining, with escalating severity as expiry
  approaches (or if already expired).

All of this is passive measurement against the target's TLS listener; nothing
is exploited.
"""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity


# protocol label -> (min_version, max_version) to pin a single version
def _version_map():
    m = {}
    V = ssl.TLSVersion
    candidates = [
        ("SSLv3", getattr(V, "SSLv3", None)),
        ("TLSv1.0", getattr(V, "TLSv1", None)),
        ("TLSv1.1", getattr(V, "TLSv1_1", None)),
        ("TLSv1.2", getattr(V, "TLSv1_2", None)),
        ("TLSv1.3", getattr(V, "TLSv1_3", None)),
    ]
    for label, ver in candidates:
        if ver is not None:
            m[label] = ver
    return m


DEPRECATED = {"SSLv3", "TLSv1.0", "TLSv1.1"}


class TlsModule(Module):
    name = "tls"
    label = "SSL/TLS Deep Audit"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        hosts = self._hosts(ctx)
        for host in hosts:
            ctx.cancel.raise_if_cancelled()
            findings.extend(self._protocol_matrix(ctx, host, 443))
            ctx.cancel.raise_if_cancelled()
            findings.extend(self._chain_and_expiry(ctx, host, 443))
        return findings

    # ------------------------------------------------------------------ #
    def _hosts(self, ctx: ModuleContext) -> list[str]:
        hosts = ctx.state.get("hosts")
        if hosts:
            return list(hosts.keys())[:25]
        return [ctx.target]

    # ------------------------------------------------------------------ #
    def _protocol_matrix(self, ctx: ModuleContext, host: str, port: int) -> list[Finding]:
        matrix: dict[str, bool] = {}
        for label, version in _version_map().items():
            if ctx.cancel.cancelled():
                break
            ctx.rate()
            accepted = self._try_version(ctx, host, port, version)
            matrix[label] = accepted
        if not matrix or not any(matrix.values()):
            ctx.log(f"No TLS listener reachable on {host}:{port}.")
            return []

        findings = [
            ctx.emit(
                Finding(
                    category=Category.TLS,
                    title=f"TLS protocol support matrix for {host}",
                    severity=Severity.INFO,
                    target=host,
                    description="Which TLS/SSL protocol versions the server accepts.",
                    evidence={"matrix": matrix},
                    module=self.name,
                )
            )
        ]
        enabled_deprecated = [p for p in matrix if matrix[p] and p in DEPRECATED]
        for proto in enabled_deprecated:
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.TLS,
                        title=f"Deprecated protocol accepted: {proto} on {host}",
                        severity=Severity.HIGH if proto == "SSLv3" else Severity.MEDIUM,
                        target=host,
                        description=f"{proto} is deprecated and should be disabled.",
                        evidence={"protocol": proto},
                        module=self.name,
                    )
                )
            )
        ctx.log(f"TLS matrix {host}: " +
                ", ".join(f"{k}={'Y' if v else 'n'}" for k, v in matrix.items()))
        return findings

    def _try_version(self, ctx: ModuleContext, host: str, port: int, version) -> bool:
        ctx.audit.record("tls_version_probe", host, port=port, version=str(version))
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                context.minimum_version = version
                context.maximum_version = version
            except (ValueError, OSError):
                # OpenSSL build refuses to enable this version at all
                return False
            with socket.create_connection((host, port), timeout=ctx.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    def _chain_and_expiry(self, ctx: ModuleContext, host: str, port: int) -> list[Finding]:
        findings: list[Finding] = []
        # 1) verifying handshake -> chain validity
        validates = None
        verify_error = ""
        ctx.rate()
        ctx.audit.record("tls_chain_verify", host, port=port)
        try:
            vctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=ctx.config.timeout) as sock:
                with vctx.wrap_socket(sock, server_hostname=host) as ss:
                    validates = True
                    chain_depth = None
                    getchain = getattr(ss, "get_verified_chain", None)
                    if callable(getchain):
                        try:
                            chain_depth = len(getchain())
                        except Exception:
                            chain_depth = None
                    cert = ss.getpeercert()
        except ssl.SSLCertVerificationError as exc:
            validates = False
            verify_error = getattr(exc, "verify_message", str(exc))
            cert = None
            chain_depth = None
        except Exception as exc:
            ctx.log(f"TLS chain check skipped for {host}: {exc}")
            return findings

        if validates:
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.TLS,
                        title=f"Certificate chain validates: {host}",
                        severity=Severity.INFO,
                        target=host,
                        description="Presented certificate chain validates against the system trust store.",
                        evidence={"chain_depth": chain_depth,
                                  "subject": _flat(cert.get("subject")) if cert else None,
                                  "issuer": _flat(cert.get("issuer")) if cert else None},
                        module=self.name,
                    )
                )
            )
            findings.extend(self._expiry(ctx, host, cert))
        else:
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.TLS,
                        title=f"Certificate chain FAILS validation: {host}",
                        severity=Severity.MEDIUM,
                        target=host,
                        description=f"Chain did not validate: {verify_error}",
                        evidence={"error": verify_error},
                        module=self.name,
                    )
                )
            )
            # still try to read expiry without verification
            findings.extend(self._expiry_unverified(ctx, host, port))
        return findings

    def _expiry(self, ctx: ModuleContext, host: str, cert: Optional[dict]) -> list[Finding]:
        if not cert:
            return []
        not_after = cert.get("notAfter")
        if not not_after:
            return []
        try:
            expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            return []
        days = (expires - datetime.datetime.utcnow()).days
        sev = Severity.INFO
        if days < 0:
            sev = Severity.HIGH
        elif days < 14:
            sev = Severity.MEDIUM
        elif days < 30:
            sev = Severity.LOW
        return [
            ctx.emit(
                Finding(
                    category=Category.TLS,
                    title=f"Certificate expires in {days} days: {host}",
                    severity=sev,
                    target=host,
                    description="TLS certificate validity window.",
                    evidence={"not_after": not_after, "days_remaining": days},
                    module=self.name,
                )
            )
        ]

    def _expiry_unverified(self, ctx: ModuleContext, host: str, port: int) -> list[Finding]:
        # Without verification, getpeercert() returns {} and the DER would need
        # a parser (cryptography) to read notAfter. We don't ship that
        # dependency, so expiry is only reported for chains that validate.
        return []


def _flat(seq):
    """Flatten the nested tuple structure getpeercert uses for subject/issuer."""
    if not seq:
        return None
    out = {}
    for rdn in seq:
        for k, v in rdn:
            out[k] = v
    return out
