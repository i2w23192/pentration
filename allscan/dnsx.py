"""DNS deep-dive (distinct from subdomain discovery).

* Full record dump for record types the recon module doesn't cover: SOA, SRV
  (common service names), CAA, DNSKEY, DS, NS, TXT.
* DNSSEC presence check — looks for DNSKEY/RRSIG and the AD (authenticated
  data) flag from a validating resolver.
* DNS cache-snooping *detection* (informational) — a non-recursive query that
  reports whether a resolver appears to answer from cache. Purely observational;
  no attempt to enumerate what a third party has cached.

Requires ``dnspython``; degrades to an informational finding when absent.
"""

from __future__ import annotations

from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity

try:
    import dns.resolver  # type: ignore
    import dns.flags  # type: ignore
    import dns.message  # type: ignore
    import dns.query  # type: ignore
    import dns.name  # type: ignore
    import dns.rdatatype  # type: ignore
    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False


# SRV service labels worth probing on a corporate domain.
SRV_SERVICES = [
    "_sip._tcp", "_sips._tcp", "_sip._udp", "_xmpp-client._tcp",
    "_xmpp-server._tcp", "_ldap._tcp", "_kerberos._tcp", "_kerberos._udp",
    "_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp", "_imap._tcp",
    "_imaps._tcp", "_submission._tcp", "_pop3._tcp", "_pop3s._tcp",
    "_http._tcp", "_minecraft._tcp", "_vlmcs._tcp",
]

DEEP_RECORD_TYPES = ["SOA", "NS", "CAA", "DNSKEY", "DS", "TXT"]


class DnsxModule(Module):
    name = "dnsx"
    label = "DNS Deep-Dive"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        from allscan.utils import is_ip

        if is_ip(ctx.target):
            ctx.log("Target is an IP; DNS deep-dive needs a domain. Skipping.")
            return []
        if not _HAVE_DNS:
            ctx.log("dnspython not installed; DNS deep-dive unavailable.")
            return [
                ctx.emit(
                    Finding(
                        category=Category.DNS,
                        title="Skipped: dnspython not installed",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="Install dnspython to enable DNS deep-dive.",
                        module=self.name,
                    )
                )
            ]

        findings: list[Finding] = []
        findings.extend(self._dump_records(ctx))
        ctx.cancel.raise_if_cancelled()
        findings.extend(self._srv_records(ctx))
        ctx.cancel.raise_if_cancelled()
        findings.extend(self._caa_check(ctx))
        ctx.cancel.raise_if_cancelled()
        findings.extend(self._dnssec_check(ctx))
        ctx.cancel.raise_if_cancelled()
        findings.extend(self._cache_snoop(ctx))
        return findings

    # ------------------------------------------------------------------ #
    def _resolver(self, ctx: ModuleContext):
        r = dns.resolver.Resolver()
        r.nameservers = ctx.config.dns_resolvers or r.nameservers
        r.lifetime = ctx.config.timeout
        return r

    def _dump_records(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        resolver = self._resolver(ctx)
        for rtype in DEEP_RECORD_TYPES:
            ctx.cancel.raise_if_cancelled()
            try:
                ctx.rate()
                ctx.audit.record("dns_query", ctx.target, rtype=rtype)
                answers = resolver.resolve(ctx.target, rtype)
            except Exception:
                continue
            values = [r.to_text() for r in answers]
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.DNS,
                        title=f"{rtype} record ({len(values)})",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description=f"DNS {rtype} record(s).",
                        evidence={"type": rtype, "values": values[:50]},
                        module=self.name,
                    )
                )
            )
            ctx.log(f"{rtype}: {len(values)} record(s).")
        return findings

    def _srv_records(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        resolver = self._resolver(ctx)
        found = []
        for svc in SRV_SERVICES:
            ctx.cancel.raise_if_cancelled()
            name = f"{svc}.{ctx.target}"
            try:
                ctx.rate()
                ctx.audit.record("dns_query", name, rtype="SRV")
                answers = resolver.resolve(name, "SRV")
            except Exception:
                continue
            for r in answers:
                found.append({"service": svc, "target": r.to_text()})
        if found:
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.DNS,
                        title=f"SRV service records discovered ({len(found)})",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="Service (SRV) records reveal exposed services.",
                        evidence={"srv": found},
                        module=self.name,
                    )
                )
            )
            ctx.log(f"SRV: {len(found)} service record(s).")
        return findings

    def _caa_check(self, ctx: ModuleContext) -> list[Finding]:
        resolver = self._resolver(ctx)
        try:
            ctx.rate()
            resolver.resolve(ctx.target, "CAA")
            return []  # present -> already dumped above
        except Exception:
            return [
                ctx.emit(
                    Finding(
                        category=Category.DNS,
                        title="No CAA record",
                        severity=Severity.LOW,
                        target=ctx.target,
                        description=(
                            "No Certification Authority Authorization record. Any CA "
                            "may issue certificates for this domain; a CAA record "
                            "restricts issuance to named CAs."
                        ),
                        evidence={"record": "CAA", "present": False},
                        module=self.name,
                    )
                )
            ]

    def _dnssec_check(self, ctx: ModuleContext) -> list[Finding]:
        resolver = self._resolver(ctx)
        has_dnskey = False
        try:
            ctx.rate()
            ctx.audit.record("dns_query", ctx.target, rtype="DNSKEY")
            resolver.resolve(ctx.target, "DNSKEY")
            has_dnskey = True
        except Exception:
            has_dnskey = False

        ad_flag = False
        try:
            ctx.rate()
            ns = (ctx.config.dns_resolvers or ["1.1.1.1"])[0]
            request = dns.message.make_query(
                ctx.target, dns.rdatatype.A, want_dnssec=True
            )
            request.flags |= dns.flags.AD
            ctx.audit.record("dnssec_check", ctx.target, resolver=ns)
            response = dns.query.udp(request, ns, timeout=ctx.config.timeout)
            ad_flag = bool(response.flags & dns.flags.AD)
        except Exception:
            ad_flag = False

        if has_dnskey or ad_flag:
            return [
                ctx.emit(
                    Finding(
                        category=Category.DNS,
                        title="DNSSEC appears enabled",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="DNSKEY present and/or resolver returned the AD flag.",
                        evidence={"dnskey": has_dnskey, "ad_flag": ad_flag},
                        module=self.name,
                    )
                )
            ]
        return [
            ctx.emit(
                Finding(
                    category=Category.DNS,
                    title="DNSSEC not enabled",
                    severity=Severity.LOW,
                    target=ctx.target,
                    description=(
                        "No DNSKEY and no authenticated-data flag observed. The zone "
                        "is not DNSSEC-signed, so responses are not cryptographically "
                        "validatable (spoofing/cache-poisoning risk)."
                    ),
                    evidence={"dnskey": False, "ad_flag": False},
                    module=self.name,
                )
            )
        ]

    def _cache_snoop(self, ctx: ModuleContext) -> list[Finding]:
        """Informational: probe the configured resolver with a non-recursive
        query (RD=0) for a common name and report whether it answered from
        cache. This observes resolver behaviour only — it does not attempt to
        enumerate another party's cached lookups."""
        ns = (ctx.config.dns_resolvers or ["1.1.1.1"])[0]
        probe = "www.google.com."
        try:
            ctx.rate()
            request = dns.message.make_query(probe, dns.rdatatype.A)
            request.flags &= ~dns.flags.RD  # non-recursive
            ctx.audit.record("dns_cache_snoop", ns, probe=probe)
            response = dns.query.udp(request, ns, timeout=ctx.config.timeout)
        except Exception:
            return []
        answered_from_cache = bool(response.answer)
        if answered_from_cache:
            return [
                ctx.emit(
                    Finding(
                        category=Category.DNS,
                        title="DNS cache snooping possible",
                        severity=Severity.LOW,
                        target=ns,
                        description=(
                            "The resolver answered a non-recursive (RD=0) query from "
                            "cache, which can let an observer infer which names it has "
                            "recently resolved. Informational only."
                        ),
                        evidence={"resolver": ns, "probe": probe, "cached": True},
                        module=self.name,
                    )
                )
            ]
        return []
