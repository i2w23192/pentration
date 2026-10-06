"""Subdomain & asset discovery.

Passive sources (crt.sh certificate transparency, DNS record enumeration) plus
active techniques (wordlist brute force with concurrent resolution, AXFR zone
transfer attempts). Wildcard DNS is detected so brute-force noise can be
flagged rather than reported as real hosts.

The module degrades gracefully: if ``dnspython`` or ``requests`` are missing,
the affected technique is skipped with an explanatory finding rather than
crashing the whole scan.
"""

from __future__ import annotations

import concurrent.futures
import json
import random
import socket
import string
from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None

try:
    import dns.resolver  # type: ignore
    import dns.query  # type: ignore
    import dns.zone  # type: ignore
    import dns.exception  # type: ignore
    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False


# A compact built-in wordlist. A real engagement should pass a larger list via
# config, but this keeps the tool useful with zero setup.
BUILTIN_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "vpn", "remote", "portal", "admin",
    "api", "api-dev", "dev", "staging", "stage", "test", "testing", "qa",
    "uat", "demo", "beta", "alpha", "preprod", "prod", "app", "apps", "web",
    "cdn", "static", "assets", "img", "images", "media", "files", "download",
    "upload", "docs", "doc", "wiki", "blog", "shop", "store", "git", "gitlab",
    "jenkins", "ci", "jira", "confluence", "status", "monitor", "grafana",
    "kibana", "prometheus", "db", "database", "sql", "mysql", "postgres",
    "redis", "mongo", "backup", "backups", "old", "new", "internal", "intranet",
    "corp", "secure", "login", "auth", "sso", "ldap", "ad", "exchange", "owa",
    "autodiscover", "cpanel", "whm", "dashboard", "panel", "console", "cloud",
    "s3", "storage", "proxy", "gateway", "gw", "fw", "firewall", "router",
    "support", "help", "helpdesk", "ticket", "mobile", "m", "wap", "beta-api",
    "v1", "v2", "graphql", "ws", "socket", "payments", "pay", "billing",
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


class ReconModule(Module):
    name = "recon"
    label = "Subdomain Discovery"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        target = ctx.target

        # Subdomain discovery only makes sense for domains, not bare IPs.
        from allscan.utils import is_ip

        if is_ip(target):
            ctx.log("Target is an IP; skipping subdomain discovery, resolving PTR.")
            findings.extend(self._reverse_ptr(ctx))
            return findings

        resolved: dict[str, list[str]] = {}

        findings.extend(self._dns_records(ctx))
        ctx.cancel.raise_if_cancelled()

        wildcard_ips = self._detect_wildcard(ctx)
        if wildcard_ips:
            findings.append(
                Finding(
                    category=Category.DNS,
                    title="Wildcard DNS detected",
                    severity=Severity.INFO,
                    target=target,
                    description=(
                        "The domain resolves arbitrary subdomains to a fixed "
                        "address set. Brute-forced results are filtered against "
                        "these addresses to avoid false positives."
                    ),
                    evidence={"wildcard_ips": sorted(wildcard_ips)},
                    module=self.name,
                )
            )

        crt_names = self._crtsh(ctx)
        ctx.cancel.raise_if_cancelled()

        brute_names = self._load_wordlist(ctx)
        candidates = set(crt_names) | {f"{w}.{target}" for w in brute_names}
        candidates.add(target)

        ctx.log(f"Resolving {len(candidates)} candidate hostnames…")
        resolved = self._resolve_all(ctx, candidates, wildcard_ips)

        for host, ips in sorted(resolved.items()):
            source = "crt.sh" if host in crt_names else "bruteforce/dns"
            f = ctx.emit(
                Finding(
                    category=Category.SUBDOMAIN,
                    title=host,
                    severity=Severity.INFO,
                    target=target,
                    description=f"Resolved subdomain ({source}).",
                    evidence={"ips": ips, "source": source},
                    module=self.name,
                )
            )
            findings.append(f)

        # expose resolved hosts to later modules (web/scan) via shared state
        ctx.state.setdefault("hosts", {})
        ctx.state["hosts"].update(resolved)

        findings.extend(self._zone_transfer(ctx))
        return findings

    # ------------------------------------------------------------------ #
    def _reverse_ptr(self, ctx: ModuleContext) -> list[Finding]:
        try:
            ctx.rate()
            ctx.audit.record("dns_ptr", ctx.target)
            host, _, _ = socket.gethostbyaddr(ctx.target)
        except Exception:
            return []
        ctx.state.setdefault("hosts", {})
        ctx.state["hosts"][ctx.target] = [ctx.target]
        return [
            ctx.emit(
                Finding(
                    category=Category.DNS,
                    title=f"PTR: {host}",
                    severity=Severity.INFO,
                    target=ctx.target,
                    description="Reverse DNS (PTR) record.",
                    evidence={"ptr": host},
                    module=self.name,
                )
            )
        ]

    def _dns_records(self, ctx: ModuleContext) -> list[Finding]:
        if not _HAVE_DNS:
            ctx.log("dnspython not installed; skipping DNS record enumeration.")
            return [self._missing_dep("dnspython", ctx)]
        findings: list[Finding] = []
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ctx.config.dns_resolvers or resolver.nameservers
        resolver.lifetime = ctx.config.timeout
        for rtype in DNS_RECORD_TYPES:
            ctx.cancel.raise_if_cancelled()
            try:
                ctx.rate()
                ctx.audit.record("dns_query", ctx.target, rtype=rtype)
                answers = resolver.resolve(ctx.target, rtype)
            except Exception:
                continue
            values = [r.to_text() for r in answers]
            sev = Severity.INFO
            if rtype == "TXT":
                # TXT records sometimes leak internal info / verification tokens
                sev = Severity.LOW if any("key" in v.lower() for v in values) else Severity.INFO
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.DNS,
                        title=f"{rtype} record",
                        severity=sev,
                        target=ctx.target,
                        description=f"DNS {rtype} record(s).",
                        evidence={"type": rtype, "values": values},
                        module=self.name,
                    )
                )
            )
            ctx.log(f"DNS {rtype}: {', '.join(values[:3])}{'…' if len(values) > 3 else ''}")
        return findings

    def _detect_wildcard(self, ctx: ModuleContext) -> set[str]:
        """Resolve a few random labels; shared answers indicate a wildcard."""
        if not _HAVE_DNS:
            return set()
        ips: set[str] = set()
        for _ in range(3):
            label = "".join(random.choices(string.ascii_lowercase, k=16))
            host = f"{label}.{ctx.target}"
            try:
                ctx.rate()
                for ip in self._resolve_one(ctx, host):
                    ips.add(ip)
            except Exception:
                pass
        return ips

    def _crtsh(self, ctx: ModuleContext) -> set[str]:
        if requests is None:
            ctx.log("requests not installed; skipping crt.sh.")
            return set()
        url = f"https://crt.sh/?q=%25.{ctx.target}&output=json"
        try:
            ctx.rate()
            ctx.audit.record("http_get", url)
            resp = requests.get(
                url,
                timeout=ctx.config.timeout + 10,
                headers={"User-Agent": ctx.config.user_agent},
                verify=ctx.config.verify_tls,
            )
            if resp.status_code != 200 or not resp.text.strip():
                ctx.log(f"crt.sh returned HTTP {resp.status_code}.")
                return set()
            data = resp.json()
        except json.JSONDecodeError:
            ctx.log("crt.sh response was not valid JSON.")
            return set()
        except Exception as exc:
            ctx.log(f"crt.sh query failed: {exc}")
            return set()
        names: set[str] = set()
        for row in data:
            for field_name in ("name_value", "common_name"):
                val = row.get(field_name, "")
                for name in str(val).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(ctx.target) and "@" not in name:
                        names.add(name)
        ctx.log(f"crt.sh yielded {len(names)} unique names.")
        return names

    def _load_wordlist(self, ctx: ModuleContext) -> list[str]:
        path = ctx.config.wordlist_subdomains
        words = BUILTIN_SUBDOMAINS
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    words = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
            except OSError as exc:
                ctx.log(f"Could not read subdomain wordlist {path}: {exc}")
        limit = ctx.config.max_subdomains_bruteforce
        return words[:limit]

    def _resolve_one(self, ctx: ModuleContext, host: str) -> list[str]:
        ips: list[str] = []
        if _HAVE_DNS:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ctx.config.dns_resolvers or resolver.nameservers
            resolver.lifetime = ctx.config.timeout
            for rtype in ("A", "AAAA"):
                try:
                    for r in resolver.resolve(host, rtype):
                        ips.append(r.to_text())
                except Exception:
                    continue
        else:
            try:
                for info in socket.getaddrinfo(host, None):
                    ips.append(info[4][0])
            except Exception:
                pass
        return sorted(set(ips))

    def _resolve_all(
        self, ctx: ModuleContext, hosts: set[str], wildcard_ips: set[str]
    ) -> dict[str, list[str]]:
        resolved: dict[str, list[str]] = {}

        def work(host: str) -> tuple[str, list[str]]:
            if ctx.cancel.cancelled():
                return host, []
            ctx.rate()
            ctx.audit.record("dns_resolve", host)
            return host, self._resolve_one(ctx, host)

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.threads) as ex:
            futures = {ex.submit(work, h): h for h in hosts}
            done = 0
            total = len(futures)
            for fut in concurrent.futures.as_completed(futures):
                if ctx.cancel.cancelled():
                    break
                done += 1
                host, ips = fut.result()
                if done % 50 == 0:
                    ctx.log(f"Resolved {done}/{total} candidates…")
                if not ips:
                    continue
                # drop pure-wildcard hits
                if wildcard_ips and set(ips) <= wildcard_ips and host != ctx.target:
                    continue
                resolved[host] = ips
        return resolved

    def _zone_transfer(self, ctx: ModuleContext) -> list[Finding]:
        if not _HAVE_DNS:
            return []
        findings: list[Finding] = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = ctx.config.timeout
            ns_records = resolver.resolve(ctx.target, "NS")
            nameservers = [r.to_text().rstrip(".") for r in ns_records]
        except Exception:
            return findings
        for ns in nameservers:
            ctx.cancel.raise_if_cancelled()
            try:
                ctx.rate()
                ctx.audit.record("dns_axfr", ctx.target, nameserver=ns)
                ns_ip = socket.gethostbyname(ns)
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, ctx.target, timeout=ctx.config.timeout)
                )
                records = [str(n) for n in zone.nodes.keys()]
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.MISCONFIG,
                            title=f"Zone transfer (AXFR) allowed via {ns}",
                            severity=Severity.HIGH,
                            target=ctx.target,
                            description=(
                                "The nameserver permitted a full zone transfer, "
                                "exposing the entire DNS zone to any client."
                            ),
                            evidence={"nameserver": ns, "record_count": len(records),
                                      "records": records[:200]},
                            module=self.name,
                        )
                    )
                )
                ctx.log(f"AXFR SUCCEEDED on {ns} ({len(records)} records) — misconfiguration!")
            except Exception:
                ctx.log(f"AXFR refused by {ns} (expected).")
        return findings

    def _missing_dep(self, dep: str, ctx: ModuleContext) -> Finding:
        return Finding(
            category=Category.DNS,
            title=f"Skipped: {dep} not installed",
            severity=Severity.INFO,
            target=ctx.target,
            description=f"Install {dep} to enable this technique.",
            module=self.name,
        )
