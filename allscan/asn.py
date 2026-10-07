"""ASN + IP-range discovery (passive).

Maps every resolved IP to its origin ASN, announced BGP prefix, registry and
owning organisation using Team Cymru's DNS-based IP-to-ASN service (no API key,
just DNS TXT lookups), then groups discovered hosts by ASN/prefix so you can
see which netblocks belong to the target versus third-party CDN/cloud.

Discovered prefixes are also stashed in ``ctx.state['asn_prefixes']`` so the
host-discovery sweep can optionally use them.

Requires ``dnspython``; degrades to an informational finding when absent.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity

try:
    import dns.resolver  # type: ignore
    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False


class AsnModule(Module):
    name = "asn"
    label = "ASN / IP-range Discovery"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        if not _HAVE_DNS:
            return [ctx.emit(Finding(
                category=Category.ASN, title="Skipped: dnspython not installed",
                severity=Severity.INFO, target=ctx.target,
                description="Install dnspython to enable ASN discovery.",
                module=self.name))]

        ips = self._collect_ips(ctx)
        if not ips:
            ctx.log("No resolved IPs to map to ASNs.")
            return []

        resolver = dns.resolver.Resolver()
        resolver.lifetime = ctx.config.timeout
        asn_cache: dict[str, dict] = {}
        groups: dict[str, dict] = {}  # asn -> {org, prefixes, ips}
        findings: list[Finding] = []

        for ip in ips:
            ctx.cancel.raise_if_cancelled()
            info = self._lookup_ip(ctx, resolver, ip)
            if not info:
                continue
            asn = info["asn"]
            g = groups.setdefault(asn, {"org": "", "prefixes": set(), "ips": []})
            g["ips"].append(ip)
            if info.get("prefix"):
                g["prefixes"].add(info["prefix"])
            if asn not in asn_cache:
                asn_cache[asn] = self._lookup_asn(ctx, resolver, asn)
            g["org"] = asn_cache[asn].get("org", "")

        ctx.state.setdefault("asn_prefixes", [])
        for asn, g in sorted(groups.items()):
            prefixes = sorted(g["prefixes"])
            ctx.state["asn_prefixes"].extend(prefixes)
            findings.append(ctx.emit(Finding(
                category=Category.ASN,
                title=f"AS{asn} — {g['org'] or 'org n/a'} ({len(g['ips'])} host(s))",
                severity=Severity.INFO,
                target=ctx.target,
                description="Hosts grouped by origin ASN / announced prefix.",
                evidence={"asn": asn, "org": g["org"], "prefixes": prefixes,
                          "ips": sorted(g["ips"]),
                          "registry": asn_cache.get(asn, {}).get("registry", "")},
                module=self.name,
            )))
            ctx.log(f"AS{asn} {g['org']}: {len(g['ips'])} host(s), prefixes={prefixes}")
        return findings

    # ------------------------------------------------------------------ #
    def _collect_ips(self, ctx: ModuleContext) -> list[str]:
        ips: set[str] = set()
        for lst in (ctx.state.get("hosts") or {}).values():
            for ip in lst:
                ips.add(ip)
        if is_ip_target := _as_ip(ctx.target):
            ips.add(is_ip_target)
        return sorted(ips)

    def _lookup_ip(self, ctx, resolver, ip: str) -> Optional[dict]:
        addr = _as_ip(ip)
        if not addr:
            return None
        v = ipaddress.ip_address(addr)
        if v.version == 6:
            rev = v.reverse_pointer.replace(".ip6.arpa", "") + ".origin6.asn.cymru.com"
        else:
            rev = ".".join(reversed(addr.split("."))) + ".origin.asn.cymru.com"
        txt = self._txt(ctx, resolver, rev)
        if not txt:
            return None
        # format: "ASN | BGP Prefix | CC | Registry | Allocated"
        parts = [p.strip() for p in txt.split("|")]
        if len(parts) < 2:
            return None
        asn = parts[0].split()[0]
        return {"asn": asn, "prefix": parts[1], "cc": parts[2] if len(parts) > 2 else ""}

    def _lookup_asn(self, ctx, resolver, asn: str) -> dict:
        txt = self._txt(ctx, resolver, f"AS{asn}.asn.cymru.com")
        if not txt:
            return {}
        # "ASN | CC | Registry | Allocated | AS Name"
        parts = [p.strip() for p in txt.split("|")]
        return {"registry": parts[2] if len(parts) > 2 else "",
                "org": parts[4] if len(parts) > 4 else ""}

    def _txt(self, ctx, resolver, name: str) -> Optional[str]:
        ctx.rate()
        ctx.audit.record("cymru_asn", name)
        try:
            answers = resolver.resolve(name, "TXT")
        except Exception:
            return None
        for r in answers:
            return r.to_text().strip('"')
        return None


def _as_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None
