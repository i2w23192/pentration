"""Attack-surface + infra-relationship mapping (passive roll-up).

Runs late in the chain and correlates everything discovered — subdomains, IPs,
ASNs/prefixes, open ports/services, web endpoints/tech and cloud assets — into
a structured relationship map (nodes + edges). It emits summary findings and
stashes the map in ``ctx.state['surface']`` / ``result.meta['surface']`` for the
report (and a future topology diagram).

Flags a few surface-hygiene items: third-party-hosted assets (hosts whose ASN
differs from the primary), and dangling DNS names (resolved/known hostnames
with no observed service).

Pure correlation of already-collected data — no new network I/O.
"""

from __future__ import annotations

from collections import defaultdict

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity


class SurfaceModule(Module):
    name = "surface"
    label = "Attack-Surface Mapping"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        result = ctx.state.get("_result")
        prior = list(getattr(result, "findings", []) or [])

        hosts = ctx.state.get("hosts") or {}
        services = ctx.state.get("services") or []
        web_hosts = ctx.state.get("web_hosts") or []

        nodes: dict[str, dict] = {}
        edges: list[dict] = []

        def node(nid: str, ntype: str, **attrs):
            n = nodes.setdefault(nid, {"id": nid, "type": ntype})
            n.update(attrs)
            return nid

        def edge(a: str, b: str, kind: str):
            edges.append({"from": a, "to": b, "kind": kind})

        # host -> IP edges
        ip_to_hosts: dict[str, list] = defaultdict(list)
        for host, ips in hosts.items():
            node(host, "host")
            for ip in ips:
                node(ip, "ip")
                edge(host, ip, "resolves_to")
                ip_to_hosts[ip].append(host)

        # ASN grouping (from asn module findings)
        ip_to_asn: dict[str, str] = {}
        asns: dict[str, dict] = {}
        for f in prior:
            fd = f if isinstance(f, dict) else f.to_dict()
            if fd.get("category") == Category.ASN:
                ev = fd.get("evidence") or {}
                asn = ev.get("asn")
                if not asn:
                    continue
                aid = node(f"AS{asn}", "asn", org=ev.get("org", ""))
                asns[asn] = {"org": ev.get("org", ""), "prefixes": ev.get("prefixes", [])}
                for ip in ev.get("ips", []):
                    node(ip, "ip")
                    edge(ip, aid, "announced_by")
                    ip_to_asn[ip] = asn

        # services -> ports
        host_services: dict[str, list] = defaultdict(list)
        for svc in services:
            h = svc.get("host") or ""
            port = svc.get("port")
            label = f"{svc.get('product','')} {svc.get('version','')}".strip() or "service"
            if h:
                node(h, "host")
                sid = node(f"{h}:{port}", "service", detail=label)
                edge(h, sid, "exposes")
                host_services[h].append(label)

        # web endpoints
        for base in web_hosts:
            node(base, "web")

        # cloud assets (from cloud module findings)
        for f in prior:
            fd = f if isinstance(f, dict) else f.to_dict()
            if fd.get("category") == Category.CLOUD:
                ev = fd.get("evidence") or {}
                url = ev.get("url")
                if url:
                    node(url, "cloud", provider=ev.get("provider", ""))

        # --- hygiene flags -------------------------------------------------
        findings: list[Finding] = []

        # primary ASN = the one owning the most IPs
        asn_ip_counts: dict[str, int] = defaultdict(int)
        for ip, asn in ip_to_asn.items():
            asn_ip_counts[asn] += 1
        primary_asn = max(asn_ip_counts, key=asn_ip_counts.get) if asn_ip_counts else None

        third_party = []
        if primary_asn:
            for ip, asn in ip_to_asn.items():
                if asn != primary_asn:
                    for h in ip_to_hosts.get(ip, [ip]):
                        third_party.append({"host": h, "ip": ip, "asn": f"AS{asn}",
                                            "org": asns.get(asn, {}).get("org", "")})
        if third_party:
            findings.append(ctx.emit(Finding(
                category=Category.SURFACE,
                title=f"{len(third_party)} asset(s) hosted on third-party ASNs",
                severity=Severity.INFO,
                target=ctx.target,
                description="Hosts whose announcing ASN differs from the primary — "
                            "typically CDN/cloud/third-party infrastructure.",
                evidence={"primary_asn": f"AS{primary_asn}", "third_party": third_party[:100]},
                module=self.name,
            )))

        # dangling DNS: known hostnames with no observed service/web endpoint
        served = {s.get("host") for s in services} | set(web_hosts)
        served |= {b.split("://", 1)[-1].split("/", 1)[0] for b in web_hosts}
        dangling = [h for h in hosts
                    if h not in served and not any(h in str(w) for w in web_hosts)]
        if dangling:
            findings.append(ctx.emit(Finding(
                category=Category.SURFACE,
                title=f"{len(dangling)} hostname(s) with no observed service",
                severity=Severity.LOW,
                target=ctx.target,
                description="Known/resolved names with no port/web service observed — "
                            "review for dangling DNS or decommissioned assets.",
                evidence={"hostnames": sorted(dangling)[:100]},
                module=self.name,
            )))

        # summary + stash the map
        surface = {
            "nodes": list(nodes.values()),
            "edges": edges,
            "counts": {
                "hosts": sum(1 for n in nodes.values() if n["type"] == "host"),
                "ips": sum(1 for n in nodes.values() if n["type"] == "ip"),
                "asns": sum(1 for n in nodes.values() if n["type"] == "asn"),
                "services": sum(1 for n in nodes.values() if n["type"] == "service"),
                "web": sum(1 for n in nodes.values() if n["type"] == "web"),
                "cloud": sum(1 for n in nodes.values() if n["type"] == "cloud"),
            },
        }
        ctx.state["surface"] = surface
        findings.insert(0, ctx.emit(Finding(
            category=Category.SURFACE,
            title=("Attack surface: "
                   + ", ".join(f"{v} {k}" for k, v in surface["counts"].items() if v)),
            severity=Severity.INFO,
            target=ctx.target,
            description="Correlated attack-surface map (nodes + relationships).",
            evidence={"counts": surface["counts"], "edge_count": len(edges)},
            module=self.name,
        )))
        ctx.log("Surface map: " + ", ".join(f"{v} {k}"
                for k, v in surface["counts"].items() if v))
        return findings
