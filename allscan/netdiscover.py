"""Network / host discovery.

Detection-only host discovery around the target:

* **ICMP ping sweep** across a CIDR range (defaults to the /24 containing the
  resolved target, or an explicit ``host_discovery_cidr`` from config).
* **ARP neighbour listing** — reads the local ARP cache (``ip neigh`` / ``arp``)
  to enumerate hosts already seen on the local segment. Read-only; no ARP
  requests are injected.
* **Traceroute** to the target, listing hops.

Everything shells out to standard system tools (``ping``, ``traceroute`` /
``tracepath``, ``ip`` / ``arp``) and degrades gracefully with an informational
finding when a tool or raw-socket privilege is unavailable — common in
containers and unprivileged shells. Nothing here is exploitation: it only
enumerates reachable hosts and path.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import shutil
import socket
import subprocess
from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity


class NetDiscoverModule(Module):
    name = "netdiscover"
    label = "Network/Host Discovery"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        target_ip = self._resolve_ip(ctx)

        findings.extend(self._ping_sweep(ctx, target_ip))
        ctx.cancel.raise_if_cancelled()
        findings.extend(self._arp_neighbours(ctx))
        ctx.cancel.raise_if_cancelled()
        findings.extend(self._traceroute(ctx))
        return findings

    # ------------------------------------------------------------------ #
    def _resolve_ip(self, ctx: ModuleContext) -> Optional[str]:
        from allscan.utils import is_ip

        if is_ip(ctx.target):
            return ctx.target
        try:
            return socket.gethostbyname(ctx.target)
        except Exception:
            return None

    def _target_cidr(self, ctx: ModuleContext, target_ip: Optional[str]):
        explicit = getattr(ctx.config, "host_discovery_cidr", None)
        if explicit:
            try:
                return ipaddress.ip_network(explicit, strict=False)
            except ValueError:
                ctx.log(f"Invalid host_discovery_cidr '{explicit}'; ignoring.")
        if not target_ip:
            return None
        try:
            # /24 around an IPv4 target; skip IPv6 sweeps (too large).
            addr = ipaddress.ip_address(target_ip)
            if addr.version != 4:
                return None
            return ipaddress.ip_network(f"{target_ip}/24", strict=False)
        except ValueError:
            return None

    # ------------------------------------------------------------------ #
    def _ping_sweep(self, ctx: ModuleContext, target_ip: Optional[str]) -> list[Finding]:
        if shutil.which("ping") is None:
            ctx.log("ping not found on PATH; skipping ICMP sweep.")
            return [self._skipped(ctx, "ICMP ping sweep", "ping binary not available")]
        cidr = self._target_cidr(ctx, target_ip)
        if cidr is None:
            ctx.log("No usable IPv4 CIDR to sweep; skipping ping sweep.")
            return []

        cap = int(getattr(ctx.config, "host_discovery_max", 256))
        hosts = [str(h) for h in cidr.hosts()][:cap]
        ctx.log(f"ICMP sweeping {cidr} ({len(hosts)} hosts)…")

        alive: list[str] = []

        def ping(ip: str) -> Optional[str]:
            if ctx.cancel.cancelled():
                return None
            ctx.rate()
            ctx.audit.record("icmp_ping", ip)
            # one echo, short wait; -n/-W keep it quick and quiet
            cmd = ["ping", "-c", "1", "-W", "1", ip]
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=5, check=False)
                return ip if proc.returncode == 0 else None
            except Exception:
                return None

        workers = max(1, min(ctx.config.threads, 64))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for result in ex.map(ping, hosts):
                if ctx.cancel.cancelled():
                    break
                if result:
                    alive.append(result)

        findings: list[Finding] = []
        if not alive:
            ctx.log("Ping sweep found no responding hosts (ICMP may be filtered).")
            return [
                self._skipped(
                    ctx, "ICMP ping sweep",
                    f"no hosts in {cidr} responded (ICMP may be filtered/blocked)",
                )
            ]
        ctx.state.setdefault("hosts", {})
        for ip in sorted(alive, key=lambda x: tuple(int(p) for p in x.split("."))):
            ctx.state["hosts"].setdefault(ip, [ip])
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.NETWORK,
                        title=f"Host alive: {ip}",
                        severity=Severity.INFO,
                        target=str(cidr),
                        description="Responded to ICMP echo during ping sweep.",
                        evidence={"ip": ip, "cidr": str(cidr)},
                        module=self.name,
                    )
                )
            )
        ctx.log(f"Ping sweep: {len(alive)} host(s) alive in {cidr}.")
        return findings

    # ------------------------------------------------------------------ #
    def _arp_neighbours(self, ctx: ModuleContext) -> list[Finding]:
        cmd = None
        if shutil.which("ip"):
            cmd = ["ip", "neigh", "show"]
        elif shutil.which("arp"):
            cmd = ["arp", "-a"]
        if not cmd:
            return [self._skipped(ctx, "ARP neighbour scan", "no ip/arp binary")]
        ctx.rate()
        ctx.audit.record("arp_cache", ctx.target, cmd=" ".join(cmd))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
        except Exception as exc:
            return [self._skipped(ctx, "ARP neighbour scan", str(exc))]
        neighbours = []
        for line in (proc.stdout or "").splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?(([0-9a-f]{2}:){5}[0-9a-f]{2})",
                          line, re.IGNORECASE)
            if m:
                neighbours.append({"ip": m.group(1), "mac": m.group(2)})
        if not neighbours:
            ctx.log("ARP cache empty (no local-segment neighbours observed).")
            return []
        ctx.log(f"ARP: {len(neighbours)} local neighbour(s) in cache.")
        return [
            ctx.emit(
                Finding(
                    category=Category.NETWORK,
                    title=f"Local ARP neighbours observed ({len(neighbours)})",
                    severity=Severity.INFO,
                    target=ctx.target,
                    description="Hosts present in the local ARP cache (read-only).",
                    evidence={"neighbours": neighbours[:128]},
                    module=self.name,
                )
            )
        ]

    # ------------------------------------------------------------------ #
    def _traceroute(self, ctx: ModuleContext) -> list[Finding]:
        tool = None
        if shutil.which("traceroute"):
            tool = ["traceroute", "-n", "-w", "2", "-q", "1", "-m", "20", ctx.target]
        elif shutil.which("tracepath"):
            tool = ["tracepath", "-n", ctx.target]
        if not tool:
            return [self._skipped(ctx, "Traceroute", "no traceroute/tracepath binary")]
        ctx.rate()
        ctx.audit.record("traceroute", ctx.target)
        try:
            proc = subprocess.run(tool, capture_output=True, text=True, timeout=90, check=False)
        except Exception as exc:
            return [self._skipped(ctx, "Traceroute", str(exc))]
        hops = []
        for line in (proc.stdout or "").splitlines():
            m = re.match(r"\s*(\d+)\s+(.*)", line)
            if m:
                hops.append({"hop": int(m.group(1)), "detail": m.group(2).strip()[:120]})
        if not hops:
            return [self._skipped(ctx, "Traceroute", "no hops returned")]
        ctx.log(f"Traceroute: {len(hops)} hop(s) to {ctx.target}.")
        return [
            ctx.emit(
                Finding(
                    category=Category.NETWORK,
                    title=f"Traceroute to {ctx.target} ({len(hops)} hops)",
                    severity=Severity.INFO,
                    target=ctx.target,
                    description="Network path to the target.",
                    evidence={"hops": hops},
                    module=self.name,
                )
            )
        ]

    # ------------------------------------------------------------------ #
    def _skipped(self, ctx: ModuleContext, what: str, why: str) -> Finding:
        return ctx.emit(
            Finding(
                category=Category.NETWORK,
                title=f"Skipped: {what}",
                severity=Severity.INFO,
                target=ctx.target,
                description=f"{what} could not run: {why}.",
                evidence={"reason": why},
                module=self.name,
            )
        )
