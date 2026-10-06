"""Port & service scanning.

Primary path wraps the ``nmap`` binary (top-1000 by default, full 65535 with
``full_ports``, ``-sV`` service/version detection, optional ``-O`` OS
detection). nmap output is parsed from its XML so results are structured.

When nmap is unavailable or ``skip_nmap`` is set, a pure-Python connect-scan +
banner grabber covers a common-ports list so the tool still produces useful
service/version hints.

Detected service/version strings are stashed in ``ctx.state['services']`` for
the CVE correlation module to consume.
"""

from __future__ import annotations

import concurrent.futures
import shutil
import socket
import ssl
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity

# Common ports probed by the fallback scanner (service name hints too).
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 5985: "winrm", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}

# Ports whose exposure is itself worth flagging at elevated severity.
SENSITIVE_PORTS = {
    23: ("Telnet exposed", Severity.MEDIUM),
    3389: ("RDP exposed", Severity.MEDIUM),
    445: ("SMB exposed", Severity.MEDIUM),
    3306: ("MySQL exposed to network", Severity.MEDIUM),
    5432: ("PostgreSQL exposed to network", Severity.MEDIUM),
    6379: ("Redis exposed (often unauthenticated)", Severity.HIGH),
    9200: ("Elasticsearch exposed (often unauthenticated)", Severity.HIGH),
    27017: ("MongoDB exposed (often unauthenticated)", Severity.HIGH),
    11211: ("Memcached exposed (often unauthenticated)", Severity.HIGH),
    2375: ("Docker API exposed (potential RCE)", Severity.HIGH),
}


class ScanModule(Module):
    name = "scan"
    label = "Port/Service Scan"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        hosts = self._targets(ctx)
        ctx.state.setdefault("services", [])

        use_nmap = (not ctx.config.skip_nmap) and shutil.which("nmap") is not None
        if not use_nmap and not ctx.config.skip_nmap:
            ctx.log("nmap not found on PATH; using built-in connect scanner.")

        for host in hosts:
            ctx.cancel.raise_if_cancelled()
            ctx.log(f"Scanning {host}…")
            if use_nmap:
                findings.extend(self._nmap_scan(ctx, host))
            else:
                findings.extend(self._fallback_scan(ctx, host))
        return findings

    # ------------------------------------------------------------------ #
    def _targets(self, ctx: ModuleContext) -> list[str]:
        hosts = ctx.state.get("hosts")
        if hosts:
            # unique resolved hostnames; cap to keep runs bounded
            return list(hosts.keys())[:50]
        return [ctx.target]

    # ------------------------------------------------------------------ #
    # nmap path
    # ------------------------------------------------------------------ #
    def _nmap_scan(self, ctx: ModuleContext, host: str) -> list[Finding]:
        cmd = ["nmap", "-sV", "-T4", "-oX", "-"]
        if ctx.config.full_ports:
            cmd += ["-p-"]
        else:
            cmd += ["--top-ports", "1000"]
        if ctx.config.os_detection:
            cmd += ["-O"]
        # keep nmap's own timing reasonable; rate limit the invocation itself
        cmd += ["--host-timeout", "15m", host]

        ctx.rate()
        ctx.audit.record("nmap", host, cmd=" ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60 * 20,
                check=False,
            )
        except subprocess.TimeoutExpired:
            ctx.log(f"nmap timed out on {host}.")
            return []
        except Exception as exc:  # pragma: no cover - environment dependent
            ctx.log(f"nmap failed on {host}: {exc}")
            return []

        if not proc.stdout.strip():
            if "requires root" in (proc.stderr or "").lower():
                ctx.log("nmap needs root for some options (e.g. -O); run with sudo.")
            return []
        return self._parse_nmap_xml(ctx, host, proc.stdout)

    def _parse_nmap_xml(self, ctx: ModuleContext, host: str, xml_text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            ctx.log("Could not parse nmap XML output.")
            return findings
        for host_el in root.findall("host"):
            # OS detection
            for osmatch in host_el.findall("./os/osmatch"):
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.SERVICE,
                            title=f"OS guess: {osmatch.get('name')}",
                            severity=Severity.INFO,
                            target=host,
                            description="nmap OS fingerprint.",
                            evidence={"accuracy": osmatch.get("accuracy")},
                            module=self.name,
                        )
                    )
                )
            for port_el in host_el.findall("./ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portid = int(port_el.get("portid"))
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                svc = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                findings.extend(
                    self._record_port(ctx, host, portid, proto, svc, product, version)
                )
        return findings

    # ------------------------------------------------------------------ #
    # fallback path
    # ------------------------------------------------------------------ #
    def _fallback_scan(self, ctx: ModuleContext, host: str) -> list[Finding]:
        findings: list[Finding] = []
        ports = list(COMMON_PORTS.keys())
        if ctx.config.full_ports:
            ports = list(range(1, 65536))

        open_ports: list[int] = []

        def probe(port: int) -> Optional[int]:
            if ctx.cancel.cancelled():
                return None
            ctx.rate()
            try:
                with socket.create_connection((host, port), timeout=ctx.config.timeout):
                    return port
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.threads) as ex:
            for result in ex.map(probe, ports):
                if ctx.cancel.cancelled():
                    break
                if result is not None:
                    open_ports.append(result)

        for port in sorted(open_ports):
            ctx.cancel.raise_if_cancelled()
            banner, product, version = self._grab_banner(ctx, host, port)
            svc = COMMON_PORTS.get(port, "unknown")
            findings.extend(
                self._record_port(ctx, host, port, "tcp", svc, product, version, banner)
            )
        return findings

    def _grab_banner(self, ctx: ModuleContext, host: str, port: int):
        """Best-effort banner grab; returns (banner, product, version)."""
        ctx.rate()
        ctx.audit.record("banner", host, port=port)
        data = b""
        try:
            sock = socket.create_connection((host, port), timeout=ctx.config.timeout)
            if port in (443, 8443, 993, 995, 465):
                sctx = ssl._create_unverified_context()
                sock = sctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(ctx.config.timeout)
            # nudge text protocols into speaking
            if port in (80, 8080, 8000, 8888, 3000, 9000):
                sock.sendall(
                    f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                )
            try:
                data = sock.recv(2048)
            except Exception:
                pass
            sock.close()
        except Exception:
            return "", "", ""
        banner = data.decode("latin-1", "replace").strip()
        product, version = _guess_version(banner)
        return banner[:400], product, version

    # ------------------------------------------------------------------ #
    def _record_port(
        self,
        ctx: ModuleContext,
        host: str,
        port: int,
        proto: str,
        svc: str,
        product: str,
        version: str,
        banner: str = "",
    ) -> list[Finding]:
        svc_desc = " ".join(p for p in (product, version) if p) or svc or "unknown"
        evidence = {
            "port": port,
            "protocol": proto,
            "service": svc,
            "product": product,
            "version": version,
        }
        if banner:
            evidence["banner"] = banner

        # stash for CVE correlation
        if product:
            ctx.state["services"].append(
                {"host": host, "port": port, "product": product, "version": version}
            )

        findings = [
            ctx.emit(
                Finding(
                    category=Category.PORT,
                    title=f"{host}:{port}/{proto} open ({svc_desc})",
                    severity=Severity.INFO,
                    target=host,
                    description="Open port / detected service.",
                    evidence=evidence,
                    module=self.name,
                )
            )
        ]
        if port in SENSITIVE_PORTS:
            title, sev = SENSITIVE_PORTS[port]
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.MISCONFIG,
                        title=f"{host}: {title}",
                        severity=sev,
                        target=host,
                        description=(
                            "A sensitive service is reachable over the network. "
                            "Confirm it requires authentication and is firewalled "
                            "to trusted sources."
                        ),
                        evidence=evidence,
                        module=self.name,
                    )
                )
            )
        ctx.log(f"{host}:{port} open — {svc_desc}")
        return findings


def _guess_version(banner: str) -> tuple[str, str]:
    """Extract a rough (product, version) from a raw banner string."""
    import re

    if not banner:
        return "", ""
    # SSH-2.0-OpenSSH_8.9p1 ; Server: nginx/1.18.0 ; etc.
    m = re.search(r"(OpenSSH|nginx|Apache|lighttpd|Microsoft-IIS|Exim|Postfix|"
                  r"vsftpd|ProFTPD|MySQL|PostgreSQL|Redis|MongoDB)[/_ ]?"
                  r"([0-9]+(?:\.[0-9]+){0,3}[a-z0-9]*)", banner, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r"Server:\s*([^\r\n/]+)/([0-9][0-9A-Za-z.\-]*)", banner, re.IGNORECASE)
    if m:
        return m.group(1).strip(), m.group(2)
    return "", ""
