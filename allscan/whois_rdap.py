"""WHOIS / RDAP registration lookup (passive).

Queries RDAP (structured JSON, via the bootstrap at rdap.org) for the target
domain and its resolved IPs, falling back to classic WHOIS over port 43 when
RDAP is unavailable. Extracts registrar, key dates, status flags, name servers
and (non-redacted) registrant org, and flags registration hygiene issues:

* domain expiring soon,
* very recently registered (a common phishing / typosquat signal).

Registry name is ``whois``; the file is ``whois_rdap`` to avoid clashing with
any installed ``whois`` package. Read-only — no data is modified.
"""

from __future__ import annotations

import datetime
import socket
from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity
from allscan.utils import is_ip

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None

RDAP_DOMAIN = "https://rdap.org/domain/"
RDAP_IP = "https://rdap.org/ip/"


class WhoisModule(Module):
    name = "whois"
    label = "WHOIS / RDAP"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        if is_ip(ctx.target):
            findings.extend(self._ip_rdap(ctx, ctx.target))
            return findings
        findings.extend(self._domain_rdap(ctx))
        # also RDAP the first resolved IP for netblock ownership
        hosts = ctx.state.get("hosts") or {}
        first_ip = None
        for ips in hosts.values():
            if ips:
                first_ip = ips[0]
                break
        if first_ip:
            findings.extend(self._ip_rdap(ctx, first_ip))
        return findings

    # ------------------------------------------------------------------ #
    def _domain_rdap(self, ctx: ModuleContext) -> list[Finding]:
        data = self._rdap_get(ctx, RDAP_DOMAIN + ctx.target)
        if data is None:
            return self._whois43(ctx)
        events = {e.get("eventAction"): e.get("eventDate")
                  for e in data.get("events", []) if isinstance(e, dict)}
        registrar = ""
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles:
                registrar = self._vcard_name(ent) or ent.get("handle", "")
                break
        nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
        status = data.get("status", [])
        registered = events.get("registration")
        expires = events.get("expiration")

        findings = [
            ctx.emit(Finding(
                category=Category.WHOIS,
                title=f"Domain registration: {registrar or 'registrar n/a'}",
                severity=Severity.INFO,
                target=ctx.target,
                description="RDAP registration data for the domain.",
                evidence={"registrar": registrar, "registered": registered,
                          "expires": expires, "status": status,
                          "nameservers": [n for n in nameservers if n],
                          "source": "rdap"},
                module=self.name,
            ))
        ]
        findings += self._date_flags(ctx, registered, expires)
        ctx.log(f"RDAP: registrar={registrar or 'n/a'}, expires={expires or 'n/a'}")
        return findings

    def _ip_rdap(self, ctx: ModuleContext, ip: str) -> list[Finding]:
        data = self._rdap_get(ctx, RDAP_IP + ip)
        if data is None:
            return []
        name = data.get("name", "")
        handle = data.get("handle", "")
        start, end = data.get("startAddress"), data.get("endAddress")
        cidr = ""
        for c in data.get("cidr0_cidrs", []) or []:
            if c.get("v4prefix"):
                cidr = f"{c['v4prefix']}/{c.get('length')}"
            elif c.get("v6prefix"):
                cidr = f"{c['v6prefix']}/{c.get('length')}"
        org = ""
        for ent in data.get("entities", []):
            org = self._vcard_name(ent) or org
            if org:
                break
        return [ctx.emit(Finding(
            category=Category.WHOIS,
            title=f"IP netblock: {name or handle or ip} ({org or 'org n/a'})",
            severity=Severity.INFO,
            target=ip,
            description="RDAP registration data for the IP netblock.",
            evidence={"ip": ip, "network_name": name, "handle": handle,
                      "range": f"{start}-{end}" if start else "", "cidr": cidr,
                      "org": org, "source": "rdap"},
            module=self.name,
        ))]

    def _date_flags(self, ctx, registered: Optional[str], expires: Optional[str]) -> list[Finding]:
        out: list[Finding] = []
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = _parse_dt(expires)
        if exp:
            days = (exp - now).days
            if days < 0:
                out.append(self._flag(ctx, "Domain registration expired",
                                      Severity.HIGH, {"expires": expires, "days": days}))
            elif days < 30:
                out.append(self._flag(ctx, f"Domain expires in {days} days",
                                      Severity.MEDIUM, {"expires": expires, "days": days}))
        reg = _parse_dt(registered)
        if reg:
            age = (now - reg).days
            if age < 90:
                out.append(self._flag(
                    ctx, f"Domain recently registered ({age} days ago)",
                    Severity.LOW,
                    {"registered": registered, "age_days": age,
                     "note": "recent registration can indicate phishing/typosquat"}))
        return out

    def _flag(self, ctx, title, sev, ev) -> Finding:
        return ctx.emit(Finding(category=Category.WHOIS, title=title, severity=sev,
                                target=ctx.target, description="Registration hygiene flag.",
                                evidence=ev, module=self.name))

    # ------------------------------------------------------------------ #
    def _rdap_get(self, ctx: ModuleContext, url: str) -> Optional[dict]:
        if requests is None:
            return None
        ctx.rate()
        ctx.audit.record("rdap_query", url)
        try:
            resp = requests.get(url, timeout=ctx.config.timeout + 10,
                                headers={"User-Agent": ctx.config.user_agent,
                                         "Accept": "application/rdap+json"},
                                verify=ctx.config.verify_tls)
            if resp.status_code != 200:
                return None
            return resp.json()
        except Exception as exc:
            ctx.log(f"RDAP query failed ({url}): {exc}")
            return None

    @staticmethod
    def _vcard_name(entity: dict) -> str:
        vcard = entity.get("vcardArray")
        if not vcard or len(vcard) < 2:
            return ""
        for item in vcard[1]:
            if isinstance(item, list) and item and item[0] in ("fn", "org"):
                return str(item[3]) if len(item) > 3 else ""
        return ""

    def _whois43(self, ctx: ModuleContext) -> list[Finding]:
        """Minimal WHOIS-over-43 fallback via IANA referral."""
        ctx.rate()
        ctx.audit.record("whois43", ctx.target)
        text = self._whois_query("whois.iana.org", ctx.target, ctx.config.timeout)
        server = ""
        for line in (text or "").splitlines():
            if line.lower().startswith("whois:"):
                server = line.split(":", 1)[1].strip()
                break
        if server:
            text = self._whois_query(server, ctx.target, ctx.config.timeout) or text
        if not text:
            ctx.log("WHOIS fallback returned nothing.")
            return []
        return [ctx.emit(Finding(
            category=Category.WHOIS,
            title="WHOIS record (port-43 fallback)",
            severity=Severity.INFO,
            target=ctx.target,
            description="Raw WHOIS data (RDAP was unavailable).",
            evidence={"source": "whois43", "server": server,
                      "excerpt": "\n".join((text or "").splitlines()[:40])},
            module=self.name,
        ))]

    @staticmethod
    def _whois_query(server: str, query: str, timeout: float) -> Optional[str]:
        try:
            with socket.create_connection((server, 43), timeout=timeout) as s:
                s.sendall((query + "\r\n").encode())
                chunks = []
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
            return b"".join(chunks).decode("utf-8", "replace")
        except Exception:
            return None


def _parse_dt(value: Optional[str]) -> Optional[datetime.datetime]:
    if not value:
        return None
    v = value.strip().replace("Z", "+00:00")
    for fmt in (None,):  # try fromisoformat first
        try:
            dt = datetime.datetime.fromisoformat(v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except ValueError:
            pass
    for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d"):
        try:
            return datetime.datetime.strptime(value[:10], fmt).replace(
                tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None
