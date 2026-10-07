"""Optional external scanner integrations.

Wraps well-known tools *when they are installed and explicitly enabled* and
parses their output into allscan's unified Finding model. Nothing here is
required — a tool that isn't on PATH or isn't enabled is simply skipped.

Tools are split by impact:

* **Passive** (OSINT / discovery): ``subfinder``, ``amass`` (passive mode),
  ``httpx`` — run whenever enabled.
* **Active** (send traffic to the target): ``nuclei``, ``nikto``,
  ``sqlmap`` (DETECTION phase only — ``--batch`` with no ``--dump``/``--os-*``),
  ``masscan`` — additionally require the ``--active`` gate and pass the scope
  guard, exactly like the built-in active module.

Enable with ``--integrations subfinder,httpx,nuclei`` (or the ``integrations``
config list). allscan never installs tools and never runs an exploitation mode;
sqlmap in particular is restricted to its detection phase.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional
from urllib.parse import urlparse

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity
from allscan.scope import ScopeGuard

# name -> impact ("passive" | "active")
KNOWN_TOOLS = {
    "subfinder": "passive",
    "amass": "passive",
    "httpx": "passive",
    "nuclei": "active",
    "nikto": "active",
    "sqlmap": "active",
    "masscan": "active",
}

NUCLEI_SEV = {"critical": Severity.HIGH, "high": Severity.HIGH,
              "medium": Severity.MEDIUM, "low": Severity.LOW,
              "info": Severity.INFO, "unknown": Severity.INFO}


class IntegrationsModule(Module):
    name = "integrations"
    label = "Scanner Integrations"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        enabled = [t.lower() for t in (getattr(ctx.config, "integrations", None) or [])]
        if not enabled:
            ctx.log("No scanner integrations enabled (--integrations). Skipping.")
            return []

        guard = ScopeGuard(
            ctx.target,
            allow=list(getattr(ctx.config, "scope_allow", []) or []),
            deny=list(getattr(ctx.config, "scope_deny", []) or []),
        )
        findings: list[Finding] = []
        for tool in enabled:
            if tool not in KNOWN_TOOLS:
                ctx.log(f"Unknown integration '{tool}' — skipping.")
                continue
            if shutil.which(tool) is None:
                findings.append(self._skipped(ctx, tool, "not installed / not on PATH"))
                continue
            impact = KNOWN_TOOLS[tool]
            if impact == "active" and not getattr(ctx.config, "active", False):
                findings.append(self._skipped(
                    ctx, tool, "active tool — requires --active"))
                continue
            ctx.cancel.raise_if_cancelled()
            handler = getattr(self, f"_run_{tool}")
            try:
                findings.extend(handler(ctx, guard))
            except Exception as exc:  # one tool must not kill the module
                ctx.log(f"{tool} integration error: {exc}")
        return findings

    # ------------------------------------------------------------------ #
    def _exec(self, ctx, cmd, timeout=600, stdin_data: Optional[str] = None):
        ctx.rate()
        ctx.audit.record("integration_exec", ctx.target, cmd=" ".join(cmd))
        try:
            return subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, check=False,
                                  input=stdin_data)
        except subprocess.TimeoutExpired:
            ctx.log(f"{cmd[0]} timed out.")
            return None
        except Exception as exc:
            ctx.log(f"{cmd[0]} failed: {exc}")
            return None

    def _hosts(self, ctx) -> list[str]:
        hosts = list((ctx.state.get("hosts") or {}).keys())
        return hosts or [ctx.target]

    def _web_urls(self, ctx) -> list[str]:
        urls = list(ctx.state.get("web_hosts") or [])
        return urls or [f"https://{ctx.target}", f"http://{ctx.target}"]

    # ---- passive tools ------------------------------------------------ #
    def _run_subfinder(self, ctx, guard) -> list[Finding]:
        from allscan.utils import is_ip
        if is_ip(ctx.target):
            return []
        proc = self._exec(ctx, ["subfinder", "-silent", "-d", ctx.target], timeout=300)
        if not proc or not proc.stdout:
            return []
        return self._ingest_subdomains(ctx, "subfinder", proc.stdout)

    def _run_amass(self, ctx, guard) -> list[Finding]:
        from allscan.utils import is_ip
        if is_ip(ctx.target):
            return []
        proc = self._exec(ctx, ["amass", "enum", "-passive", "-silent",
                                "-d", ctx.target], timeout=600)
        if not proc or not proc.stdout:
            return []
        return self._ingest_subdomains(ctx, "amass", proc.stdout)

    def _run_httpx(self, ctx, guard) -> list[Finding]:
        hosts = self._hosts(ctx)
        proc = self._exec(ctx, ["httpx", "-silent", "-json", "-no-color"],
                          timeout=300, stdin_data="\n".join(hosts))
        if not proc or not proc.stdout:
            return []
        return parse_httpx(proc.stdout, emit=lambda **kw: self._emit(ctx, **kw))

    # ---- active tools (scope-checked) --------------------------------- #
    def _run_nuclei(self, ctx, guard) -> list[Finding]:
        urls = [u for u in self._web_urls(ctx)
                if guard.check(urlparse(u).hostname or "")]
        if not urls:
            return []
        proc = self._exec(ctx, ["nuclei", "-silent", "-jsonl", "-no-color"],
                          timeout=900, stdin_data="\n".join(urls))
        if not proc or not proc.stdout:
            return []
        return parse_nuclei(proc.stdout, emit=lambda **kw: self._emit(ctx, **kw))

    def _run_nikto(self, ctx, guard) -> list[Finding]:
        out = []
        for host in self._hosts(ctx):
            if not guard.check(host):
                ctx.audit.record("scope_blocked", host, tool="nikto")
                continue
            proc = self._exec(ctx, ["nikto", "-host", host, "-Format", "json",
                                    "-nointeractive"], timeout=900)
            if proc and proc.stdout:
                out += parse_nikto(proc.stdout, host,
                                   emit=lambda **kw: self._emit(ctx, **kw))
        return out

    def _run_sqlmap(self, ctx, guard) -> list[Finding]:
        out = []
        # DETECTION PHASE ONLY: --batch, low level/risk, no --dump / --os-* / --sql-*.
        for url in self._web_urls(ctx):
            if "?" not in url:
                continue
            if not guard.check(urlparse(url).hostname or ""):
                ctx.audit.record("scope_blocked", url, tool="sqlmap")
                continue
            proc = self._exec(ctx, ["sqlmap", "-u", url, "--batch", "--level=1",
                                    "--risk=1", "--smart", "--disable-coloring",
                                    "--flush-session"], timeout=900)
            if proc and proc.stdout:
                out += parse_sqlmap(proc.stdout, url,
                                    emit=lambda **kw: self._emit(ctx, **kw))
        return out

    def _run_masscan(self, ctx, guard) -> list[Finding]:
        out = []
        for host in self._hosts(ctx):
            if not guard.check(host):
                ctx.audit.record("scope_blocked", host, tool="masscan")
                continue
            proc = self._exec(ctx, ["masscan", host, "-p1-1000", "--rate", "1000",
                                    "-oJ", "-"], timeout=600)
            if proc and proc.stdout:
                out += parse_masscan(proc.stdout, emit=lambda **kw: self._emit(ctx, **kw))
        return out

    # ------------------------------------------------------------------ #
    def _ingest_subdomains(self, ctx, tool: str, stdout: str) -> list[Finding]:
        names = [ln.strip().lower() for ln in stdout.splitlines() if ln.strip()]
        names = [n for n in names if n.endswith(ctx.target) and "*" not in n]
        ctx.state.setdefault("hosts", {})
        new = 0
        for n in names:
            if n not in ctx.state["hosts"]:
                ctx.state["hosts"].setdefault(n, [])
                new += 1
        ctx.log(f"{tool}: {len(names)} subdomains ({new} new).")
        if not names:
            return []
        return [self._emit(
            ctx, category=Category.SUBDOMAIN,
            title=f"{tool}: {len(names)} subdomain(s) ({new} new)",
            severity=Severity.INFO, target=ctx.target,
            description=f"Subdomains enumerated by {tool}.",
            evidence={"tool": tool, "count": len(names), "sample": sorted(names)[:50]})]

    def _emit(self, ctx, **kw) -> Finding:
        kw.setdefault("module", self.name)
        return ctx.emit(Finding(**kw))

    def _skipped(self, ctx, tool: str, why: str) -> Finding:
        ctx.log(f"{tool}: skipped ({why}).")
        return self._emit(ctx, category=Category.ACTIVE if KNOWN_TOOLS.get(tool) == "active"
                          else Category.WEB,
                          title=f"Integration skipped: {tool}", severity=Severity.INFO,
                          target=ctx.target, description=f"{tool} not run: {why}.",
                          evidence={"tool": tool, "reason": why})


# --------------------------------------------------------------------------- #
# pure output parsers (unit-testable without the tools installed)
# --------------------------------------------------------------------------- #

def parse_httpx(stdout: str, emit) -> list[Finding]:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        url = d.get("url") or d.get("input") or ""
        title = d.get("title", "")
        status = d.get("status_code") or d.get("status-code")
        tech = d.get("tech") or d.get("technologies") or []
        out.append(emit(category=Category.WEB,
                        title=f"httpx: {url} [{status}] {title}".strip(),
                        severity=Severity.INFO, target=url,
                        description="Live HTTP endpoint (httpx).",
                        evidence={"tool": "httpx", "status": status, "title": title,
                                  "tech": tech, "webserver": d.get("webserver", "")}))
    return out


def parse_nuclei(stdout: str, emit) -> list[Finding]:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        info = d.get("info", {})
        sev = NUCLEI_SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        name = info.get("name") or d.get("template-id") or "nuclei finding"
        matched = d.get("matched-at") or d.get("host") or ""
        out.append(emit(category=Category.ACTIVE,
                        title=f"nuclei: {name}",
                        severity=sev, target=matched,
                        description=str(info.get("description", ""))[:400],
                        evidence={"tool": "nuclei", "template": d.get("template-id"),
                                  "matched_at": matched,
                                  "tags": info.get("tags", [])},
                        location=matched, confidence="medium",
                        note="manual validation required"))
    return out


def parse_nikto(stdout: str, host: str, emit) -> list[Finding]:
    out = []
    try:
        data = json.loads(stdout)
    except Exception:
        return out
    # nikto JSON: {"vulnerabilities":[{"id","msg","url","method"}...]} (per host)
    runs = data if isinstance(data, list) else [data]
    for run in runs:
        for v in (run.get("vulnerabilities") or []):
            out.append(emit(category=Category.ACTIVE,
                            title=f"nikto: {v.get('msg', '')[:120]}",
                            severity=Severity.LOW, target=host,
                            description=str(v.get("msg", ""))[:400],
                            evidence={"tool": "nikto", "id": v.get("id"),
                                      "url": v.get("url"), "method": v.get("method")},
                            location=v.get("url") or host, confidence="low",
                            note="manual validation required"))
    return out


def parse_sqlmap(stdout: str, url: str, emit) -> list[Finding]:
    """Detect-phase sqlmap: flag only the 'parameter is/ might be injectable'
    signal. We never run or parse data-extraction output."""
    import re as _re
    out = []
    text = stdout.lower()
    m = _re.search(r"parameter '([^']+)'.*?(?:is vulnerable|appears to be injectable|"
                   r"might be injectable|is injectable)", text, _re.DOTALL)
    positive = ("is vulnerable" in text
                or bool(_re.search(r"(?:appears to be|might be|is) injectable", text)))
    if positive:
        param = m.group(1) if m else ""
        out.append(emit(category=Category.ACTIVE,
                        title=f"sqlmap: parameter appears injectable"
                              + (f" ('{param}')" if param else ""),
                        severity=Severity.HIGH, target=url,
                        description="sqlmap detection phase reported an injectable "
                                    "parameter. Detection only — no data extraction was run.",
                        evidence={"tool": "sqlmap", "param": param,
                                  "phase": "detection"},
                        location=f"{url} [param={param}]" if param else url,
                        confidence="medium", note="manual validation required"))
    return out


def parse_masscan(stdout: str, emit) -> list[Finding]:
    out = []
    try:
        data = json.loads(stdout)
    except Exception:
        # masscan -oJ emits a JSON array that may have a trailing comma; retry
        try:
            data = json.loads("[" + stdout.strip().strip(",").lstrip("[").rstrip("]") + "]")
        except Exception:
            return out
    for rec in data if isinstance(data, list) else []:
        ip = rec.get("ip", "")
        for p in rec.get("ports", []):
            port = p.get("port")
            out.append(emit(category=Category.PORT,
                            title=f"masscan: {ip}:{port}/{p.get('proto','tcp')} open",
                            severity=Severity.INFO, target=ip,
                            description="Open port (masscan).",
                            evidence={"tool": "masscan", "port": port,
                                      "proto": p.get("proto")}))
    return out
