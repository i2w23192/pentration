"""Certificate discovery + CT-log monitoring (passive).

Collects certificates observed for the target domain from Certificate
Transparency logs (via crt.sh JSON): issuers, validity windows, and all SAN
names (which surface additional subdomains, fed back into shared state).

**CT monitoring (diff mode):** each run records a baseline of the certificate
identities seen (crt.sh entry IDs) under the output directory. On a later run it
diffs against that baseline and flags **newly-issued certificates** since the
last scan — an early warning for shadow infrastructure or unauthorized issuance.

Entirely passive: it reads public CT-log data, nothing is sent to the target.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity
from allscan.utils import is_ip

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None

CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"


class CertsModule(Module):
    name = "certs"
    label = "Certificate / CT-log Discovery"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        if is_ip(ctx.target):
            ctx.log("Target is an IP; CT-log discovery needs a domain. Skipping.")
            return []
        if requests is None:
            return [ctx.emit(Finding(
                category=Category.CERT, title="Skipped: requests not installed",
                severity=Severity.INFO, target=ctx.target,
                description="Install requests to enable CT-log discovery.",
                module=self.name))]

        entries = self._fetch_crtsh(ctx)
        if not entries:
            ctx.log("No CT-log entries returned.")
            return []

        findings: list[Finding] = []
        sans: set[str] = set()
        issuers: dict[str, int] = {}
        ids: set[str] = set()
        wildcard = False
        for e in entries:
            eid = str(e.get("id", ""))
            if eid:
                ids.add(eid)
            issuer = (e.get("issuer_name") or "").strip()
            if issuer:
                issuers[issuer] = issuers.get(issuer, 0) + 1
            for name in str(e.get("name_value", "")).splitlines():
                name = name.strip().lower()
                if name.startswith("*."):
                    wildcard = True
                    name = name[2:]
                if name.endswith(ctx.target) and "@" not in name:
                    sans.add(name)

        # feed new subdomains to shared state for downstream modules
        ctx.state.setdefault("hosts", {})
        new_hosts = [s for s in sans if s not in ctx.state["hosts"]]
        for s in new_hosts:
            ctx.state["hosts"].setdefault(s, [])

        findings.append(ctx.emit(Finding(
            category=Category.CERT,
            title=f"CT logs: {len(entries)} certs, {len(sans)} SAN name(s), "
                  f"{len(issuers)} issuer(s)",
            severity=Severity.INFO,
            target=ctx.target,
            description="Certificates observed for the domain in CT logs.",
            evidence={"cert_count": len(entries), "san_count": len(sans),
                      "issuers": sorted(issuers, key=issuers.get, reverse=True)[:10],
                      "wildcard": wildcard,
                      "sample_sans": sorted(sans)[:50]},
            module=self.name,
        )))
        if wildcard:
            findings.append(ctx.emit(Finding(
                category=Category.CERT, title="Wildcard certificate observed",
                severity=Severity.INFO, target=ctx.target,
                description="A wildcard certificate (*.domain) is in use.",
                evidence={"domain": ctx.target}, module=self.name)))

        findings.extend(self._ct_diff(ctx, ids))
        ctx.log(f"CT: {len(entries)} certs, {len(sans)} SANs, {len(new_hosts)} new name(s).")
        return findings

    # ------------------------------------------------------------------ #
    def _fetch_crtsh(self, ctx: ModuleContext) -> list:
        url = CRTSH.format(domain=ctx.target)
        ctx.rate()
        ctx.audit.record("crtsh", url)
        try:
            resp = requests.get(url, timeout=ctx.config.timeout + 20,
                                headers={"User-Agent": ctx.config.user_agent},
                                verify=ctx.config.verify_tls)
            if resp.status_code != 200 or not resp.text.strip():
                return []
            return resp.json()
        except Exception as exc:
            ctx.log(f"crt.sh query failed: {exc}")
            return []

    def _baseline_path(self, ctx: ModuleContext) -> Path:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in ctx.target)
        return Path(ctx.config.output_dir) / f"allscan_ctbaseline_{safe}.json"

    def _ct_diff(self, ctx: ModuleContext, current_ids: set) -> list[Finding]:
        path = self._baseline_path(ctx)
        previous: set = set()
        if path.exists():
            try:
                previous = set(json.loads(path.read_text()).get("cert_ids", []))
            except Exception:
                previous = set()
        findings: list[Finding] = []
        if previous:
            new_ids = current_ids - previous
            if new_ids:
                findings.append(ctx.emit(Finding(
                    category=Category.CERT,
                    title=f"{len(new_ids)} new certificate(s) issued since last scan",
                    severity=Severity.MEDIUM,
                    target=ctx.target,
                    description="New CT-log entries appeared since the saved baseline — "
                                "possible new/shadow infrastructure or unauthorized issuance.",
                    evidence={"new_cert_ids": sorted(new_ids)[:100],
                              "new_count": len(new_ids),
                              "baseline": str(path)},
                    module=self.name,
                )))
                ctx.log(f"CT monitoring: {len(new_ids)} NEW cert(s) since baseline.")
            else:
                ctx.log("CT monitoring: no new certs since baseline.")
        else:
            ctx.log("CT monitoring: saved first baseline (no prior run to diff).")
        # update baseline
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(
                {"target": ctx.target, "updated": time.time(),
                 "cert_ids": sorted(current_ids)}, default=str))
        except Exception as exc:
            ctx.log(f"Could not write CT baseline: {exc}")
        return findings
