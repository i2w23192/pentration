"""Vuln-intelligence roll-up (Phase 4 completion).

Enriches the findings already gathered (it runs after CVE correlation and
exploit-reference enrichment) with the remaining vuln-intelligence signals:

* **CPE identification** — derives a CPE 2.3 string for each versioned
  service / CVE finding.
* **Vuln-age tracking** — ages each CVE from its identifier year and flags
  aging high-risk issues (old + KEV/high).
* **Business-impact scoring** — combines finding severity, likelihood
  (KEV/EPSS/active-confirmation via :mod:`allscan.mapping`) and **asset
  criticality** into a 0–100 risk score and a Critical/High/Medium/Low band,
  annotated onto each finding.
* **False-positive management** — fingerprints listed in
  ``config.suppress_fingerprints`` are marked suppressed and excluded from the
  top-risk roll-up.

Annotations are written onto the findings' evidence (no new network I/O); a
risk-scored summary + top-risk list are stashed in ``ctx.state`` for the report.
"""

from __future__ import annotations

import datetime
import re

from allscan.base import Module, ModuleContext
from allscan.mapping import likelihood
from allscan.models import Category, Finding, Severity
from allscan.platform import fingerprint

_SEV_W = {"high": 4, "medium": 3, "low": 2, "info": 1}
_LIKE_W = {"high": 3, "medium": 2, "low": 1}
_CRIT_W = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_MAX = 4 * 3 * 4


def make_cpe(product: str, version: str = "", vendor: str = "") -> str:
    def norm(s):
        return re.sub(r"[^a-z0-9._-]", "_", (s or "").strip().lower()) or "*"
    v = norm(vendor) if vendor else norm(product)
    return f"cpe:2.3:a:{v}:{norm(product)}:{norm(version) if version else '*'}:*:*:*:*:*:*:*"


def cve_age_years(cve_id: str) -> int | None:
    m = re.match(r"cve-(\d{4})-", (cve_id or "").lower())
    if not m:
        return None
    return max(0, datetime.datetime.now().year - int(m.group(1)))


def risk_score(severity: str, like: str, criticality: str) -> tuple[int, str]:
    raw = _SEV_W.get(severity, 1) * _LIKE_W.get(like, 1) * _CRIT_W.get(criticality, 2)
    score = round(raw / _MAX * 100)
    band = ("Critical" if score >= 60 else "High" if score >= 35
            else "Medium" if score >= 15 else "Low")
    return score, band


class VulnIntelModule(Module):
    name = "vulnintel"
    label = "Vuln Intelligence & Risk Scoring"

    def _criticality_for(self, ctx: ModuleContext, target: str) -> str:
        amap = getattr(ctx.config, "asset_criticality", None) or {}
        tl = (target or "").lower()
        for key, band in amap.items():
            if key.lower() in tl:
                return str(band).lower()
        return str(getattr(ctx.config, "default_criticality", "medium")).lower()

    def run(self, ctx: ModuleContext) -> list[Finding]:
        result = ctx.state.get("_result")
        prior = list(getattr(result, "findings", []) or [])
        if not prior:
            return []
        suppress = set(getattr(ctx.config, "suppress_fingerprints", None) or [])

        scored = []
        suppressed = 0
        for f in prior:
            fp = fingerprint(f)
            crit = self._criticality_for(ctx, f.target)
            like = likelihood(f)
            score, band = risk_score(f.severity.value, like, crit)
            f.evidence["asset_criticality"] = crit
            f.evidence["likelihood"] = like
            f.evidence["risk_score"] = score
            f.evidence["risk_band"] = band
            # CPE for versioned product findings
            product = f.evidence.get("product")
            version = f.evidence.get("version")
            if product and f.category in (Category.CVE, Category.SERVICE,
                                          Category.FINGERPRINT, Category.EXPLOITREF):
                f.evidence.setdefault("cpe", make_cpe(product, version or "", ))
            # vuln age for CVEs
            cid = f.evidence.get("cve_id")
            if cid:
                age = cve_age_years(cid)
                if age is not None:
                    f.evidence["age_years"] = age
            if fp in suppress:
                f.evidence["suppressed"] = True
                f.evidence["status"] = "false-positive"
                suppressed += 1
                continue
            scored.append({"fingerprint": fp, "title": f.title,
                           "category": f.category, "severity": f.severity.value,
                           "likelihood": like, "criticality": crit,
                           "risk_score": score, "risk_band": band,
                           "target": f.target, "kev": f.evidence.get("kev", False),
                           "epss": f.evidence.get("epss")})

        scored.sort(key=lambda x: -x["risk_score"])
        top = scored[:15]
        ctx.state["risk_scored"] = scored
        ctx.state["top_risks"] = top

        findings: list[Finding] = []
        # flag aging high-risk CVEs
        for f in prior:
            age = f.evidence.get("age_years")
            if age is not None and age >= 3 and (
                    f.evidence.get("kev") or f.severity.rank >= Severity.HIGH.rank):
                findings.append(ctx.emit(Finding(
                    category=Category.EXPLOITREF,
                    title=f"Aging high-risk vulnerability: {f.evidence.get('cve_id')} "
                          f"({age}y old)",
                    severity=Severity.HIGH if f.evidence.get("kev") else Severity.MEDIUM,
                    target=f.target,
                    description="A high-risk/known-exploited CVE that is several years "
                                "old remains present — long-standing exposure.",
                    evidence={"cve_id": f.evidence.get("cve_id"), "age_years": age,
                              "kev": f.evidence.get("kev", False)},
                    note="manual validation required",
                    module=self.name)))

        crit = sum(1 for s in scored if s["risk_band"] == "Critical")
        high = sum(1 for s in scored if s["risk_band"] == "High")
        findings.insert(0, ctx.emit(Finding(
            category=Category.COMPLIANCE,
            title=f"Risk scoring: {crit} critical / {high} high business-impact finding(s)"
                  + (f", {suppressed} suppressed" if suppressed else ""),
            severity=Severity.INFO,
            target=ctx.target,
            description="Business-impact risk scoring (severity × likelihood × asset "
                        "criticality), CPE identification, vuln-age tracking, and "
                        "false-positive suppression. Top risks are in the report.",
            evidence={"top_risks": top, "scored": len(scored), "suppressed": suppressed,
                      "default_criticality": getattr(ctx.config, "default_criticality", "medium")},
            module=self.name)))
        ctx.log(f"Vuln intel: scored {len(scored)}, {crit} critical / {high} high, "
                f"{suppressed} suppressed.")
        return findings
