"""Threat-model & compliance roll-up.

Runs late (after surface, before compliance) and, using :mod:`allscan.mapping`,
rolls every finding up into:

* a **risk matrix** (severity x likelihood),
* an **ATT&CK technique** spread + **STRIDE** category spread,
* the **compliance frameworks** touched (OWASP / CWE / NIST / CIS / PCI).

It stashes these in ``ctx.state`` (copied into ``result.meta`` by the engine)
so the report generator can render dedicated sections, and emits a short
summary finding. Pure correlation — no network I/O.
"""

from __future__ import annotations

from allscan.base import Module, ModuleContext
from allscan.mapping import risk_matrix, summarize_mappings
from allscan.models import Category, Finding, Severity


class ThreatModelModule(Module):
    name = "threatmodel"
    label = "Threat Model & Compliance Mapping"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        result = ctx.state.get("_result")
        prior = list(getattr(result, "findings", []) or [])
        if not prior:
            return []
        matrix = risk_matrix(prior)
        mappings = summarize_mappings(prior)
        ctx.state["risk_matrix"] = matrix
        ctx.state["threatmodel"] = mappings

        top = mappings["attack_techniques"][:3]
        top_str = ", ".join(f"{t['technique_id']} ({t['count']})" for t in top)
        high_risk = matrix["high"]["high"] + matrix["high"]["medium"]
        ctx.log(f"Threat model: {len(mappings['attack_techniques'])} ATT&CK techniques, "
                f"STRIDE={mappings['stride']}, top={top_str}")
        return [ctx.emit(Finding(
            category=Category.COMPLIANCE,
            title=f"Threat-model mapping: {len(mappings['attack_techniques'])} ATT&CK "
                  f"technique(s), {high_risk} high-risk finding(s)",
            severity=Severity.INFO,
            target=ctx.target,
            description="MITRE ATT&CK / STRIDE / compliance-framework roll-up and risk "
                        "matrix for this engagement (see evidence; rendered in the report).",
            evidence={"risk_matrix": matrix,
                      "attack_techniques": mappings["attack_techniques"][:15],
                      "stride": mappings["stride"],
                      "compliance_frameworks": mappings["compliance_frameworks"]},
            module=self.name,
        ))]
