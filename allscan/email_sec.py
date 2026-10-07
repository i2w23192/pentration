"""Email / domain security posture.

Checks the presence and basic validity of the three domain-level email
authentication records:

* **SPF**  — a ``v=spf1`` TXT record; flags a missing record and a permissive
  ``+all`` / ``?all`` policy.
* **DMARC** — ``_dmarc.<domain>`` TXT with ``v=DMARC1``; flags a missing record
  and a ``p=none`` (monitor-only) policy.
* **DKIM** — probes a set of common selectors for a ``v=DKIM1`` key and notes
  whether any were found (absence is informational — selectors are arbitrary).

Detection-only: it reads published DNS records and reports gaps. Module name is
``email`` in the registry; the file is ``email_sec`` to avoid shadowing the
Python standard-library ``email`` package.
"""

from __future__ import annotations

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity

try:
    import dns.resolver  # type: ignore
    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False


COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "dkim",
    "mail", "smtp", "s1", "s2", "mandrill", "mailchimp", "sendgrid",
    "amazonses", "zoho", "protonmail", "fm1", "fm2", "fm3",
]


class EmailModule(Module):
    name = "email"
    label = "Email Security (SPF/DKIM/DMARC)"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        from allscan.utils import is_ip

        if is_ip(ctx.target):
            ctx.log("Target is an IP; email posture needs a domain. Skipping.")
            return []
        if not _HAVE_DNS:
            return [
                ctx.emit(
                    Finding(
                        category=Category.EMAIL,
                        title="Skipped: dnspython not installed",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="Install dnspython to enable email posture checks.",
                        module=self.name,
                    )
                )
            ]
        findings: list[Finding] = []
        findings.extend(self._spf(ctx))
        ctx.cancel.raise_if_cancelled()
        findings.extend(self._dmarc(ctx))
        ctx.cancel.raise_if_cancelled()
        findings.extend(self._dkim(ctx))
        return findings

    # ------------------------------------------------------------------ #
    def _txt(self, ctx: ModuleContext, name: str) -> list[str]:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ctx.config.dns_resolvers or resolver.nameservers
        resolver.lifetime = ctx.config.timeout
        ctx.rate()
        ctx.audit.record("dns_query", name, rtype="TXT")
        try:
            answers = resolver.resolve(name, "TXT")
        except Exception:
            return []
        out = []
        for r in answers:
            out.append("".join(s.decode() if isinstance(s, bytes) else str(s)
                               for s in getattr(r, "strings", [])) or r.to_text().strip('"'))
        return out

    def _spf(self, ctx: ModuleContext) -> list[Finding]:
        records = [t for t in self._txt(ctx, ctx.target) if t.lower().startswith("v=spf1")]
        if not records:
            ctx.log("No SPF record.")
            return [self._fail("Missing SPF record", Severity.MEDIUM, ctx,
                               "No v=spf1 TXT record; senders cannot verify authorized "
                               "mail servers, aiding spoofing.", {"record": "SPF"})]
        spf = records[0]
        findings = [self._ok("SPF record present", ctx, {"spf": spf})]
        lowered = spf.lower()
        if "+all" in lowered or lowered.rstrip().endswith("?all"):
            findings.append(
                self._fail("Permissive SPF policy", Severity.MEDIUM, ctx,
                           "SPF ends with +all/?all, which authorizes any sender.",
                           {"spf": spf})
            )
        elif "~all" not in lowered and "-all" not in lowered:
            findings.append(
                self._fail("SPF has no all mechanism", Severity.LOW, ctx,
                           "SPF record lacks a terminating ~all/-all; policy is undefined "
                           "for unlisted senders.", {"spf": spf})
            )
        return findings

    def _dmarc(self, ctx: ModuleContext) -> list[Finding]:
        records = [t for t in self._txt(ctx, f"_dmarc.{ctx.target}")
                   if t.lower().startswith("v=dmarc1")]
        if not records:
            ctx.log("No DMARC record.")
            return [self._fail("Missing DMARC record", Severity.MEDIUM, ctx,
                               "No _dmarc TXT record; recipients have no policy for "
                               "handling unauthenticated mail.", {"record": "DMARC"})]
        dmarc = records[0]
        findings = [self._ok("DMARC record present", ctx, {"dmarc": dmarc})]
        policy = ""
        for part in dmarc.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                policy = part.split("=", 1)[1].strip().lower()
        if policy == "none":
            findings.append(
                self._fail("DMARC policy is p=none (monitor only)", Severity.LOW, ctx,
                           "DMARC is in monitor mode; spoofed mail is not quarantined "
                           "or rejected.", {"dmarc": dmarc, "policy": policy})
            )
        return findings

    def _dkim(self, ctx: ModuleContext) -> list[Finding]:
        found = []
        for selector in COMMON_DKIM_SELECTORS:
            ctx.cancel.raise_if_cancelled()
            name = f"{selector}._domainkey.{ctx.target}"
            for txt in self._txt(ctx, name):
                if "v=dkim1" in txt.lower() or "k=rsa" in txt.lower() or "p=" in txt.lower():
                    found.append(selector)
                    break
        if found:
            ctx.log(f"DKIM selectors found: {', '.join(found)}")
            return [self._ok(f"DKIM key(s) found ({len(found)} selector(s))", ctx,
                             {"selectors": found})]
        ctx.log("No DKIM key found on common selectors (selectors are arbitrary).")
        return [
            ctx.emit(
                Finding(
                    category=Category.EMAIL,
                    title="No DKIM key on common selectors",
                    severity=Severity.LOW,
                    target=ctx.target,
                    description=(
                        "No DKIM key found on common selectors. Selectors are arbitrary, "
                        "so this is informational — DKIM may use a custom selector."
                    ),
                    evidence={"checked_selectors": COMMON_DKIM_SELECTORS},
                    module=self.name,
                )
            )
        ]

    # ------------------------------------------------------------------ #
    def _ok(self, title: str, ctx: ModuleContext, evidence: dict) -> Finding:
        return ctx.emit(
            Finding(category=Category.EMAIL, title=title, severity=Severity.INFO,
                    target=ctx.target, description="Email authentication record present.",
                    evidence=evidence, module=self.name)
        )

    def _fail(self, title: str, sev: Severity, ctx: ModuleContext,
              desc: str, evidence: dict) -> Finding:
        return ctx.emit(
            Finding(category=Category.EMAIL, title=title, severity=sev,
                    target=ctx.target, description=desc, evidence=evidence,
                    module=self.name)
        )
