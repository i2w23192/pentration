"""WAF / CDN detection and rate-limit observation.

* **WAF/CDN fingerprint** — inspects response headers, cookies and server
  banners (from the web module's captured pages, or a fresh root request) for
  signatures of common WAFs/CDNs: Cloudflare, Akamai, AWS CloudFront/WAF,
  Fastly, Sucuri, Imperva/Incapsula, F5 BIG-IP, Barracuda, ModSecurity, etc.

* **Rate-limit observation** — makes a *small, bounded* burst of requests to the
  root (capped, and still subject to the global rate limiter) and notes whether
  the server responded with HTTP 429 / Retry-After or similar. This is
  observational only: it does not try to find or exceed the actual limit.

Knowing a WAF/CDN sits in front matters because it changes how other findings
should be interpreted (origin vs. edge). All detection-only.
"""

from __future__ import annotations

import re
from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity

try:
    import requests  # type: ignore
    from requests.exceptions import RequestException  # type: ignore
except Exception:  # pragma: no cover
    requests = None
    RequestException = Exception


# label -> list of (header-or-cookie name regex, value regex or "")
WAF_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "Cloudflare": [("server", "cloudflare"), ("cf-ray", ""), ("cf-cache-status", "")],
    "Akamai": [("server", "akamai"), ("x-akamai-transformed", ""), ("x-akamai-request-id", "")],
    "AWS CloudFront": [("server", "cloudfront"), ("x-amz-cf-id", ""), ("via", "cloudfront")],
    "AWS WAF": [("x-amzn-requestid", ""), ("x-amz-apigw-id", "")],
    "Fastly": [("x-served-by", "cache-"), ("x-fastly-request-id", ""), ("fastly-io-info", "")],
    "Sucuri": [("x-sucuri-id", ""), ("x-sucuri-cache", ""), ("server", "sucuri")],
    "Imperva/Incapsula": [("x-iinfo", ""), ("x-cdn", "incapsula"), ("set-cookie", "incap_ses|visid_incap")],
    "F5 BIG-IP": [("set-cookie", "BIGipServer"), ("server", "big-?ip")],
    "Barracuda": [("set-cookie", "barra_counter_session")],
    "ModSecurity": [("server", "mod_security|modsecurity")],
    "Varnish": [("x-varnish", ""), ("via", "varnish")],
    "Fortinet FortiWeb": [("set-cookie", "FORTIWAFSID")],
}


class WafModule(Module):
    name = "waf"
    label = "WAF/CDN & Rate-limit Detection"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        if requests is None:
            return [
                ctx.emit(
                    Finding(
                        category=Category.WAF,
                        title="Skipped: requests not installed",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="Install requests to enable WAF/CDN detection.",
                        module=self.name,
                    )
                )
            ]
        findings: list[Finding] = []
        headers = self._root_headers(ctx)
        if headers is not None:
            findings.extend(self._fingerprint(ctx, headers))
        findings.extend(self._rate_limit_observe(ctx))
        return findings

    # ------------------------------------------------------------------ #
    def _root_headers(self, ctx: ModuleContext) -> Optional[dict]:
        pages = ctx.state.get("pages") or {}
        for base, page in pages.items():
            if page.get("headers"):
                return page["headers"]
        # fallback: fetch the root
        for scheme in ("https", "http"):
            url = f"{scheme}://{ctx.target}"
            ctx.rate()
            ctx.audit.record("http_get", url)
            try:
                resp = requests.get(url, timeout=ctx.config.timeout,
                                    headers={"User-Agent": ctx.config.user_agent},
                                    verify=ctx.config.verify_tls)
                return dict(resp.headers)
            except RequestException:
                continue
        return None

    def _fingerprint(self, ctx: ModuleContext, headers: dict) -> list[Finding]:
        lowered = {k.lower(): str(v) for k, v in headers.items()}
        blob = "\n".join(f"{k}: {v}" for k, v in lowered.items())
        detected: list[str] = []
        for waf, sigs in WAF_SIGNATURES.items():
            for name_re, val_re in sigs:
                for hname, hval in lowered.items():
                    if re.search(name_re, hname):
                        if not val_re or re.search(val_re, hval, re.IGNORECASE):
                            detected.append(waf)
                            break
                if waf in detected:
                    break
        detected = list(dict.fromkeys(detected))
        if not detected:
            ctx.log("No WAF/CDN signature matched in response headers.")
            return [
                ctx.emit(
                    Finding(
                        category=Category.WAF,
                        title="No WAF/CDN fingerprint detected",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="No known WAF/CDN signature in response headers "
                                    "(origin may be directly exposed, or signatures stripped).",
                        evidence={"checked": list(WAF_SIGNATURES.keys())},
                        module=self.name,
                    )
                )
            ]
        ctx.log(f"WAF/CDN detected: {', '.join(detected)}")
        return [
            ctx.emit(
                Finding(
                    category=Category.WAF,
                    title=f"WAF/CDN detected: {', '.join(detected)}",
                    severity=Severity.INFO,
                    target=ctx.target,
                    description="A WAF/CDN sits in front of the target; interpret other "
                                "findings as edge rather than origin behaviour.",
                    evidence={"detected": detected},
                    module=self.name,
                )
            )
        ]

    def _rate_limit_observe(self, ctx: ModuleContext) -> list[Finding]:
        """Bounded, polite observation — a few requests, watching for 429."""
        url = f"https://{ctx.target}"
        burst = min(5, max(2, ctx.config.threads // 4))
        statuses: list[int] = []
        retry_after = None
        for _ in range(burst):
            if ctx.cancel.cancelled():
                break
            ctx.rate()  # still honour the global limiter
            ctx.audit.record("http_get", url, note="rate-limit-observe")
            try:
                resp = requests.get(url, timeout=ctx.config.timeout,
                                    headers={"User-Agent": ctx.config.user_agent},
                                    verify=ctx.config.verify_tls)
            except RequestException:
                url = f"http://{ctx.target}"
                continue
            statuses.append(resp.status_code)
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                break
        if 429 in statuses:
            return [
                ctx.emit(
                    Finding(
                        category=Category.WAF,
                        title="Rate limiting observed (HTTP 429)",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="The server returned 429 Too Many Requests during a "
                                    "small request burst — rate limiting is in effect.",
                        evidence={"statuses": statuses, "retry_after": retry_after,
                                  "requests_sent": len(statuses)},
                        module=self.name,
                    )
                )
            ]
        if statuses:
            ctx.log(f"No rate limiting observed in {len(statuses)} requests.")
            return [
                ctx.emit(
                    Finding(
                        category=Category.WAF,
                        title="No rate limiting observed",
                        severity=Severity.LOW,
                        target=ctx.target,
                        description=f"No HTTP 429 across {len(statuses)} bounded requests. "
                                    "allscan does not probe aggressively, so this is "
                                    "informational, not a definitive absence.",
                        evidence={"statuses": statuses},
                        module=self.name,
                    )
                )
            ]
        return []
