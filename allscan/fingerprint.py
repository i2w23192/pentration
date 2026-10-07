"""API & technology fingerprinting.

* **API endpoints** — probes a small set of common API/doc locations
  (``/api``, ``/graphql``, ``/swagger.json``, ``/openapi.json``,
  ``/.well-known/openapi`` …) and flags exposed API surface / interactive docs.
* **CMS detection with version** — WordPress, Drupal, Joomla, Magento, Ghost,
  etc., from body markers, meta generator tags and well-known paths; extracts a
  version where the generator tag or readme exposes one.
* **Framework / library fingerprinting** — server-side framework and front-end
  library hints from headers and response patterns.

Reuses the HTTP responses the web module captured (``ctx.state['pages']``) and
makes a few extra GETs for the API/CMS probes. Detection-only — it reads
responses and never submits queries, mutations or auth.
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


API_PROBES: list[tuple[str, Severity, str]] = [
    ("api", Severity.INFO, "API root reachable"),
    ("api/v1", Severity.INFO, "API v1 reachable"),
    ("api/v2", Severity.INFO, "API v2 reachable"),
    ("graphql", Severity.LOW, "GraphQL endpoint exposed"),
    ("graphiql", Severity.MEDIUM, "GraphiQL interface exposed"),
    ("swagger.json", Severity.LOW, "Swagger spec exposed"),
    ("swagger-ui.html", Severity.LOW, "Swagger UI exposed"),
    ("openapi.json", Severity.LOW, "OpenAPI spec exposed"),
    ("api-docs", Severity.LOW, "API docs exposed"),
    ("v2/api-docs", Severity.LOW, "Springfox API docs exposed"),
    (".well-known/openapi.json", Severity.LOW, "OpenAPI (well-known) exposed"),
    ("api/swagger.json", Severity.LOW, "Swagger spec exposed"),
]

# CMS markers: name -> (body/header regexes, generator regex for version)
CMS_SIGNATURES = {
    "WordPress": (
        [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        r'name="generator" content="WordPress ([0-9.]+)"',
    ),
    "Drupal": (
        [r"Drupal\.settings", r"/sites/default/files", r"X-Generator: Drupal"],
        r'name="generator" content="Drupal ([0-9.]+)',
    ),
    "Joomla": (
        [r"/media/jui/", r"com_content", r"Joomla!"],
        r'name="generator" content="Joomla! ([0-9.]+)',
    ),
    "Magento": (
        [r"/static/version", r"Mage\.", r"magento"],
        r"Magento/([0-9.]+)",
    ),
    "Ghost": (
        [r"content=\"Ghost", r"ghost-url"],
        r'content="Ghost ([0-9.]+)"',
    ),
    "Shopify": ([r"cdn\.shopify\.com", r"Shopify\."], r""),
    "Wix": ([r"X-Wix-", r"wix\.com"], r""),
    "Squarespace": ([r"squarespace", r"Squarespace"], r""),
}

# framework/library hints from headers/body
FRAMEWORK_HINTS: list[tuple[str, str]] = [
    (r"X-Powered-By:\s*Express", "Express (Node.js)"),
    (r"X-Powered-By:\s*PHP/([0-9.]+)", "PHP {0}"),
    (r"X-AspNet-Version:\s*([0-9.]+)", "ASP.NET {0}"),
    (r"X-AspNetMvc-Version:\s*([0-9.]+)", "ASP.NET MVC {0}"),
    (r"Server:\s*gunicorn/?([0-9.]*)", "gunicorn {0}"),
    (r"Server:\s*Werkzeug/?([0-9.]*)", "Werkzeug/Flask {0}"),
    (r"X-Runtime", "Ruby on Rails"),
    (r"X-Drupal-Cache", "Drupal"),
    (r"laravel_session", "Laravel"),
    (r"__NEXT_DATA__", "Next.js"),
    (r"ng-version=\"([0-9.]+)\"", "Angular {0}"),
    (r"data-reactroot", "React"),
    (r"vue(?:\.min)?\.js", "Vue.js"),
]


class FingerprintModule(Module):
    name = "fingerprint"
    label = "API & Tech Fingerprinting"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        if requests is None:
            return [
                ctx.emit(
                    Finding(
                        category=Category.FINGERPRINT,
                        title="Skipped: requests not installed",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="Install requests to enable fingerprinting.",
                        module=self.name,
                    )
                )
            ]
        findings: list[Finding] = []
        pages = ctx.state.get("pages") or {}
        bases = list(pages.keys())
        if not bases:
            # no web module run; probe the target root directly
            bases = [f"https://{ctx.target}", f"http://{ctx.target}"]

        seen_bases = set()
        for base in bases[:25]:
            root = base.rstrip("/")
            if root in seen_bases:
                continue
            seen_bases.add(root)
            ctx.cancel.raise_if_cancelled()
            page = pages.get(base)
            headers_blob, body = self._material(ctx, base, page)
            if headers_blob is None:
                continue
            findings.extend(self._cms(ctx, root, headers_blob, body))
            findings.extend(self._frameworks(ctx, root, headers_blob, body))
            findings.extend(self._api_probes(ctx, root))
        return findings

    # ------------------------------------------------------------------ #
    def _material(self, ctx: ModuleContext, base: str, page: Optional[dict]):
        """Return (headers_blob, body) using cached page or a fresh GET."""
        if page:
            headers = page.get("headers") or {}
            blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
            return blob, page.get("body") or ""
        ctx.rate()
        ctx.audit.record("http_get", base)
        try:
            resp = requests.get(base, timeout=ctx.config.timeout,
                                headers={"User-Agent": ctx.config.user_agent},
                                verify=ctx.config.verify_tls)
        except RequestException:
            return None, ""
        blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        return blob, resp.text or ""

    def _cms(self, ctx: ModuleContext, base: str, headers_blob: str, body: str) -> list[Finding]:
        findings: list[Finding] = []
        haystack = headers_blob + "\n" + body
        for cms, (markers, version_re) in CMS_SIGNATURES.items():
            hits = sum(1 for m in markers if re.search(m, haystack, re.IGNORECASE))
            if hits == 0:
                continue
            version = ""
            if version_re:
                vm = re.search(version_re, haystack, re.IGNORECASE)
                if vm and vm.groups():
                    version = vm.group(1)
            title = f"CMS detected: {cms}" + (f" {version}" if version else "")
            if version:
                ctx.state.setdefault("services", []).append(
                    {"host": base, "port": "", "product": cms, "version": version}
                )
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.FINGERPRINT,
                        title=f"{title} ({base})",
                        severity=Severity.LOW if version else Severity.INFO,
                        target=base,
                        description="Content management system fingerprint"
                                    + (" with version (feeds CVE correlation)." if version else "."),
                        evidence={"cms": cms, "version": version, "markers_matched": hits},
                        module=self.name,
                    )
                )
            )
            ctx.log(f"CMS: {cms} {version} on {base}")
        return findings

    def _frameworks(self, ctx: ModuleContext, base: str, headers_blob: str, body: str) -> list[Finding]:
        findings: list[Finding] = []
        haystack = headers_blob + "\n" + body
        detected: list[str] = []
        for pattern, label in FRAMEWORK_HINTS:
            m = re.search(pattern, haystack, re.IGNORECASE)
            if not m:
                continue
            if "{0}" in label and m.groups():
                detected.append(label.format(m.group(1)).strip())
            else:
                detected.append(label.split(" {0}")[0])
        detected = list(dict.fromkeys(d for d in detected if d))
        if detected:
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.FINGERPRINT,
                        title=f"Frameworks/libraries: {', '.join(detected)} ({base})",
                        severity=Severity.INFO,
                        target=base,
                        description="Server-side framework / front-end library fingerprint.",
                        evidence={"detected": detected},
                        module=self.name,
                    )
                )
            )
            ctx.log(f"Frameworks on {base}: {', '.join(detected)}")
        return findings

    def _api_probes(self, ctx: ModuleContext, base: str) -> list[Finding]:
        findings: list[Finding] = []
        for path, sev, label in API_PROBES:
            if ctx.cancel.cancelled():
                break
            url = f"{base}/{path}"
            ctx.rate()
            ctx.audit.record("http_get", url)
            try:
                resp = requests.get(url, timeout=ctx.config.timeout,
                                    headers={"User-Agent": ctx.config.user_agent},
                                    allow_redirects=False, verify=ctx.config.verify_tls)
            except RequestException:
                continue
            if resp.status_code not in (200, 201, 401, 403):
                continue
            # confirm it looks like API/doc content, not a generic 200 HTML page
            ctype = resp.headers.get("Content-Type", "")
            looks_api = (
                "json" in ctype or "yaml" in ctype
                or "swagger" in resp.text[:2000].lower()
                or "openapi" in resp.text[:2000].lower()
                or path in ("graphql", "graphiql")
                or resp.status_code in (401, 403)
            )
            if not looks_api and path.startswith("api"):
                continue
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.FINGERPRINT,
                        title=f"{label}: {url} [{resp.status_code}]",
                        severity=sev if resp.status_code in (200, 201) else Severity.INFO,
                        target=base,
                        description="API endpoint / documentation surface discovered.",
                        evidence={"url": url, "status": resp.status_code,
                                  "content_type": ctype},
                        module=self.name,
                    )
                )
            )
            ctx.log(f"API: {url} -> {resp.status_code} ({label})")
        return findings
