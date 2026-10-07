"""Web enumeration & content discovery.

For every discovered host this module:

* probes HTTP and HTTPS (status, title, redirect chain)
* fingerprints a tech stack from headers and body markers
* brute-forces a curated list of common/sensitive paths (``.git/``, ``.env``,
  backups, config files, admin panels) and flags directory listing
* hands page source to :mod:`allscan.headers` indirectly by storing it in
  shared state for the HTML analysis module

All requests go through the global rate limiter and are audited.
"""

from __future__ import annotations

import concurrent.futures
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


# Paths that frequently expose secrets or sensitive functionality when present.
SENSITIVE_PATHS: list[tuple[str, Severity, str]] = [
    (".git/HEAD", Severity.HIGH, "Exposed .git repository"),
    (".git/config", Severity.HIGH, "Exposed .git config"),
    (".env", Severity.HIGH, "Exposed .env file (likely secrets)"),
    (".env.local", Severity.HIGH, "Exposed .env.local file"),
    ("config.php", Severity.MEDIUM, "Exposed config.php"),
    ("wp-config.php", Severity.HIGH, "Exposed wp-config.php"),
    ("config.yaml", Severity.MEDIUM, "Exposed config.yaml"),
    ("config.json", Severity.MEDIUM, "Exposed config.json"),
    ("docker-compose.yml", Severity.MEDIUM, "Exposed docker-compose.yml"),
    ("Dockerfile", Severity.LOW, "Exposed Dockerfile"),
    ("backup.zip", Severity.MEDIUM, "Exposed backup archive"),
    ("backup.sql", Severity.HIGH, "Exposed SQL dump"),
    ("db.sql", Severity.HIGH, "Exposed SQL dump"),
    ("dump.sql", Severity.HIGH, "Exposed SQL dump"),
    (".htpasswd", Severity.HIGH, "Exposed .htpasswd"),
    (".svn/entries", Severity.MEDIUM, "Exposed .svn metadata"),
    (".DS_Store", Severity.LOW, "Exposed .DS_Store"),
    ("phpinfo.php", Severity.MEDIUM, "Exposed phpinfo()"),
    ("server-status", Severity.MEDIUM, "Apache server-status exposed"),
    ("actuator", Severity.MEDIUM, "Spring Boot actuator exposed"),
    ("actuator/env", Severity.HIGH, "Spring Boot actuator/env (secrets)"),
    ("swagger-ui.html", Severity.LOW, "Swagger UI exposed"),
    ("api/swagger.json", Severity.LOW, "Swagger spec exposed"),
    ("robots.txt", Severity.INFO, "robots.txt"),
    ("sitemap.xml", Severity.INFO, "sitemap.xml"),
    ("admin/", Severity.LOW, "Admin path reachable"),
    ("login", Severity.INFO, "Login page"),
    ("wp-login.php", Severity.LOW, "WordPress login"),
    ("phpmyadmin/", Severity.MEDIUM, "phpMyAdmin reachable"),
    (".well-known/security.txt", Severity.INFO, "security.txt present"),
]

# body/header markers -> technology label
TECH_MARKERS: list[tuple[str, str]] = [
    ("x-powered-by", "{value}"),
    ("wp-content", "WordPress"),
    ("Drupal.settings", "Drupal"),
    ("/sites/default/files", "Drupal"),
    ("joomla", "Joomla"),
    ("__NEXT_DATA__", "Next.js"),
    ("ng-version", "Angular"),
    ("data-reactroot", "React"),
    ("csrf-param", "Ruby on Rails"),
    ("laravel_session", "Laravel"),
    ("django", "Django"),
    ("jsessionid", "Java/Servlet"),
    ("x-aspnet-version", "ASP.NET"),
]


class WebModule(Module):
    name = "web"
    label = "Web Enumeration"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        if requests is None:
            ctx.log("requests not installed; web enumeration unavailable.")
            return [
                Finding(
                    category=Category.WEB,
                    title="Skipped: requests not installed",
                    severity=Severity.INFO,
                    target=ctx.target,
                    description="Install requests to enable web enumeration.",
                    module=self.name,
                )
            ]

        findings: list[Finding] = []
        hosts = list((ctx.state.get("hosts") or {ctx.target: []}).keys())
        ctx.state.setdefault("web_hosts", [])

        for host in hosts[:50]:
            ctx.cancel.raise_if_cancelled()
            for scheme in ("https", "http"):
                base = f"{scheme}://{host}"
                live = self._probe(ctx, base)
                if not live:
                    continue
                findings.extend(live["findings"])
                ctx.state["web_hosts"].append(base)
                # store page source for HTML analysis module
                ctx.state.setdefault("pages", {})[base] = {
                    "body": live["body"],
                    "headers": live["headers"],
                    "status": live["status"],
                    "cookies": live["cookies"],
                }
                findings.extend(self._dir_bruteforce(ctx, base))
                # only need one working scheme per host for content discovery
                break
        return findings

    # ------------------------------------------------------------------ #
    def _probe(self, ctx: ModuleContext, base: str) -> Optional[dict]:
        ctx.rate()
        ctx.audit.record("http_get", base)
        try:
            resp = requests.get(
                base,
                timeout=ctx.config.timeout,
                headers={"User-Agent": ctx.config.user_agent},
                allow_redirects=ctx.config.follow_redirects,
                verify=ctx.config.verify_tls,
            )
        except RequestException:
            return None

        body = resp.text or ""
        title = self._title(body)
        tech = self._fingerprint(resp.headers, body)
        findings: list[Finding] = []

        findings.append(
            ctx.emit(
                Finding(
                    category=Category.WEB,
                    title=f"{base} [{resp.status_code}] {title or ''}".strip(),
                    severity=Severity.INFO,
                    target=base,
                    description="Live HTTP endpoint.",
                    evidence={
                        "status": resp.status_code,
                        "title": title,
                        "final_url": resp.url,
                        "tech": tech,
                        "content_length": len(body),
                    },
                    module=self.name,
                )
            )
        )
        if tech:
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.WEB,
                        title=f"{base} tech: {', '.join(tech)}",
                        severity=Severity.INFO,
                        target=base,
                        description="Fingerprinted technologies.",
                        evidence={"tech": tech},
                        module=self.name,
                    )
                )
            )
            # feed version-bearing tech to CVE correlation
            for item in tech:
                m = re.search(r"([A-Za-z][\w .\-]+?)[/ ]([0-9][0-9A-Za-z.\-]*)", item)
                if m:
                    ctx.state.setdefault("services", []).append(
                        {"host": base, "port": "", "product": m.group(1).strip(),
                         "version": m.group(2)}
                    )
        ctx.log(f"{base} -> {resp.status_code} {title or ''}")
        return {
            "findings": findings,
            "body": body,
            "headers": dict(resp.headers),
            "status": resp.status_code,
            "cookies": [self._cookie_dict(c) for c in resp.cookies],
        }

    def _dir_bruteforce(self, ctx: ModuleContext, base: str) -> list[Finding]:
        findings: list[Finding] = []
        paths = self._paths(ctx)

        def check(entry):
            path, sev, label = entry
            if ctx.cancel.cancelled():
                return None
            url = base.rstrip("/") + "/" + path
            ctx.rate()
            ctx.audit.record("http_get", url)
            try:
                resp = requests.get(
                    url,
                    timeout=ctx.config.timeout,
                    headers={"User-Agent": ctx.config.user_agent},
                    allow_redirects=False,
                    verify=ctx.config.verify_tls,
                )
            except RequestException:
                return None
            if resp.status_code in (200, 201, 203, 204, 301, 302, 401, 403):
                return (url, sev, label, resp)
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.threads) as ex:
            for result in ex.map(check, paths):
                if ctx.cancel.cancelled():
                    break
                if result is None:
                    continue
                url, sev, label, resp = result
                # downgrade auth-gated hits to informational
                effective = sev
                if resp.status_code in (401, 403):
                    effective = Severity.INFO if sev.rank <= Severity.LOW.rank else Severity.LOW
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.WEB,
                            title=f"{label}: {url} [{resp.status_code}]",
                            severity=effective,
                            target=base,
                            description="Path discovered via content brute force.",
                            evidence={
                                "url": url,
                                "status": resp.status_code,
                                "content_length": len(resp.content),
                            },
                            module=self.name,
                        )
                    )
                )
                # directory listing detection
                if resp.status_code == 200 and self._looks_like_listing(resp.text):
                    findings.append(
                        ctx.emit(
                            Finding(
                                category=Category.MISCONFIG,
                                title=f"Directory listing enabled: {url}",
                                severity=Severity.MEDIUM,
                                target=base,
                                description="Server returns an auto-generated index listing.",
                                evidence={"url": url},
                                module=self.name,
                            )
                        )
                    )
                ctx.log(f"{url} -> {resp.status_code} ({label})")
        return findings

    # ------------------------------------------------------------------ #
    def _paths(self, ctx: ModuleContext):
        if ctx.config.wordlist_web:
            try:
                with open(ctx.config.wordlist_web, "r", encoding="utf-8", errors="ignore") as fh:
                    extra = [
                        (ln.strip().lstrip("/"), Severity.INFO, "wordlist path")
                        for ln in fh
                        if ln.strip() and not ln.startswith("#")
                    ]
                return SENSITIVE_PATHS + extra
            except OSError as exc:
                ctx.log(f"Could not read web wordlist: {exc}")
        return SENSITIVE_PATHS

    @staticmethod
    def _title(body: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if not m:
            return ""
        return re.sub(r"\s+", " ", m.group(1)).strip()[:120]

    @staticmethod
    def _fingerprint(headers, body: str) -> list[str]:
        tech: list[str] = []
        server = headers.get("Server")
        if server:
            tech.append(server)
        for marker, label in TECH_MARKERS:
            if marker in {k.lower() for k in headers.keys()}:
                val = headers.get(marker) or headers.get(marker.title()) or ""
                tech.append(label.format(value=val) if "{value}" in label else label)
            elif marker.lower() in body.lower():
                tech.append(label)
        # dedupe preserving order
        seen: set[str] = set()
        out: list[str] = []
        for t in tech:
            if t and t not in seen:
                seen.add(t)
                out.append(t)
        return out

    @staticmethod
    def _looks_like_listing(body: str) -> bool:
        markers = ("Index of /", "<title>Directory listing for",
                   "Parent Directory</a>")
        return any(m in body for m in markers)

    @staticmethod
    def _cookie_dict(cookie) -> dict:
        return {
            "name": cookie.name,
            "secure": bool(cookie.secure),
            "httponly": bool(cookie._rest.get("HttpOnly") or cookie._rest.get("httponly")),
            "samesite": cookie._rest.get("SameSite") or cookie._rest.get("samesite"),
        }
