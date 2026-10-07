"""Vulnerability correlation — informational CVE listing only.

For every service/library version collected by earlier modules
(``ctx.state['services']``) this module queries the public NVD CVE API and
lists matching known CVEs with their CVSS severity. It also flags a handful of
common misconfigurations that earlier modules surfaced evidence for.

IMPORTANT: this module is deliberately *informational*. It never fetches,
generates, or stores proof-of-concept or exploit code — only the public CVE
identifiers, summaries and severity scores that NVD publishes.
"""

from __future__ import annotations

import time
from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity
from allscan.utils import dedupe_preserve

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# CIRCL CVE Search — additional CVE/CVSS source alongside NVD.
CIRCL_SEARCH = "https://cve.circl.lu/api/search"


def _cvss_to_severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.INFO
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


class VulnsModule(Module):
    name = "vulns"
    label = "CVE Correlation"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        if requests is None:
            ctx.log("requests not installed; CVE correlation unavailable.")
        else:
            services = ctx.state.get("services") or []
            # unique product/version pairs
            seen: set[tuple[str, str]] = set()
            queries: list[tuple[str, str]] = []
            for svc in services:
                product = (svc.get("product") or "").strip()
                version = (svc.get("version") or "").strip()
                if not product or not version:
                    continue
                key = (product.lower(), version)
                if key in seen:
                    continue
                seen.add(key)
                queries.append((product, version))

            sources = [s.lower() for s in (getattr(ctx.config, "cve_sources", None)
                                           or ["nvd"])]
            if not queries:
                ctx.log("No versioned services to correlate against CVE sources.")
            seen_cves: set[str] = set()
            for product, version in queries:
                ctx.cancel.raise_if_cancelled()
                if "nvd" in sources:
                    findings.extend(self._query_nvd(ctx, product, version, seen_cves))
                    # NVD asks for ~6s between calls without a key; be polite.
                    time.sleep(0.6 if ctx.config.nvd_api_key else 6.0)
                if "circl" in sources:
                    findings.extend(self._query_circl(ctx, product, version, seen_cves))
                    time.sleep(0.4)

        findings.extend(self._misconfig_summary(ctx))
        return findings

    # ------------------------------------------------------------------ #
    def _query_nvd(self, ctx: ModuleContext, product: str, version: str,
                   seen_cves: set) -> list[Finding]:
        keyword = f"{product} {version}".strip()
        params = {"keywordSearch": keyword, "resultsPerPage": 20}
        headers = {"User-Agent": ctx.config.user_agent}
        if ctx.config.nvd_api_key:
            headers["apiKey"] = ctx.config.nvd_api_key

        ctx.rate()
        ctx.audit.record("nvd_query", keyword)
        try:
            resp = requests.get(
                NVD_API,
                params=params,
                headers=headers,
                timeout=ctx.config.timeout + 15,
                verify=ctx.config.verify_tls,
            )
        except Exception as exc:
            ctx.log(f"NVD query failed for '{keyword}': {exc}")
            return []
        if resp.status_code == 403:
            ctx.log("NVD returned 403 (rate limited). Consider setting nvd_api_key.")
            return []
        if resp.status_code != 200:
            ctx.log(f"NVD returned HTTP {resp.status_code} for '{keyword}'.")
            return []
        try:
            data = resp.json()
        except Exception:
            return []

        findings: list[Finding] = []
        vulns = data.get("vulnerabilities", [])
        ctx.log(f"NVD: {len(vulns)} CVE(s) matched '{keyword}'.")
        for item in vulns[:20]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "CVE-?")
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score, vector = self._extract_cvss(cve.get("metrics", {}))
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.CVE,
                        title=f"{cve_id} — {product} {version} (CVSS {score if score else 'n/a'})",
                        severity=_cvss_to_severity(score),
                        target=keyword,
                        description=desc[:500],
                        evidence={
                            "cve_id": cve_id,
                            "product": product,
                            "version": version,
                            "cvss": score,
                            "vector": vector,
                            "source": "nvd",
                            "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        },
                        module=self.name,
                    )
                )
            )
        return findings

    def _query_circl(self, ctx: ModuleContext, product: str, version: str,
                     seen_cves: set) -> list[Finding]:
        """Query the CIRCL CVE Search API (vendor/product search)."""
        # CIRCL searches by a free-text term; use the product name and filter
        # results to those mentioning the version to keep noise down.
        url = f"{CIRCL_SEARCH}/{product}"
        ctx.rate()
        ctx.audit.record("circl_query", f"{product} {version}")
        try:
            resp = requests.get(
                url, timeout=ctx.config.timeout + 10,
                headers={"User-Agent": ctx.config.user_agent},
                verify=ctx.config.verify_tls,
            )
        except Exception as exc:
            ctx.log(f"CIRCL query failed for '{product}': {exc}")
            return []
        if resp.status_code != 200:
            ctx.log(f"CIRCL returned HTTP {resp.status_code} for '{product}'.")
            return []
        try:
            data = resp.json()
        except Exception:
            return []
        # CIRCL returns either a list or {"results"/"data": [...]} depending on
        # API version; normalize defensively.
        rows = data if isinstance(data, list) else (
            data.get("results") or data.get("data") or [])
        findings: list[Finding] = []
        count = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            cve_id = row.get("id") or row.get("cveMetadata", {}).get("cveId") or ""
            if not cve_id or not cve_id.upper().startswith("CVE-"):
                continue
            summary = (row.get("summary") or row.get("description") or "")
            if isinstance(summary, list):
                summary = " ".join(str(s) for s in summary)
            # keep results that reference the version (reduces false matches)
            if version and version not in summary and version not in str(row):
                continue
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            score = row.get("cvss")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.CVE,
                        title=f"{cve_id} — {product} {version} (CVSS {score if score else 'n/a'})",
                        severity=_cvss_to_severity(score),
                        target=f"{product} {version}".strip(),
                        description=str(summary)[:500],
                        evidence={
                            "cve_id": cve_id,
                            "product": product,
                            "version": version,
                            "cvss": score,
                            "source": "circl",
                            "reference": f"https://cve.circl.lu/cve/{cve_id}",
                        },
                        module=self.name,
                    )
                )
            )
            count += 1
            if count >= 20:
                break
        if findings:
            ctx.log(f"CIRCL: {len(findings)} additional CVE(s) for '{product} {version}'.")
        return findings

    @staticmethod
    def _extract_cvss(metrics: dict):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0].get("cvssData", {})
                return data.get("baseScore"), data.get("vectorString")
        return None, None

    # ------------------------------------------------------------------ #
    def _misconfig_summary(self, ctx: ModuleContext) -> list[Finding]:
        """Flag common misconfigs from evidence other modules collected."""
        findings: list[Finding] = []
        services = ctx.state.get("services") or []

        # anonymous FTP check
        for svc in services:
            if str(svc.get("port")) == "21" or "ftp" in str(svc.get("product", "")).lower():
                anon = self._check_anonymous_ftp(ctx, svc.get("host", ctx.target))
                if anon:
                    findings.append(anon)
                break

        # default login pages already flagged by web module; summarize count
        return findings

    def _check_anonymous_ftp(self, ctx: ModuleContext, host: str) -> Optional[Finding]:
        import ftplib

        ctx.rate()
        ctx.audit.record("ftp_anon", host)
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, 21, timeout=ctx.config.timeout)
            ftp.login("anonymous", "allscan@example.com")
            ftp.quit()
        except Exception:
            return None
        ctx.log(f"Anonymous FTP permitted on {host}!")
        return ctx.emit(
            Finding(
                category=Category.MISCONFIG,
                title=f"Anonymous FTP login allowed on {host}",
                severity=Severity.HIGH,
                target=host,
                description="The FTP server accepted an anonymous login.",
                evidence={"host": host, "port": 21},
                module=self.name,
            )
        )
