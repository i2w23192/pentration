"""Cloud exposure checks (detection-only).

* **Bucket references** — scans discovered subdomains and captured HTML/JS for
  cloud-storage URLs (AWS S3, Azure Blob, Google Cloud Storage) and, for each
  unique bucket, makes a *single* request to the bucket root to classify it as
  publicly listable, private, or non-existent — based purely on the HTTP status
  and whether a listing document is returned. It never enumerates or downloads
  objects, and never attempts writes.

* **Metadata endpoint references** — flags references to cloud instance
  metadata endpoints (``169.254.169.254``, ``metadata.google.internal`` …) in
  page source, which are common SSRF sinks. It reports the reference only; it
  does not probe the metadata service or attempt any SSRF.

Everything here is identification and reporting; nothing is accessed beyond the
public bucket root needed to determine listability.
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


# bucket reference patterns -> provider label + a function producing the root URL
BUCKET_PATTERNS = [
    # s3: bucket.s3.amazonaws.com, bucket.s3.region.amazonaws.com, s3.amazonaws.com/bucket
    ("AWS S3", re.compile(r"https?://([a-z0-9.\-]+)\.s3[.\-]([a-z0-9\-]+\.)?amazonaws\.com", re.I)),
    ("AWS S3", re.compile(r"https?://s3[.\-]([a-z0-9\-]+\.)?amazonaws\.com/([a-z0-9.\-]+)", re.I)),
    ("Azure Blob", re.compile(r"https?://([a-z0-9]+)\.blob\.core\.windows\.net", re.I)),
    ("Google Cloud Storage", re.compile(r"https?://storage\.googleapis\.com/([a-z0-9._\-]+)", re.I)),
    ("Google Cloud Storage", re.compile(r"https?://([a-z0-9._\-]+)\.storage\.googleapis\.com", re.I)),
]

METADATA_REFS = [
    ("169.254.169.254", "AWS/Azure/GCP instance metadata IP"),
    ("metadata.google.internal", "GCP metadata hostname"),
    ("metadata.azure.com", "Azure metadata hostname"),
    ("100.100.100.200", "Alibaba Cloud metadata IP"),
]


class CloudModule(Module):
    name = "cloud"
    label = "Cloud Exposure"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        if requests is None:
            return [
                ctx.emit(
                    Finding(
                        category=Category.CLOUD,
                        title="Skipped: requests not installed",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="Install requests to enable cloud-exposure checks.",
                        module=self.name,
                    )
                )
            ]
        findings: list[Finding] = []
        corpus = self._gather_corpus(ctx)

        buckets = self._extract_buckets(corpus)
        ctx.log(f"Cloud: {len(buckets)} unique bucket reference(s) found.")
        for provider, url in sorted(buckets):
            ctx.cancel.raise_if_cancelled()
            findings.extend(self._classify_bucket(ctx, provider, url))

        findings.extend(self._metadata_refs(ctx, corpus))
        return findings

    # ------------------------------------------------------------------ #
    def _gather_corpus(self, ctx: ModuleContext) -> str:
        parts: list[str] = []
        # discovered hostnames
        for host in (ctx.state.get("hosts") or {}):
            parts.append(host)
        # captured pages (body + headers)
        for base, page in (ctx.state.get("pages") or {}).items():
            parts.append(base)
            parts.append(page.get("body") or "")
            for k, v in (page.get("headers") or {}).items():
                parts.append(f"{k}: {v}")
        return "\n".join(parts)

    def _extract_buckets(self, corpus: str) -> set[tuple[str, str]]:
        found: set[tuple[str, str]] = set()
        for provider, pat in BUCKET_PATTERNS:
            for m in pat.finditer(corpus):
                found.add((provider, m.group(0).rstrip("/")))
        return found

    def _classify_bucket(self, ctx: ModuleContext, provider: str, url: str) -> list[Finding]:
        ctx.rate()
        ctx.audit.record("cloud_bucket_probe", url, provider=provider)
        try:
            # single request to the bucket root only; no object listing/download
            resp = requests.get(url, timeout=ctx.config.timeout,
                                headers={"User-Agent": ctx.config.user_agent},
                                allow_redirects=False, verify=ctx.config.verify_tls)
        except RequestException as exc:
            ctx.log(f"Bucket probe failed for {url}: {exc}")
            return []
        status = resp.status_code
        body_head = (resp.text or "")[:2000]
        listable = status == 200 and (
            "<ListBucketResult" in body_head
            or "<EnumerationResults" in body_head
            or "<?xml" in body_head and ("Contents" in body_head or "Blob" in body_head)
        )
        if listable:
            sev, state = Severity.HIGH, "publicly listable"
        elif status in (401, 403):
            sev, state = Severity.LOW, "exists but access denied (private)"
        elif status == 404:
            sev, state = Severity.INFO, "referenced but not found / no such bucket"
        else:
            sev, state = Severity.INFO, f"reference (HTTP {status})"
        ctx.log(f"Bucket {url}: {state}")
        return [
            ctx.emit(
                Finding(
                    category=Category.CLOUD,
                    title=f"{provider} bucket {state}: {url}",
                    severity=sev,
                    target=url,
                    description=(
                        "Cloud storage bucket referenced by the target. Status classifies "
                        "listability only; object contents were not accessed."
                    ),
                    evidence={"provider": provider, "url": url, "status": status,
                              "state": state},
                    module=self.name,
                )
            )
        ]

    def _metadata_refs(self, ctx: ModuleContext, corpus: str) -> list[Finding]:
        findings: list[Finding] = []
        for needle, label in METADATA_REFS:
            if needle in corpus:
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.CLOUD,
                            title=f"Cloud metadata endpoint referenced in content: {needle}",
                            severity=Severity.MEDIUM,
                            target=ctx.target,
                            description=(
                                f"{label} appears in discovered content — a common SSRF "
                                "sink. Reported as a reference only; the metadata service "
                                "was not probed."
                            ),
                            evidence={"reference": needle, "label": label},
                            module=self.name,
                        )
                    )
                )
                ctx.log(f"Metadata reference found: {needle}")
        return findings
