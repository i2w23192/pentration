"""Result delivery — Discord webhook.

Posts a finished scan's reports to a Discord webhook the operator supplies
(in the TUI settings screen or via ``--discord-webhook``). It sends a short
summary embed plus the **JSON and HTML** report files as attachments.

Only the user's own reports go to the user's own webhook; the webhook URL is
treated as a secret (never written to the audit log or printed back).
"""

from __future__ import annotations

import datetime
import json
import re
from pathlib import Path
from typing import Optional

from allscan import __version__
from allscan.config import MODULE_LABELS
from allscan.models import ScanResult, Severity

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None

# Discord: 8 MB per attachment on the free tier; keep a safe margin.
MAX_ATTACH_BYTES = 8 * 1024 * 1024
_WEBHOOK_RE = re.compile(
    r"^https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+/?$")

# severity -> Discord embed colour (decimal)
_SEV_COLOR = {"high": 0xE5484D, "medium": 0xF5A623, "low": 0xD4A700, "info": 0x4A9EFF}


def looks_like_webhook(url: str) -> bool:
    return bool(_WEBHOOK_RE.match((url or "").strip()))


def _module_fields(result: ScanResult) -> list[dict]:
    """One embed field per module that ran, with its finding breakdown."""
    per: dict[str, dict[str, int]] = {}
    for f in result.findings:
        sev = per.setdefault(f.module, {"high": 0, "medium": 0, "low": 0, "info": 0})
        sev[f.severity.value] += 1
    fields = []
    for name in result.modules_run[:25]:
        counts = per.get(name, {"high": 0, "medium": 0, "low": 0, "info": 0})
        total = sum(counts.values())
        if total:
            parts = [f"{counts[s]} {s}" for s in ("high", "medium", "low", "info") if counts[s]]
            value = f"{total} finding(s) — " + ", ".join(parts)
        else:
            value = "no findings"
        fields.append({"name": MODULE_LABELS.get(name, name), "value": value, "inline": False})
    return fields


def build_payload(result: ScanResult) -> dict:
    """Build the Discord message payload — one field per module. Pure, no I/O."""
    counts = result.counts_by_severity()
    top_sev = next((s for s in ("high", "medium", "low", "info") if counts[s]), "info")
    heading = f"**{result.target}**" + (" (partial)" if result.partial else "")
    desc = (f"{heading}\n"
            f"Results of the recon scan for the tool \"All Scan v{__version__}\" — "
            f"{len(result.findings)} findings across {len(result.modules_run)} module(s) "
            f"in {result.duration:.1f}s. Detection/report only; manual validation required.")
    return {
        "username": "RECON RESULTS",
        "embeds": [{
            "title": f"All Scan v{__version__}",
            "description": desc,
            "color": _SEV_COLOR.get(top_sev, 0x4A9EFF),
            "fields": _module_fields(result),
            "footer": {"text": "Copyrights to @i2w23192"},
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }],
    }


def _attachments(paths: list[Path]) -> tuple[list, list[str]]:
    """Pick the JSON + HTML report files; return (multipart parts, skipped notes)."""
    ctypes = {".json": "application/json", ".html": "text/html"}
    parts, skipped = [], []
    idx = 0
    for p in paths:
        if p.suffix not in ctypes:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size > MAX_ATTACH_BYTES:
            skipped.append(f"{p.name} ({size // 1024} KiB > 8 MiB limit)")
            continue
        parts.append((f"files[{idx}]", (p.name, p.read_bytes(), ctypes[p.suffix])))
        idx += 1
    return parts, skipped


def send_discord(webhook_url: str, result: ScanResult, paths: list[Path],
                 *, timeout: float = 15.0, proxy: Optional[str] = None) -> tuple[bool, str]:
    """Send the summary + JSON/HTML attachments. Returns (ok, message)."""
    if requests is None:
        return False, "requests not installed"
    url = (webhook_url or "").strip()
    if not url:
        return False, "no webhook URL"
    if not looks_like_webhook(url):
        return False, "that does not look like a Discord webhook URL"

    parts, skipped = _attachments([Path(p) for p in paths])
    if not parts:
        return False, "no JSON/HTML report files to attach"
    multipart = [("payload_json", (None, json.dumps(build_payload(result)),
                                   "application/json"))] + parts
    kwargs = {"files": multipart, "timeout": timeout}
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}
    try:
        # Verify TLS against the system CA (Discord is a known host); this is
        # independent of the recon verify_tls setting.
        resp = requests.post(url, **kwargs)
    except Exception as exc:
        return False, f"request failed: {exc}"
    if resp.status_code in (200, 204):
        note = f"sent {len(parts)} file(s)"
        if skipped:
            note += f"; skipped {', '.join(skipped)}"
        return True, note
    if resp.status_code == 429:
        return False, "rate limited by Discord (429)"
    return False, f"Discord returned HTTP {resp.status_code}"


def deliver(result: ScanResult, config, paths: list) -> Optional[str]:
    """If a Discord webhook is configured, deliver reports. Returns a status
    line (for display) or None when no webhook is set."""
    url = getattr(config, "discord_webhook", None)
    if not url:
        return None
    ok, msg = send_discord(url, result, [Path(p) for p in paths],
                           proxy=getattr(config, "proxy", None))
    return ("Discord: " + msg) if ok else ("Discord delivery failed — " + msg)
