"""Reporting: JSON persistence, Markdown/HTML summaries, and run diffing.

A run is persisted as a single JSON file (the source of truth). Markdown and
HTML summaries are generated from that structure, severity-tagged and colour
coded. The diff feature compares two JSON runs for the same target and reports
new / resolved / unchanged findings.

The "past scans" store is simply the directory of JSON files under the output
directory; :func:`list_runs` enumerates them.
"""

from __future__ import annotations

import html as html_lib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from allscan.models import Finding, ScanResult, Severity

SEVERITY_ORDER = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

# ANSI-free hex colours reused by the HTML report and (loosely) the TUI.
SEVERITY_COLORS = {
    "high": "#e5484d",
    "medium": "#f5a623",
    "low": "#f2d600",
    "info": "#4a9eff",
}


def _safe_target(target: str) -> str:
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)


def run_filename(result: ScanResult) -> str:
    ts = time.strftime("%Y%m%d-%H%M%S", time.localtime(result.started_at))
    return f"allscan_{_safe_target(result.target)}_{ts}.json"


# --------------------------------------------------------------------------- #
# JSON persistence
# --------------------------------------------------------------------------- #


def save_json(result: ScanResult, output_dir: Path) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / run_filename(result)
    path.write_text(json.dumps(result.to_dict(), indent=2, default=str))
    return path


def load_json(path: Path) -> ScanResult:
    data = json.loads(Path(path).read_text())
    return ScanResult.from_dict(data)


@dataclass
class RunRef:
    path: Path
    target: str
    started_at: float
    finding_count: int
    partial: bool

    @property
    def when(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at))


def list_runs(output_dir: Path) -> list[RunRef]:
    """Enumerate saved runs, newest first. Tolerates malformed files."""
    output_dir = Path(output_dir)
    runs: list[RunRef] = []
    if not output_dir.exists():
        return runs
    for path in output_dir.glob("allscan_*.json"):
        try:
            data = json.loads(path.read_text())
            runs.append(
                RunRef(
                    path=path,
                    target=data.get("target", "?"),
                    started_at=data.get("started_at", 0.0),
                    finding_count=len(data.get("findings", [])),
                    partial=data.get("partial", False),
                )
            )
        except Exception:
            continue
    runs.sort(key=lambda r: r.started_at, reverse=True)
    return runs


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #


def to_markdown(result: ScanResult) -> str:
    lines: list[str] = []
    counts = result.counts_by_severity()
    lines.append(f"# allscan report — {result.target}")
    lines.append("")
    lines.append(f"- **Target:** `{result.target}`")
    lines.append(f"- **Started:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.started_at))}")
    lines.append(f"- **Duration:** {result.duration:.1f}s")
    lines.append(f"- **Modules:** {', '.join(result.modules_run) or '—'}")
    if result.partial:
        lines.append("- **Note:** scan was cancelled; results are partial.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev.value.title()} | {counts[sev.value]} |")
    lines.append(f"| **Total** | **{len(result.findings)}** |")
    lines.append("")

    checklist = (result.meta or {}).get("compliance") or []
    if checklist:
        passes = sum(1 for r in checklist if r.get("status") == "pass")
        fails = sum(1 for r in checklist if r.get("status") == "fail")
        warns = sum(1 for r in checklist if r.get("status") == "warn")
        lines.append("## Compliance Checklist")
        lines.append("")
        lines.append(f"**{passes} pass · {fails} fail · {warns} warn**")
        lines.append("")
        lines.append("| Status | Check | Baseline | Detail |")
        lines.append("| --- | --- | --- | --- |")
        icon = {"pass": "✅ pass", "fail": "❌ fail", "warn": "⚠️ warn", "n/a": "— n/a"}
        for r in checklist:
            lines.append(
                f"| {icon.get(r.get('status'), r.get('status'))} | {r.get('name')} "
                f"| {r.get('baseline')} | {r.get('detail')} |"
            )
        lines.append("")

    grouped = result.by_category()
    for category in sorted(grouped.keys()):
        findings = grouped[category]
        lines.append(f"## {category} ({len(findings)})")
        lines.append("")
        for f in findings:
            badge = f"`{f.severity.value.upper()}`"
            lines.append(f"### {badge} {f.title}")
            if f.location:
                lines.append(f"*Location:* `{f.location}`  ")
            elif f.target:
                lines.append(f"*Target:* `{f.target}`  ")
            if f.confidence:
                lines.append(f"*Confidence:* {f.confidence}  ")
            if f.description:
                lines.append(f.description)
            if f.note:
                lines.append(f"> ⚠ {f.note}")
            if f.evidence:
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(f.evidence, indent=2, default=str))
                lines.append("```")
            lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_Generated by allscan — for authorized security testing only._")
    return "\n".join(lines)


def save_markdown(result: ScanResult, output_dir: Path) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / (run_filename(result)[:-5] + ".md")
    path.write_text(to_markdown(result))
    return path


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #


def to_html(result: ScanResult) -> str:
    counts = result.counts_by_severity()
    grouped = result.by_category()

    def esc(s) -> str:
        return html_lib.escape(str(s))

    rows = []
    for sev in SEVERITY_ORDER:
        rows.append(
            f'<div class="pill" style="background:{SEVERITY_COLORS[sev.value]}">'
            f"{sev.value.title()}: {counts[sev.value]}</div>"
        )
    pills = "\n".join(rows)

    sections = []
    for category in sorted(grouped.keys()):
        items = []
        for f in grouped[category]:
            color = SEVERITY_COLORS[f.severity.value]
            evidence = ""
            if f.evidence:
                evidence = (
                    f'<pre class="evidence">{esc(json.dumps(f.evidence, indent=2, default=str))}</pre>'
                )
            items.append(
                f"""
        <details class="finding">
          <summary>
            <span class="badge" style="background:{color}">{esc(f.severity.value.upper())}</span>
            <span class="ftitle">{esc(f.title)}</span>
          </summary>
          <div class="fbody">
            {f'<div class="target">location: <code>{esc(f.location)}</code></div>' if f.location else (f'<div class="target">target: <code>{esc(f.target)}</code></div>' if f.target else '')}
            {f'<div class="target">confidence: {esc(f.confidence)}</div>' if f.confidence else ''}
            {f'<p>{esc(f.description)}</p>' if f.description else ''}
            {f'<p class="note">⚠ {esc(f.note)}</p>' if f.note else ''}
            {evidence}
          </div>
        </details>"""
            )
        sections.append(
            f'<section><h2>{esc(category)} <small>({len(grouped[category])})</small></h2>'
            + "".join(items)
            + "</section>"
        )

    # compliance checklist section
    checklist = (result.meta or {}).get("compliance") or []
    compliance_html = ""
    if checklist:
        status_color = {"pass": "#3fb950", "fail": "#e5484d", "warn": "#f5a623", "n/a": "#8b949e"}
        rows_html = []
        for r in checklist:
            st = r.get("status", "")
            rows_html.append(
                f"<tr>"
                f'<td><span class="cbadge" style="background:{status_color.get(st, "#8b949e")}">'
                f"{esc(st.upper())}</span></td>"
                f"<td>{esc(r.get('name'))}</td>"
                f"<td class=\"cbaseline\">{esc(r.get('baseline'))}</td>"
                f"<td class=\"cdetail\">{esc(r.get('detail'))}</td>"
                f"</tr>"
            )
        passes = sum(1 for r in checklist if r.get("status") == "pass")
        fails = sum(1 for r in checklist if r.get("status") == "fail")
        warns = sum(1 for r in checklist if r.get("status") == "warn")
        compliance_html = (
            '<section><h2>compliance checklist '
            f"<small>({passes} pass · {fails} fail · {warns} warn)</small></h2>"
            '<table class="checklist"><thead><tr><th>Status</th><th>Check</th>'
            "<th>Baseline</th><th>Detail</th></tr></thead><tbody>"
            + "".join(rows_html)
            + "</tbody></table></section>"
        )

    body_sections = "\n".join(sections)
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result.started_at))
    partial = (
        '<div class="warn">Scan was cancelled — results are partial.</div>'
        if result.partial
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>allscan report — {esc(result.target)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         background:#0d1117; color:#c9d1d9; margin:0; padding:2rem; }}
  h1 {{ color:#fff; margin:0 0 .25rem; }}
  .meta {{ color:#8b949e; margin-bottom:1rem; font-size:.9rem; }}
  .pills {{ display:flex; gap:.5rem; flex-wrap:wrap; margin:1rem 0; }}
  .pill {{ padding:.35rem .75rem; border-radius:999px; color:#0d1117; font-weight:700; }}
  section {{ margin:1.5rem 0; }}
  h2 {{ border-bottom:1px solid #21262d; padding-bottom:.3rem; color:#fff; text-transform:capitalize; }}
  h2 small {{ color:#8b949e; font-weight:400; }}
  .finding {{ background:#161b22; border:1px solid #21262d; border-radius:8px;
             margin:.5rem 0; padding:.5rem .75rem; }}
  summary {{ cursor:pointer; display:flex; gap:.6rem; align-items:center; }}
  .badge {{ padding:.1rem .5rem; border-radius:6px; color:#0d1117; font-size:.72rem; font-weight:700; }}
  .ftitle {{ font-weight:600; color:#e6edf3; }}
  .fbody {{ margin:.6rem 0 .2rem; padding-left:.3rem; }}
  .target {{ color:#8b949e; font-size:.85rem; margin-bottom:.4rem; }}
  .evidence {{ background:#0d1117; border:1px solid #21262d; border-radius:6px;
              padding:.6rem; overflow:auto; font-size:.8rem; color:#9ecbff; }}
  .warn {{ background:#3d1d1d; border:1px solid #e5484d; color:#ffb3b3;
          padding:.6rem .9rem; border-radius:6px; margin:1rem 0; }}
  footer {{ margin-top:2rem; color:#8b949e; font-size:.8rem; }}
  table.checklist {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
  table.checklist th {{ text-align:left; color:#8b949e; border-bottom:1px solid #21262d;
                        padding:.35rem .5rem; }}
  table.checklist td {{ padding:.35rem .5rem; border-bottom:1px solid #161b22;
                        vertical-align:top; }}
  .cbadge {{ padding:.1rem .45rem; border-radius:6px; color:#0d1117; font-weight:700;
            font-size:.72rem; }}
  .cbaseline {{ color:#8b949e; white-space:nowrap; }}
  .cdetail {{ color:#9ecbff; }}
  .note {{ color:#ffcf99; font-size:.85rem; }}
</style>
</head>
<body>
  <h1>allscan report</h1>
  <div class="meta">
    target <code>{esc(result.target)}</code> ·
    started {started} · duration {result.duration:.1f}s ·
    modules: {esc(', '.join(result.modules_run) or '—')}
  </div>
  {partial}
  <div class="pills">{pills}</div>
  {compliance_html}
  {body_sections}
  <footer>Generated by allscan — for authorized security testing only.</footer>
</body>
</html>"""


def save_html(result: ScanResult, output_dir: Path) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / (run_filename(result)[:-5] + ".html")
    path.write_text(to_html(result))
    return path


# --------------------------------------------------------------------------- #
# Diffing
# --------------------------------------------------------------------------- #


@dataclass
class DiffResult:
    target: str
    added: list[Finding]
    removed: list[Finding]
    unchanged: list[Finding]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "added": [f.to_dict() for f in self.added],
            "removed": [f.to_dict() for f in self.removed],
            "unchanged_count": len(self.unchanged),
        }


def diff_runs(old: ScanResult, new: ScanResult) -> DiffResult:
    """Compare two runs by finding dedupe-key (category, target, title)."""
    old_map = {f.dedupe_key(): f for f in old.findings}
    new_map = {f.dedupe_key(): f for f in new.findings}
    added = [f for k, f in new_map.items() if k not in old_map]
    removed = [f for k, f in old_map.items() if k not in new_map]
    unchanged = [f for k, f in new_map.items() if k in old_map]
    added.sort(key=lambda f: (-f.severity.rank, f.category, f.title))
    removed.sort(key=lambda f: (-f.severity.rank, f.category, f.title))
    return DiffResult(
        target=new.target, added=added, removed=removed, unchanged=unchanged
    )


def diff_to_markdown(d: DiffResult) -> str:
    lines = [f"# allscan diff — {d.target}", ""]
    lines.append(f"- **New findings:** {len(d.added)}")
    lines.append(f"- **Resolved findings:** {len(d.removed)}")
    lines.append(f"- **Unchanged:** {len(d.unchanged)}")
    lines.append("")
    if d.added:
        lines.append("## 🔺 New")
        for f in d.added:
            lines.append(f"- `{f.severity.value.upper()}` [{f.category}] {f.title}")
        lines.append("")
    if d.removed:
        lines.append("## ✅ Resolved")
        for f in d.removed:
            lines.append(f"- `{f.severity.value.upper()}` [{f.category}] {f.title}")
        lines.append("")
    return "\n".join(lines)
