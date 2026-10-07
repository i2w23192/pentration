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

    top = (result.meta or {}).get("top_risks") or []
    if top:
        lines.append("## Top Risks (business impact)")
        lines.append("")
        lines.append("| Score | Band | Sev | Likelihood | Asset | Finding |")
        lines.append("| ---: | --- | --- | --- | --- | --- |")
        for r in top[:15]:
            lines.append(f"| {r['risk_score']} | {r['risk_band']} | {r['severity']} "
                         f"| {r['likelihood']} | {r['criticality']} | {r['title'][:50]} |")
        lines.append("")

    matrix = (result.meta or {}).get("risk_matrix") or {}
    if matrix:
        lines.append("## Risk Matrix (severity × likelihood)")
        lines.append("")
        lines.append("| Severity ↓ / Likelihood → | High | Medium | Low |")
        lines.append("| --- | ---: | ---: | ---: |")
        for sev in ("high", "medium", "low", "info"):
            if sev in matrix:
                m = matrix[sev]
                lines.append(f"| {sev.title()} | {m.get('high', 0)} | "
                             f"{m.get('medium', 0)} | {m.get('low', 0)} |")
        lines.append("")

    tm = (result.meta or {}).get("threatmodel") or {}
    if tm:
        lines.append("## Threat Model & Compliance Mapping")
        lines.append("")
        stride = tm.get("stride") or {}
        if stride:
            lines.append("**STRIDE:** " + ", ".join(f"{k} ({v})" for k, v in stride.items()))
            lines.append("")
        if tm.get("attack_techniques"):
            lines.append("| ATT&CK Technique | Name | Tactic | Count |")
            lines.append("| --- | --- | --- | ---: |")
            for t in tm["attack_techniques"][:15]:
                lines.append(f"| {t['technique_id']} | {t['technique']} | "
                             f"{t['tactic']} | {t['count']} |")
            lines.append("")
        fw = tm.get("compliance_frameworks") or {}
        if fw:
            lines.append("| Framework | References |")
            lines.append("| --- | --- |")
            for name, refs in fw.items():
                lines.append(f"| {name.upper()} | {', '.join(refs)} |")
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


TYPE_COLUMNS = ["host", "ip", "asn", "service", "web", "cloud"]
TYPE_COLORS = {"host": "#4a9eff", "ip": "#3fb950", "asn": "#f5a623",
               "service": "#bc8cff", "web": "#2dd4bf", "cloud": "#e5484d"}


def topology_svg(surface: dict, max_per_col: int = 24) -> str:
    """Render the attack-surface map as a layered inline SVG (no deps).

    Nodes are laid out in columns by type (host→ip→asn→service/web/cloud) and
    edges drawn as connecting lines. Safe to embed in the HTML report.
    """
    nodes = (surface or {}).get("nodes") or []
    edges = (surface or {}).get("edges") or []
    if not nodes:
        return ""
    cols: dict[str, list] = {t: [] for t in TYPE_COLUMNS}
    for n in nodes:
        t = n.get("type")
        if t in cols:
            cols[t].append(n)
    col_x = {t: 90 + i * 150 for i, t in enumerate(TYPE_COLUMNS)}
    row_h = 26
    pos: dict[str, tuple] = {}
    max_rows = 1
    for t in TYPE_COLUMNS:
        items = cols[t][:max_per_col]
        max_rows = max(max_rows, len(items))
        for j, n in enumerate(items):
            pos[n["id"]] = (col_x[t], 50 + j * row_h)
    width = 90 + len(TYPE_COLUMNS) * 150
    height = max(120, 50 + max_rows * row_h + 20)

    def esc(s):
        return html_lib.escape(str(s))

    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" '
             f'style="max-height:460px" xmlns="http://www.w3.org/2000/svg">']
    parts.append(f'<rect width="{width}" height="{height}" fill="#0d1117"/>')
    # edges first (behind nodes)
    for e in edges:
        a, b = pos.get(e.get("from")), pos.get(e.get("to"))
        if a and b:
            parts.append(f'<line x1="{a[0]}" y1="{a[1]}" x2="{b[0]}" y2="{b[1]}" '
                         f'stroke="#30363d" stroke-width="0.6"/>')
    # column headers
    for t in TYPE_COLUMNS:
        if cols[t]:
            parts.append(f'<text x="{col_x[t]}" y="28" fill="#8b949e" font-size="11" '
                         f'text-anchor="middle" font-family="monospace">{t} '
                         f'({len(cols[t])})</text>')
    # nodes
    for nid, (x, y) in pos.items():
        ntype = next((n["type"] for n in nodes if n["id"] == nid), "host")
        color = TYPE_COLORS.get(ntype, "#8b949e")
        label = nid if len(nid) <= 22 else nid[:21] + "…"
        parts.append(f'<circle cx="{x}" cy="{y}" r="3.5" fill="{color}"/>')
        parts.append(f'<text x="{x + 6}" y="{y + 3}" fill="#c9d1d9" font-size="9" '
                     f'font-family="monospace">{esc(label)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def save_svg(result: ScanResult, output_dir: Path) -> Optional[Path]:
    svg = topology_svg((result.meta or {}).get("surface") or {})
    if not svg:
        return None
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / (run_filename(result)[:-5] + "_topology.svg")
    path.write_text('<?xml version="1.0" encoding="UTF-8"?>\n' + svg)
    return path


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

    # top risks by business impact
    top = (result.meta or {}).get("top_risks") or []
    toprisk_html = ""
    if top:
        band_color = {"Critical": "#e5484d", "High": "#f5a623",
                      "Medium": "#d4a700", "Low": "#4a9eff"}
        rows_html = "".join(
            f"<tr><td style='text-align:right'><b>{r['risk_score']}</b></td>"
            f"<td style='color:{band_color.get(r['risk_band'], '#8b949e')}'>{esc(r['risk_band'])}</td>"
            f"<td>{esc(r['severity'])}</td><td>{esc(r['likelihood'])}</td>"
            f"<td>{esc(r['criticality'])}</td><td>{esc(r['title'][:70])}</td></tr>"
            for r in top[:15])
        toprisk_html = (
            '<section><h2>top risks <small>(business impact)</small></h2>'
            '<table class="checklist"><thead><tr><th>Score</th><th>Band</th><th>Sev</th>'
            '<th>Likelihood</th><th>Asset</th><th>Finding</th></tr></thead><tbody>'
            + rows_html + "</tbody></table></section>")

    # risk matrix (severity x likelihood)
    matrix = (result.meta or {}).get("risk_matrix") or {}
    risk_html = ""
    if matrix:
        likes = ["high", "medium", "low"]
        cell_bg = {"high": "#e5484d", "medium": "#f5a623", "low": "#d4a700", "info": "#4a9eff"}
        rows_html = []
        for sev in ("high", "medium", "low", "info"):
            if sev not in matrix:
                continue
            tds = "".join(
                f'<td style="text-align:center">{matrix[sev].get(l, 0) or ""}</td>'
                for l in likes)
            rows_html.append(
                f'<tr><th style="color:{cell_bg.get(sev)}">{esc(sev.title())}</th>{tds}</tr>')
        risk_html = (
            '<section><h2>risk matrix <small>(severity × likelihood)</small></h2>'
            '<table class="checklist"><thead><tr><th>Severity ↓ / Likelihood →</th>'
            '<th>High</th><th>Medium</th><th>Low</th></tr></thead><tbody>'
            + "".join(rows_html) + "</tbody></table></section>")

    # ATT&CK / STRIDE / compliance mapping
    tm = (result.meta or {}).get("threatmodel") or {}
    mapping_html = ""
    if tm:
        techs = "".join(
            f"<tr><td>{esc(t['technique_id'])}</td><td>{esc(t['technique'])}</td>"
            f"<td>{esc(t['tactic'])}</td><td style='text-align:center'>{t['count']}</td></tr>"
            for t in tm.get("attack_techniques", [])[:15])
        stride = " · ".join(f"{k}: {v}" for k, v in (tm.get("stride") or {}).items())
        fw = tm.get("compliance_frameworks") or {}
        fw_rows = "".join(
            f"<tr><td>{esc(name.upper())}</td><td>{esc(', '.join(refs))}</td></tr>"
            for name, refs in fw.items())
        mapping_html = (
            '<section><h2>threat model &amp; compliance mapping</h2>'
            + (f'<p class="cdetail">STRIDE: {esc(stride)}</p>' if stride else '')
            + '<h3 style="color:#8b949e">MITRE ATT&CK techniques</h3>'
            '<table class="checklist"><thead><tr><th>Technique</th><th>Name</th>'
            '<th>Tactic</th><th>Count</th></tr></thead><tbody>' + techs + '</tbody></table>'
            + ('<h3 style="color:#8b949e">Compliance frameworks</h3>'
               '<table class="checklist"><thead><tr><th>Framework</th><th>References</th>'
               '</tr></thead><tbody>' + fw_rows + '</tbody></table>' if fw_rows else '')
            + '</section>')

    # topology diagram from the surface map
    topo = topology_svg((result.meta or {}).get("surface") or {})
    topo_html = (f'<section><h2>attack-surface topology</h2>{topo}</section>' if topo else "")

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
  {toprisk_html}
  {risk_html}
  {topo_html}
  {mapping_html}
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


def save_aggregate(results: list, output_dir: Path) -> Path:
    """Write an aggregate summary across several per-target runs.

    ``results`` is a list of (target, ScanResult) tuples. Produces a JSON file
    and a sibling Markdown summary; returns the JSON path.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    rows = []
    totals = {s.value: 0 for s in Severity}
    for target, result in results:
        counts = result.counts_by_severity()
        for k, v in counts.items():
            totals[k] += v
        rows.append({
            "target": target,
            "findings": len(result.findings),
            "severity_counts": counts,
            "partial": result.partial,
            "duration": round(result.duration, 1),
            "modules_run": result.modules_run,
        })
    agg = {
        "generated": time.time(),
        "targets": len(results),
        "severity_totals": totals,
        "total_findings": sum(r["findings"] for r in rows),
        "per_target": rows,
    }
    jpath = output_dir / f"allscan_aggregate_{ts}.json"
    jpath.write_text(json.dumps(agg, indent=2, default=str))

    lines = [f"# allscan aggregate summary ({len(results)} targets)", ""]
    lines.append("| Target | Findings | High | Med | Low | Info | Partial |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | :---: |")
    for r in sorted(rows, key=lambda x: (-x["severity_counts"]["high"],
                                         -x["severity_counts"]["medium"])):
        c = r["severity_counts"]
        lines.append(f"| {r['target']} | {r['findings']} | {c['high']} | {c['medium']} "
                     f"| {c['low']} | {c['info']} | {'yes' if r['partial'] else ''} |")
    lines.append(f"| **Total** | **{agg['total_findings']}** | {totals['high']} "
                 f"| {totals['medium']} | {totals['low']} | {totals['info']} | |")
    (output_dir / f"allscan_aggregate_{ts}.md").write_text("\n".join(lines))
    return jpath


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
