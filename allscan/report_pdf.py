"""PDF reporting via ReportLab.

Produces a professional PDF with:

* a title block (target, timestamp, duration, module list),
* an **executive summary** — severity counts, compliance pass/fail roll-up (if
  the compliance module ran), and the top risk-prioritised findings,
* a **risk-prioritised findings table** sorted by severity then confidence.

ReportLab is an optional dependency; :func:`save_pdf` raises ImportError when it
is not installed, which the caller handles gracefully.
"""

from __future__ import annotations

import time
from pathlib import Path

from allscan.models import ScanResult, Severity
from allscan.report import run_filename

SEV_HEX = {"high": "#e5484d", "medium": "#f5a623", "low": "#d4a700", "info": "#4a9eff"}
SEV_ORDER = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def save_pdf(result: ScanResult, output_dir: Path) -> Path:
    # Imports are local so the whole tool still works without reportlab.
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / (run_filename(result)[:-5] + ".pdf")

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, leading=10))
    styles.add(ParagraphStyle("CellTitle", parent=styles["Normal"], fontSize=8, leading=10))
    story = []

    counts = result.counts_by_severity()
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result.started_at))

    # --- title -----------------------------------------------------------
    story.append(Paragraph("allscan — Security Assessment Report", styles["Title"]))
    story.append(Paragraph(
        f"Target: <b>{_esc(result.target)}</b> &nbsp;|&nbsp; Started: {started} "
        f"&nbsp;|&nbsp; Duration: {result.duration:.1f}s", styles["Normal"]))
    story.append(Paragraph(
        f"Modules: {_esc(', '.join(result.modules_run) or '—')}", styles["Small"]))
    if result.partial:
        story.append(Paragraph(
            '<font color="#e5484d">Scan was cancelled — results are partial.</font>',
            styles["Normal"]))
    story.append(Spacer(1, 6 * mm))

    # --- executive summary ----------------------------------------------
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    total = len(result.findings)
    sev_cells = [["Severity", "Count"]]
    for s in SEV_ORDER:
        sev_cells.append([s.value.title(), str(counts[s.value])])
    sev_cells.append(["Total", str(total)])
    sev_table = Table(sev_cells, colWidths=[40 * mm, 25 * mm])
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
    ]
    for i, s in enumerate(SEV_ORDER, start=1):
        style.append(("TEXTCOLOR", (0, i), (0, i), colors.HexColor(SEV_HEX[s.value])))
    sev_table.setStyle(TableStyle(style))
    story.append(sev_table)
    story.append(Spacer(1, 4 * mm))

    # compliance roll-up, if present
    checklist = (result.meta or {}).get("compliance") or []
    if checklist:
        p = sum(1 for r in checklist if r.get("status") == "pass")
        f = sum(1 for r in checklist if r.get("status") == "fail")
        w = sum(1 for r in checklist if r.get("status") == "warn")
        story.append(Paragraph(
            f"<b>Compliance baseline:</b> {p} pass / "
            f'<font color="#e5444d">{f} fail</font> / '
            f'<font color="#f5a623">{w} warn</font>', styles["Normal"]))
        story.append(Spacer(1, 3 * mm))

    # narrative
    highs = counts["high"]
    meds = counts["medium"]
    narrative = (
        f"This assessment of <b>{_esc(result.target)}</b> recorded "
        f"<b>{total}</b> findings across {len(result.modules_run)} module(s): "
        f"<font color='#e5484d'>{highs} high</font>, "
        f"<font color='#f5a623'>{meds} medium</font>, "
        f"{counts['low']} low and {counts['info']} informational. "
    )
    if highs:
        narrative += ("High-severity items should be triaged first; see the "
                      "risk-prioritised table below. ")
    narrative += ("All findings require manual validation. Active-probing and "
                  "exploit-reference items are detection/intelligence only — no "
                  "exploitation was performed.")
    story.append(Paragraph(narrative, styles["Normal"]))
    story.append(Spacer(1, 6 * mm))

    # --- risk-prioritised findings table --------------------------------
    story.append(Paragraph("Risk-Prioritised Findings", styles["Heading2"]))
    ordered = sorted(
        result.findings,
        key=lambda x: (-x.severity.rank, -_conf_rank(x.confidence), x.category, x.title),
    )
    header = ["Sev", "Category", "Finding", "Location / Target"]
    rows = [header]
    for fnd in ordered[:400]:  # keep the PDF bounded
        rows.append([
            fnd.severity.value.upper(),
            _esc(fnd.category),
            Paragraph(_esc(fnd.title)[:160], styles["CellTitle"]),
            Paragraph(_esc(fnd.location or fnd.target)[:120], styles["Small"]),
        ])
    table = Table(rows, colWidths=[14 * mm, 26 * mm, 95 * mm, 45 * mm], repeatRows=1)
    tstyle = [
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]
    for i, fnd in enumerate(ordered[:400], start=1):
        tstyle.append(("TEXTCOLOR", (0, i), (0, i),
                       colors.HexColor(SEV_HEX.get(fnd.severity.value, "#000000"))))
        tstyle.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    table.setStyle(TableStyle(tstyle))
    story.append(table)
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "Generated by allscan — for authorized security testing only. "
        "Detection / reference output; findings require manual validation.",
        styles["Small"]))

    doc = SimpleDocTemplate(str(path), pagesize=A4,
                            leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm,
                            title=f"allscan report — {result.target}")
    doc.build(story)
    return path


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _conf_rank(confidence: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get((confidence or "").lower(), 0)
