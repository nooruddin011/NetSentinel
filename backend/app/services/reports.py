"""PDF and CSV report generation."""
from __future__ import annotations

import csv
import io
import time
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from app.branding import APP_NAME

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

CSV_COLUMNS = ["id", "first_seen", "last_seen", "count", "attack_type", "severity", "risk_score", "confidence",
               "src_ip", "dst_ip", "status", "origin", "handled_by"]


def csv_safe(v):
    """Neutralise spreadsheet formula injection: values starting with = + - @ tab/CR become text."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def alerts_csv(rows: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for r in rows:
        out = []
        for c in CSV_COLUMNS:
            v = r.get(c)
            if c in ("first_seen", "last_seen") and v:
                v = datetime.fromtimestamp(v, tz=timezone.utc).isoformat(timespec="seconds")
            out.append(csv_safe(v))
        w.writerow(out)
    return buf.getvalue()


def _table(data, widths=None, header=True):
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
             ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    t.setStyle(TableStyle(style))
    return t


def build_pdf(overview: dict, alerts: list, sources: list, report: dict, hours: int) -> bytes:
    styles = getSampleStyleSheet()
    P = lambda text, st="BodyText": Paragraph(escape(str(text)), styles[st])  # noqa: E731  (all DB text is escaped)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm,
                            title=f"{APP_NAME} threat report")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    el = [P(f"{APP_NAME} - Threat Report", "Title"), P(f"Generated {now} | window: last {hours} h"), Spacer(1, 6 * mm)]
    el += [P("1. Executive summary", "Heading2"),
           P(f"{overview['total_events']} events analysed; {overview['threats']} flagged as threats from "
             f"{overview['unique_attackers']} distinct sources. {overview['open_alerts']} alerts open "
             f"({overview['critical_open']} Critical). Average risk score {overview['avg_risk']}/100. "
             f"{overview['mitigations_applied']} mitigation(s) applied (simulated)."), Spacer(1, 4 * mm)]
    sev = overview["by_severity"]
    el += [_table([["Severity", "Events"]] + [[k, v] for k, v in sev.items()], [50 * mm, 30 * mm]), Spacer(1, 4 * mm)]
    by = overview["by_attack"][:10]
    if by:
        d = Drawing(170 * mm, 60 * mm)
        ch = VerticalBarChart()
        ch.x, ch.y, ch.width, ch.height = 10 * mm, 12 * mm, 150 * mm, 42 * mm
        ch.data = [[a["value"] for a in by]]
        ch.categoryAxis.categoryNames = [a["name"][:12] for a in by]
        ch.categoryAxis.labels.fontSize = 6
        ch.categoryAxis.labels.angle = 20
        ch.categoryAxis.labels.dy = -8
        ch.bars[0].fillColor = colors.HexColor("#3b82f6")
        d.add(ch)
        el += [P("2. Attack distribution", "Heading2"), d]
    if sources:
        el += [P("3. Top attacking sources", "Heading2"),
               _table([["Source IP", "Events", "Max risk", "Main attack", "Blocked"]] +
                      [[s["src_ip"], s["events"], s["max_risk"], s["top_attack"], "yes" if s["blocked"] else "no"] for s in sources])]
    crit = [a for a in alerts if a["severity"] in ("Critical", "High")][:15]
    if crit:
        el += [Spacer(1, 4 * mm), P("4. Highest-severity alerts", "Heading2"),
               _table([["#", "Severity", "Attack", "Source", "Risk", "Count", "Status"]] +
                      [[a["id"], a["severity"], a["attack_type"], a["src_ip"], a["risk_score"], a["count"], a["status"]] for a in crit])]
    ms = (report or {}).get("models") or {}
    if ms:
        el += [Spacer(1, 4 * mm), P("5. Detection model performance (hold-out set)", "Heading2")]
        if ((report.get("dataset") or {}).get("synthetic")):
            el += [P("Figures are measured on simulated traffic and demonstrate the pipeline; they are not a real-world benchmark.")]
        el += [_table([["Model", "Accuracy", "Precision", "Recall", "F1", "ROC-AUC", "FPR", "ms/event"]] +
                      [[k, m["accuracy"], m["precision"], m["recall"], m["f1"], m["roc_auc"], m["false_positive_rate"], m.get("infer_ms")]
                       for k, m in ms.items()])]
    doc.build(el)
    return buf.getvalue()
