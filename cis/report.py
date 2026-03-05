"""
cis_report.py — HTML report generation for the CIS Azure Audit Tool.

Contains generate_html() which produces a self-contained single-file HTML
report with embedded CSS, JavaScript, live filters, and export buttons.
"""

from __future__ import annotations

import base64
import csv
import datetime
import html
import io
import json
from pathlib import Path
from typing import Any

from cis.config import BENCHMARK_VER, LOGGER, VERSION, FAIL, INFO, MANUAL, PASS, ERROR, SUPPRESSED
from cis.helpers import _ctrl_sort_key
from cis.models import R

# Visual style for each status type used in table rows and badges.
# Format: (text_hex_colour, background_hex_colour, emoji)
_STATUS_STYLE = {
    PASS: ("#16a34a", "#f0fdf4", "✅"),  # Green
    FAIL: ("#dc2626", "#fef2f2", "❌"),  # Red
    ERROR: ("#ea580c", "#fff7ed", "⚠️"),  # Orange
    INFO: ("#2563eb", "#eff6ff", "ℹ️"),  # Blue
    MANUAL: ("#7c3aed", "#f5f3ff", "📋"),  # Purple
    SUPPRESSED: ("#64748b", "#f1f5f9", "🔇"),  # Muted grey
}


def generate_html(
    results: list[R],
    output: str,
    scope_info: dict[str, Any] | None = None,
    history: list[dict[str, Any]] | None = None,
    sub_timestamps: dict[str, str] | None = None,
) -> None:
    """
    Generate a self-contained HTML audit report from a list of R instances.

    The report is a single .html file with:
      - Embedded CSS (no external stylesheets)
      - Embedded JavaScript (no external scripts)
      - Summary cards (total counts per status)
      - Per-section table with colour-coded rows
      - Live filter by search text, status, and CIS level
      - Subscription / resource column for context
      - Remediation guidance on every FAIL row

    All user data (resource names, subscription names, error messages) is
    passed through html.escape() before embedding to prevent XSS.

    Parameters
    ──────────
    results    : List of R instances to render
    output     : Output file path (e.g. "cis_azure_audit_report.html")
    scope_info : Optional dict with keys: tenant, user, scope_label,
                 subscriptions (list of name strings), level_filter
    history    : Optional list of past run summaries for the trend chart
    """
    # ── Counts and score ──────────────────────────────────────────────────────
    counts = {s: sum(1 for r in results if r.status == s) for s in [PASS, FAIL, ERROR, INFO, MANUAL, SUPPRESSED]}
    total = len(results)

    # Compliance score excludes INFO (not applicable), MANUAL (human review),
    # and SUPPRESSED (accepted risk — counted separately, not as a pass or fail).
    denom = max(total - counts[INFO] - counts[MANUAL] - counts[SUPPRESSED], 1)  # Avoid division by zero
    score = round(counts[PASS] / denom * 100, 1)
    score_col = "#16a34a" if score >= 80 else "#d97706" if score >= 60 else "#dc2626"

    # ── L1 / L2 breakdown ─────────────────────────────────────────────────────
    l1_counts = {s: sum(1 for r in results if r.level == 1 and r.status == s) for s in [PASS, FAIL, ERROR]}
    l2_counts = {s: sum(1 for r in results if r.level == 2 and r.status == s) for s in [PASS, FAIL, ERROR]}
    l1_score = round(l1_counts[PASS] / max(l1_counts[PASS] + l1_counts[FAIL] + l1_counts[ERROR], 1) * 100, 1)
    l2_score = round(l2_counts[PASS] / max(l2_counts[PASS] + l2_counts[FAIL] + l2_counts[ERROR], 1) * 100, 1)
    l1_col = "#16a34a" if l1_score >= 80 else "#d97706" if l1_score >= 60 else "#dc2626"
    l2_col = "#16a34a" if l2_score >= 80 else "#d97706" if l2_score >= 60 else "#dc2626"
    overall_pass = counts[PASS]
    overall_total = counts[PASS] + counts[FAIL] + counts[ERROR]
    l1_total = l1_counts[PASS] + l1_counts[FAIL] + l1_counts[ERROR]
    l2_total = l2_counts[PASS] + l2_counts[FAIL] + l2_counts[ERROR]

    # ── Build table rows grouped by section ───────────────────────────────────
    # Group results by their section field and sort alphabetically
    sections: dict = {}
    for r in results:
        sections.setdefault(r.section, []).append(r)

    # ── Per-section scores (passed to JS for section breakdown chart) ─────────
    sec_data: dict = {}
    for sec, grp in sections.items():
        sp = sum(1 for r in grp if r.status == PASS)
        sf = sum(1 for r in grp if r.status == FAIL)
        se = sum(1 for r in grp if r.status == ERROR)
        sec_data[sec] = {"pass": sp, "fail": sf, "error": se, "score": round(sp / max(sp + sf + se, 1) * 100, 1)}
    sec_data_json = json.dumps(sec_data, ensure_ascii=False)

    rows = ""
    for sec_idx, sec in enumerate(sorted(sections, key=lambda s: _ctrl_sort_key(s.split(" ")[0]))):
        grp = sections[sec]
        sec_id = f"sec-{sec_idx}"
        # Count passing checks in this section (INFO and MANUAL excluded)
        sp = sum(1 for r in grp if r.status == PASS)
        rows += (
            f'<tr class="sh" data-sec-id="{sec_id}">'
            f'<td colspan="6">'
            f'<span class="sec-arrow">▼</span>'
            f"<b>{html.escape(sec)}</b>"
            f'<span class="ss">{sp} of {len(grp)} checks passed</span>'
            f"</td></tr>\n"
        )

        # Sort within section: numerically by control_id, then subscription, then resource
        for r in sorted(grp, key=lambda x: (_ctrl_sort_key(x.control_id), x.subscription_name, x.resource)):
            col, bg, icon = _STATUS_STYLE.get(r.status, ("#374151", "#f9fafb", "?"))

            # Build the Subscription / Resource cell content
            # Tenant-wide checks have no subscription_name
            sub_cell = ""
            if r.subscription_name:
                sub_cell += f'<div class="sub-name">📋 {html.escape(r.subscription_name)}</div>'
            else:
                sub_cell += '<div class="sub-name" style="color:#94a3b8">Tenant-wide</div>'
            if r.resource:
                sub_cell += f'<div class="res-name">' f"🔹 <code>{html.escape(r.resource)}</code></div>"

            # Remediation hint only appears on FAIL rows
            fix = (
                f'<div class="fix">💡 {html.escape(r.remediation)}</div>' if r.remediation and r.status == FAIL else ""
            )

            # data-* attributes are used by the JavaScript filter function
            rows += (
                f'<tr style="background:{bg}" '
                f'data-sec="{sec_id}" data-sec-name="{html.escape(sec)}" '
                f'data-status="{r.status}" data-level="L{r.level}" '
                f'data-sub="{html.escape(r.subscription_name or "")}">'
                f"<td><code>{html.escape(r.control_id)}</code></td>"
                f'<td><span class="lv">L{r.level}</span></td>'
                f"<td>{html.escape(r.title)}</td>"
                f'<td class="sub-col">{sub_cell}</td>'
                f'<td><span class="badge" style="color:{col}">{icon} {r.status}</span></td>'
                f"<td>{html.escape(r.details)}{fix}</td>"
                f"</tr>\n"
            )

    # ── Per-subscription summary table ───────────────────────────────────────
    sub_stats: dict[str, dict[str, int]] = {}
    for r in results:
        sn = r.subscription_name or ""
        if not sn:
            continue
        if sn not in sub_stats:
            sub_stats[sn] = {PASS: 0, FAIL: 0, ERROR: 0, INFO: 0, MANUAL: 0, SUPPRESSED: 0}
        sub_stats[sn][r.status] = sub_stats[sn].get(r.status, 0) + 1

    def _sub_score(s: dict[str, int]) -> float:
        return s[PASS] / max(s[PASS] + s[FAIL] + s[ERROR], 1) * 100

    today = datetime.datetime.now(datetime.timezone.utc).date()

    def _audited_cell(sname: str) -> str:
        """Return an HTML <td> showing the audit date and staleness for a subscription."""
        ts_str = (sub_timestamps or {}).get(sname)
        if not ts_str:
            return "<td>—</td>"
        try:
            audited = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00")).date()
        except ValueError:
            return "<td>—</td>"
        age = (today - audited).days
        if age == 0:
            label = "today"
            color = "#64748b"
        elif age == 1:
            label = "yesterday"
            color = "#64748b"
        else:
            label = f"{age}d ago"
            color = "#d97706" if age <= 30 else "#dc2626"
        date_str = audited.strftime("%b %d")
        return f'<td style="color:{color};white-space:nowrap">{date_str}<br><small>{label}</small></td>'

    sub_rows_html = ""
    for sn in sorted(sub_stats, key=lambda x: _sub_score(sub_stats[x])):
        st = sub_stats[sn]
        pct = round(_sub_score(st), 1)
        col = "#16a34a" if pct >= 80 else "#d97706" if pct >= 60 else "#dc2626"
        scored = max(st[PASS] + st[FAIL] + st[ERROR], 1)
        pass_w = round(st[PASS] / scored * 100)
        fail_w = round(st[FAIL] / scored * 100)
        err_w = max(0, 100 - pass_w - fail_w)
        bar = (
            f'<div class="sbar">'
            f'<span style="width:{pass_w}%;background:#16a34a"></span>'
            f'<span style="width:{fail_w}%;background:#dc2626"></span>'
            f'<span style="width:{err_w}%;background:#ea580c"></span>'
            f"</div>"
        )
        sub_rows_html += (
            f'<tr class="sub-row" data-sub="{html.escape(sn)}">'
            f'<td style="font-weight:600">{html.escape(sn)}</td>'
            f'<td><span style="color:{col};font-weight:700">{pct}%</span></td>'
            f"<td>{bar}</td>"
            f'<td style="color:#16a34a;font-weight:600">{st[PASS]}</td>'
            f'<td style="color:#dc2626;font-weight:600">{st[FAIL]}</td>'
            f'<td style="color:#ea580c">{st[ERROR]}</td>'
            f'<td style="color:#64748b">{st[INFO]}</td>'
            f'<td style="color:#7c3aed">{st[MANUAL]}</td>'
            f'<td style="color:#64748b">{st[SUPPRESSED]}</td>'
            f"{_audited_cell(sn)}"
            f"</tr>\n"
        )
    sub_table = (
        '<div class="sub-summary-wrap">'
        "<h2>Subscription Summary "
        "<small>(click a row to filter the table below)</small></h2>"
        '<table class="sub-summary">'
        "<thead><tr>"
        "<th>Subscription</th><th>Score</th><th>Breakdown</th>"
        "<th>&#10003; Pass</th><th>&#10007; Fail</th>"
        "<th>&#9888; Error</th><th>Info</th><th>Manual</th><th>&#128263; Suppressed</th>"
        "<th>Audited</th>"
        f"</tr></thead><tbody>{sub_rows_html}</tbody></table></div>"
        if sub_rows_html
        else ""
    )

    # ── Generate JSON and CSV export files alongside the HTML ─────────────────
    base = Path(output).with_suffix("")
    json_name = Path(output).stem + ".json"
    csv_name = Path(output).stem + ".csv"

    json_data = [
        {
            "control": r.control_id,
            "level": r.level,
            "title": r.title,
            "subscription": r.subscription_name or "",
            "resource": r.resource or "",
            "status": r.status,
            "details": r.details,
        }
        for r in results
    ]
    base.with_suffix(".json").write_text(json.dumps(json_data, indent=2, ensure_ascii=False), encoding="utf-8")

    csv_buf = io.StringIO()
    writer = csv.DictWriter(
        csv_buf,
        fieldnames=["control", "level", "title", "subscription", "resource", "status", "details"],
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(json_data)
    csv_text = csv_buf.getvalue()
    base.with_suffix(".csv").write_text(csv_text, encoding="utf-8")
    csv_data_uri = "data:text/csv;base64," + base64.b64encode(csv_text.encode("utf-8")).decode("ascii")

    # ── Report timestamp ──────────────────────────────────────────────────────
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Scope info block ─────────────────────────────────────────────────────
    si = scope_info or {}
    scope_rows = ""
    if si.get("tenant"):
        scope_rows += f'<tr><th>Tenant</th><td>{html.escape(si["tenant"])}</td></tr>\n'
    if si.get("user"):
        scope_rows += f'<tr><th>Audited by</th><td>{html.escape(si["user"])}</td></tr>\n'
    if si.get("scope_label"):
        scope_rows += f'<tr><th>Scope</th><td>{html.escape(si["scope_label"])}</td></tr>\n'
    if si.get("subscriptions"):
        subs_html = ", ".join(html.escape(s) for s in si["subscriptions"])
        scope_rows += f'<tr><th>Subscriptions ({len(si["subscriptions"])})</th><td>{subs_html}</td></tr>\n'
    if si.get("level_filter"):
        scope_rows += f'<tr><th>Level filter</th><td>Level {html.escape(str(si["level_filter"]))} only</td></tr>\n'
    scope_block = f'<div class="scope-info"><table>{scope_rows}</table></div>' if scope_rows else ""

    # ── Trend chart (collapsible, only when 2+ usable history entries exist) ────
    trend_block = ""
    if history:
        # Drop 0% entries (no real audit data) and deduplicate same-day same-score pairs
        _seen_trend: set[tuple[str, float]] = set()
        _filtered_hist = []
        for _h in history:
            if _h["score"] == 0:
                continue
            _key = (_h["timestamp"][:10], _h["score"])
            if _key not in _seen_trend:
                _seen_trend.add(_key)
                _filtered_hist.append(_h)
    if history and len(_filtered_hist) >= 2:
        trend_js_data = json.dumps(
            [{"ts": h["timestamp"][:10], "score": h["score"]} for h in _filtered_hist],
            ensure_ascii=False,
        )
        trend_block = f"""
<details class="trend-box">
  <summary>&#128200; Compliance Trend &#8212; last {len(_filtered_hist)} run(s)</summary>
  <div class="trend-inner">
    <canvas id="trend-cv" height="130"></canvas>
  </div>
</details>
<script>
(function(){{
  var TREND = {trend_js_data};
  var cv = document.getElementById('trend-cv');
  if (!cv || !TREND.length) return;
  cv.width = cv.parentElement.offsetWidth || 700;
  var W = cv.width, H = cv.height;
  var PAD = {{t:20, r:20, b:36, l:44}};
  var iW = W - PAD.l - PAD.r, iH = H - PAD.t - PAD.b;
  var ctx = cv.getContext('2d');
  var scores = TREND.map(function(d){{return d.score;}});
  var minS = Math.max(0, Math.min.apply(null,scores) - 5);
  var maxS = Math.min(100, Math.max.apply(null,scores) + 5);
  function sx(i){{ return PAD.l + (i / (TREND.length - 1)) * iW; }}
  function sy(v){{ return PAD.t + iH - ((v - minS) / (maxS - minS)) * iH; }}
  // grid lines
  ctx.strokeStyle = '#e2e8f0'; ctx.lineWidth = 1;
  [0,25,50,75,100].forEach(function(v){{
    if (v < minS || v > maxS) return;
    var y = sy(v);
    ctx.beginPath(); ctx.moveTo(PAD.l, y); ctx.lineTo(PAD.l + iW, y); ctx.stroke();
    ctx.fillStyle='#94a3b8'; ctx.font='11px sans-serif'; ctx.textAlign='right';
    ctx.fillText(v+'%', PAD.l - 6, y + 4);
  }});
  // filled area
  ctx.beginPath();
  ctx.moveTo(sx(0), sy(scores[0]));
  scores.forEach(function(s,i){{ if(i) ctx.lineTo(sx(i), sy(s)); }});
  ctx.lineTo(sx(scores.length-1), PAD.t+iH);
  ctx.lineTo(sx(0), PAD.t+iH);
  ctx.closePath();
  ctx.fillStyle = 'rgba(37,99,235,0.08)'; ctx.fill();
  // line
  ctx.beginPath();
  scores.forEach(function(s,i){{ i ? ctx.lineTo(sx(i),sy(s)) : ctx.moveTo(sx(i),sy(s)); }});
  ctx.strokeStyle = '#2563eb'; ctx.lineWidth = 2; ctx.stroke();
  // dots + labels
  TREND.forEach(function(d,i){{
    var x=sx(i), y=sy(d.score);
    var col = d.score>=80?'#16a34a':d.score>=60?'#d97706':'#dc2626';
    ctx.beginPath(); ctx.arc(x,y,4,0,2*Math.PI);
    ctx.fillStyle=col; ctx.fill();
    ctx.strokeStyle='#fff'; ctx.lineWidth=1.5; ctx.stroke();
    ctx.fillStyle=col; ctx.font='bold 11px sans-serif'; ctx.textAlign='center';
    ctx.fillText(d.score+'%', x, y-9);
    ctx.fillStyle='#64748b'; ctx.font='10px sans-serif';
    ctx.fillText(d.ts, x, H-8);
  }});
}})();
</script>"""

    # ── Full HTML page ────────────────────────────────────────────────────────
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CIS Azure Audit Report — {ts}</title>
<style>
/* ── Reset and base ── */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: #f8fafc; color: #1e293b; line-height: 1.5; }}

/* ── Header ── */
header {{ background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
          color: #fff; padding: 2rem; }}
header h1 {{ font-size: 1.6rem; font-weight: 700; margin-bottom: .25rem; }}
header p  {{ opacity: .8; font-size: .9rem; }}

/* ── Score cards ── */
.cards {{ display: flex; gap: 1rem; padding: 1.5rem 2rem; flex-wrap: wrap; }}
.card  {{ flex: 1; min-width: 120px; background: #fff; border-radius: 10px;
          padding: 1.2rem; text-align: center;
          box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
.card .n {{ font-size: 2rem; font-weight: 800; line-height: 1; }}
.card .l {{ font-size: .78rem; color: #64748b; margin-top: .3rem; }}
.c-sc .n {{ font-size: 2.4rem; }}
.c-pa .n {{ color: #16a34a; }}
.c-fa .n {{ color: #dc2626; }}
.c-er .n {{ color: #ea580c; }}
.c-in .n {{ color: #2563eb; }}
.c-ma .n {{ color: #7c3aed; }}
.c-su .n {{ color: #64748b; }}

/* ── Trend box ── */
.trend-box {{ margin: 0 2rem 1rem; border: 1px solid #e2e8f0; border-radius: 8px;
    background: #fff; overflow: hidden; }}
.trend-box > summary {{ padding: .65rem 1rem; font-size: .85rem; font-weight: 600;
    color: #475569; cursor: pointer; list-style: none; user-select: none; }}
.trend-box > summary::-webkit-details-marker {{ display: none; }}
.trend-box > summary:hover {{ background: #f8fafc; }}
.trend-inner {{ padding: .75rem 1rem 1rem; }}
.trend-inner canvas {{ width: 100%; display: block; }}

/* ── Filter bar ── */
.filters {{ display: flex; align-items: center; gap: .75rem; padding: .8rem 2rem;
             background: #fff; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; }}
.filters label {{ font-weight: 600; font-size: .85rem; color: #475569; }}
.filters input, .filters select {{
    border: 1px solid #cbd5e1; border-radius: 6px; padding: .4rem .7rem;
    font-size: .85rem; outline: none; }}
.filters input {{ min-width: 220px; }}
.filters input:focus {{ border-color: #2563eb; }}
.exp-btn {{ background: #1e3a5f; color: #fff; border-radius: 6px; padding: .4rem .8rem;
    font-size: .85rem; text-decoration: none; white-space: nowrap;
    border: none; cursor: pointer; font-family: inherit; }}
.exp-btn:hover {{ background: #2563eb; }}

/* ── Table wrapper ── */
.wrap  {{ overflow-x: auto; padding: 0 2rem 2rem; }}
table  {{ width: 100%; border-collapse: collapse; font-size: .84rem;
           background: #fff; border-radius: 10px; overflow: hidden;
           box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
thead  {{ background: #1e3a5f; color: #fff; }}
th, td {{ padding: .55rem .8rem; text-align: left; border-bottom: 1px solid #e2e8f0; }}
th     {{ font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }}

/* ── Section header rows ── */
tr.sh td {{ background: #f1f5f9; font-size: .8rem; color: #475569;
             border-top: 2px solid #cbd5e1; padding: .5rem .8rem; }}
tr.sh  {{ cursor: pointer; user-select: none; }}
tr.sh:hover td {{ background: #e2e8f0; }}
.sec-arrow {{ display: inline-block; margin-right: .45rem; font-size: .8rem;
              transition: transform .15s; }}
.ss    {{ float: right; color: #94a3b8; font-weight: normal; }}

/* ── Status badge ── */
.badge {{ font-size: .78rem; font-weight: 700; white-space: nowrap; }}
.lv    {{ font-size: .7rem; background: #e2e8f0; border-radius: 4px;
           padding: 1px 5px; font-weight: 600; color: #475569; }}

/* ── Subscription / resource column ── */
.sub-col  {{ min-width: 180px; max-width: 240px; vertical-align: top; }}
.sub-name {{ font-size: .78rem; color: #374151; font-weight: 600;
              padding: 1px 0; margin-bottom: 2px; }}
.res-name {{ font-size: .76rem; color: #6b7280; margin-top: 3px; }}
.res-name code {{ background: rgba(0,0,0,.06); padding: 1px 4px; border-radius: 3px; }}

/* ── Remediation hint ── */
.fix {{ margin-top: .4rem; font-size: .78rem; color: #64748b; font-style: italic; }}

/* ── Scope info table ── */
.scope-info {{ margin-top: 1rem; }}
.scope-info table {{ border-collapse: collapse; font-size: .82rem; background: rgba(255,255,255,.12);
    border-radius: 6px; overflow: hidden; }}
.scope-info th {{ color: rgba(255,255,255,.7); font-weight: 600; padding: .25rem .8rem;
    text-align: right; white-space: nowrap; border-right: 1px solid rgba(255,255,255,.2); }}
.scope-info td {{ color: #fff; padding: .25rem .8rem; }}

/* ── Footer ── */
footer {{ text-align: center; padding: 1.5rem; color: #94a3b8; font-size: .8rem; }}

/* ── Subscription summary ── */
.sub-summary-wrap {{ padding: 0 2rem 1.5rem; }}
.sub-summary-wrap h2 {{ font-size: 1rem; font-weight: 700; color: #1e293b; margin-bottom: .6rem; }}
.sub-summary-wrap h2 small {{ font-size: .75rem; color: #94a3b8; font-weight: normal; }}
.sub-summary {{ width: 100%; border-collapse: collapse; background: #fff;
    border-radius: 10px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
.sub-summary thead {{ background: #1e3a5f; color: #fff; }}
.sub-summary th, .sub-summary td {{ padding: .45rem .8rem; text-align: left;
    border-bottom: 1px solid #e2e8f0; font-size: .83rem; }}
.sub-summary th {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; }}
.sub-row {{ cursor: pointer; }}
.sub-row:hover {{ background: #f1f5f9 !important; }}
.sub-row.active {{ background: #dbeafe !important; outline: 2px solid #2563eb; }}
.sbar {{ display: flex; height: 8px; border-radius: 4px; overflow: hidden;
    min-width: 120px; background: #e2e8f0; }}
.sbar span {{ display: block; height: 100%; }}

/* ── Back to top button ── */
#back-top {{ position: fixed; bottom: 1.5rem; right: 1.5rem; width: 2.5rem; height: 2.5rem;
    background: #2563eb; color: #fff; border-radius: 50%; font-size: 1.1rem;
    box-shadow: 0 2px 8px rgba(0,0,0,.2); text-decoration: none;
    display: flex; align-items: center; justify-content: center; z-index: 999; }}
#back-top:hover {{ background: #1d4ed8; }}

/* ── Print / PDF stylesheet ── */
@media print {{
    /* Hide interactive-only elements */
    #back-top, .filters, .trend-box {{ display: none !important; }}
    .sub-summary-wrap h2 small {{ display: none; }}
    .sec-arrow {{ display: none; }}
    tr.sh {{ cursor: default; }}

    /* Clean page background */
    body {{ background: #fff; font-size: .78rem; }}
    .wrap {{ overflow: visible; padding: 0 1rem 1rem; }}

    /* Keep dark header and coloured row backgrounds in print */
    header, tr[style], tr.sh td, thead,
    .cards .card {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}

    /* Remove screen-only shadows and borders */
    .cards .card {{ box-shadow: none; border: 1px solid #e2e8f0; }}
    table, .sub-summary {{ box-shadow: none; }}

    /* Repeat table header on each printed page */
    thead {{ display: table-header-group; }}

    /* Page-break rules: keep a row together, keep section header with its rows */
    tr            {{ page-break-inside: avoid; }}
    tr.sh         {{ page-break-after: avoid; }}
    .dashboard    {{ page-break-inside: avoid; }}
    .sub-summary-wrap {{ page-break-inside: avoid; }}

    /* Remove hover / active highlights that mean nothing on paper */
    .sub-row:hover {{ background: inherit !important; }}
    .sub-row.active {{ outline: none; background: inherit !important; }}

    /* Slightly tighter column for print */
    .sub-col {{ min-width: 100px; max-width: 160px; }}
    table {{ font-size: .78rem; }}
}}

/* ── Compliance dashboard ── */
.dashboard {{ display: flex; gap: 2rem; padding: 1rem 2rem 1.5rem;
    flex-wrap: wrap; align-items: flex-start; background: #fff;
    border-bottom: 1px solid #e2e8f0; }}
.dash-donuts {{ display: flex; gap: 2rem; flex-wrap: wrap; align-items: flex-start; }}
.donut-group {{ display: flex; flex-direction: column; align-items: center; gap: .25rem; }}
.donut-label {{ font-size: .7rem; font-weight: 700; color: #475569;
    text-transform: uppercase; letter-spacing: .05em; text-align: center; margin-bottom: .15rem; }}
.lv-badge {{ font-size: .62rem; font-weight: 700; color: #fff; border-radius: 3px;
    padding: 0 4px; margin-left: 4px; vertical-align: middle; }}
.donut-pct {{ font-size: 1.45rem; font-weight: 800; line-height: 1; margin-top: .2rem; }}
.donut-cnt {{ font-size: .72rem; color: #94a3b8; margin-top: .1rem; }}
.donut-legend {{ display: flex; gap: .9rem; margin-top: .7rem; flex-wrap: wrap; }}
.donut-legend span {{ display: flex; align-items: center; gap: .35rem;
    font-size: .74rem; color: #475569; }}
.donut-legend i {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px; }}
.sec-breakdown {{ flex: 1; min-width: 260px; }}
.sb-title {{ font-size: .72rem; font-weight: 700; color: #475569;
    text-transform: uppercase; letter-spacing: .05em; margin-bottom: .75rem; }}
.sb-subtitle {{ font-size: .67rem; font-weight: 400; color: #94a3b8;
    text-transform: none; letter-spacing: 0; margin-left: .4rem; }}
.sb-row {{ display: flex; align-items: center; gap: .6rem; margin-bottom: .42rem; }}
.sb-name {{ font-size: .77rem; color: #1e293b; font-weight: 500; width: 200px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }}
.sb-bar {{ flex: 1; height: 9px; border-radius: 5px; background: #e2e8f0;
    overflow: hidden; display: flex; min-width: 80px; }}
.sb-bar span {{ display: block; height: 100%; }}
.sb-pct {{ font-size: .77rem; font-weight: 700; width: 40px; text-align: right; flex-shrink: 0; }}
</style>
</head>
<body>
<a id="top"></a>
<header>
  <h1>🔒 CIS Azure Audit Report — {ts}</h1>
  <p>Audit Tool v{VERSION} &nbsp;·&nbsp; Generated: {ts}</p>
  {scope_block}
</header>
<div class="cards">
  <div class="card c-sc">
    <div class="n">{score}%</div>
    <div class="l">Compliance Score</div>
  </div>
  <div class="card c-pa"><div class="n">{counts[PASS]}</div><div class="l">✅ Passed</div></div>
  <div class="card c-fa"><div class="n">{counts[FAIL]}</div><div class="l">❌ Failed</div></div>
  <div class="card c-er"><div class="n">{counts[ERROR]}</div><div class="l">⚠️ Errors</div></div>
  <div class="card c-in"><div class="n">{counts[INFO]}</div><div class="l">ℹ️ Info/N/A</div></div>
  <div class="card c-ma"><div class="n">{counts[MANUAL]}</div><div class="l">📋 Manual</div></div>
  <div class="card c-su"><div class="n">{counts[SUPPRESSED]}</div><div class="l">🔇 Suppressed</div></div>
</div>
<div class="dashboard">
  <div class="dash-donuts">
    <div class="donut-group">
      <div class="donut-label">Overall</div>
      <canvas id="d-overall" width="110" height="110"></canvas>
      <div id="pct-overall" class="donut-pct" style="color:{score_col}">{score}%</div>
      <div id="cnt-overall" class="donut-cnt">{overall_pass} / {overall_total} pass</div>
    </div>
    <div class="donut-group">
      <div class="donut-label">Level 1<span class="lv-badge" style="background:#dc2626">L1</span></div>
      <canvas id="d-l1" width="110" height="110"></canvas>
      <div id="pct-l1" class="donut-pct" style="color:{l1_col}">{l1_score}%</div>
      <div id="cnt-l1" class="donut-cnt">{l1_counts[PASS]} / {l1_total} pass</div>
    </div>
    <div class="donut-group">
      <div class="donut-label">Level 2<span class="lv-badge" style="background:#7c3aed">L2</span></div>
      <canvas id="d-l2" width="110" height="110"></canvas>
      <div id="pct-l2" class="donut-pct" style="color:{l2_col}">{l2_score}%</div>
      <div id="cnt-l2" class="donut-cnt">{l2_counts[PASS]} / {l2_total} pass</div>
    </div>
    <div class="donut-legend">
      <span><i style="background:#16a34a"></i>Pass</span>
      <span><i style="background:#dc2626"></i>Fail</span>
      <span><i style="background:#cbd5e1"></i>Error / N/A</span>
    </div>
  </div>
  <div class="sec-breakdown" id="sec-breakdown"></div>
</div>
{trend_block}
{sub_table}
<div class="filters">
  <label>Filter:</label>
  <input id="s" placeholder="Search control ID or title...">
  <select id="st">
    <option value="">All statuses</option>
    <option>PASS</option><option>FAIL</option><option>ERROR</option>
    <option>INFO</option><option>MANUAL</option><option>SUPPRESSED</option>
  </select>
  <select id="lv">
    <option value="">All levels</option>
    <option value="L1">Level 1</option><option value="L2">Level 2</option>
  </select>
  <a href="{json_name}" class="exp-btn">&#8681; Export JSON</a>
  <a href="{csv_data_uri}" download="{csv_name}" class="exp-btn">&#8681; Export CSV</a>
</div>
<div class="wrap"><table>
<thead><tr>
  <th>Control</th><th>Level</th><th>Title</th><th>Subscription / Resource</th><th>Status</th><th>Details</th>
</tr></thead>
<tbody id="tb">{rows}</tbody>
</table></div>
<a href="#top" id="back-top" title="Back to top">&#8679;</a>
<footer>
  CIS Microsoft Azure Foundations Benchmark v{BENCHMARK_VER} (Sep 2025) &nbsp;·&nbsp;
  Tool v{VERSION} &nbsp;·&nbsp;
  Compliance score excludes INFO, MANUAL, and SUPPRESSED checks.
  Manual controls require separate review per the CIS PDF.
</footer>
<script>
/* ── Live filter ────────────────────────────────────────────────────────────
   Filters table rows in real-time as the user types or changes dropdowns.
   Section header rows (class "sh") are hidden when all their data rows are
   hidden, preventing empty section headers in the filtered view.
────────────────────────────────────────────────────────────────────────── */
(function(){{
  var s  = document.getElementById('s');    // Search text input
  var st = document.getElementById('st');   // Status dropdown
  var lv = document.getElementById('lv');   // Level dropdown

  /* Data for charts — passed from Python */
  var JS_COUNTS   = {{PASS: {counts[PASS]}, FAIL: {counts[FAIL]}, ERROR: {counts[ERROR]}}};
  var JS_L1       = {{pass: {l1_counts[PASS]}, fail: {l1_counts[FAIL]}, error: {l1_counts[ERROR]}}};
  var JS_L2       = {{pass: {l2_counts[PASS]}, fail: {l2_counts[FAIL]}, error: {l2_counts[ERROR]}}};
  var JS_SECTIONS = {sec_data_json};

  /* Active subscription filter — empty string means "show all" */
  var subF = '';

  /* Tracks which section IDs are collapsed (true = collapsed) */
  var _collapsed = {{}};

  /* Section collapse — event delegation (onclick attr can't reach IIFE-scoped functions) */
  document.querySelectorAll('#tb tr.sh').forEach(function(hdr) {{
    hdr.addEventListener('click', function() {{
      var id = hdr.dataset.secId;
      _collapsed[id] = !_collapsed[id];
      hdr.querySelector('.sec-arrow').textContent = _collapsed[id] ? '▶' : '▼';
      filter();
    }});
  }});

  function filter(){{
    var sv  = s.value.toLowerCase();    // Search value (lowercase for case-insensitive match)
    var stv = st.value;                 // Selected status ("PASS", "FAIL", etc. or "")
    var lvv = lv.value;                 // Selected level ("L1", "L2", or "")
    var filtering = !!(sv || stv || lvv || subF); // Any filter active?

    /* Show/hide data rows — collapse state is overridden when a filter is active */
    document.querySelectorAll('#tb tr:not(.sh)').forEach(function(r){{
      var badge = r.querySelector('.badge');  // Status badge element
      var lb    = r.querySelector('.lv');     // Level badge element

      var ok = (!sv  || r.textContent.toLowerCase().includes(sv))    // Text search
              && (!stv || (badge && badge.textContent.includes(stv))) // Status filter
              && (!lvv || (lb    && lb.textContent === lvv))          // Level filter
              && (!subF || r.dataset.sub === subF);                   // Subscription filter

      /* Store filter match for section-header visibility logic below */
      r.dataset.filterMatch = ok ? '1' : '0';

      /* When filtering, show all matching rows regardless of collapse state */
      r.style.display = (ok && (!_collapsed[r.dataset.sec] || filtering)) ? '' : 'none';
    }});

    /* Hide section header rows only when no children match the current filter */
    document.querySelectorAll('#tb tr.sh').forEach(function(h){{
      var sib = h.nextElementSibling;
      var anyMatch = false;
      /* Walk siblings until the next section header (or end of tbody) */
      while (sib && !sib.classList.contains('sh')) {{
        if (sib.dataset.filterMatch === '1') anyMatch = true;
        sib = sib.nextElementSibling;
      }}
      h.style.display = anyMatch ? '' : 'none';
    }});
  }}

  /* Attach event listeners to all three filter controls */
  s.addEventListener('input', filter);
  st.addEventListener('change', filter);
  lv.addEventListener('change', filter);

  /* Subscription summary row click — click to filter, click again to deselect */
  document.querySelectorAll('.sub-row').forEach(function(row) {{
    row.addEventListener('click', function() {{
      if (subF === row.dataset.sub) {{
        subF = '';
        row.classList.remove('active');
      }} else {{
        subF = row.dataset.sub;
        document.querySelectorAll('.sub-row').forEach(function(r) {{ r.classList.remove('active'); }});
        row.classList.add('active');
      }}
      filter();
      updateCharts();
    }});
  }});

  /* Recompute and redraw donuts + section breakdown for the selected subscription.
     When no subscription is selected, restore the full-audit data. */
  function updateCharts() {{
    var counts, l1, l2, secs;
    if (!subF) {{
      counts = JS_COUNTS;
      l1     = JS_L1;
      l2     = JS_L2;
      secs   = JS_SECTIONS;
    }} else {{
      counts = {{PASS: 0, FAIL: 0, ERROR: 0}};
      l1     = {{pass: 0, fail: 0, error: 0}};
      l2     = {{pass: 0, fail: 0, error: 0}};
      secs   = {{}};
      document.querySelectorAll('#tb tr:not(.sh)').forEach(function(r) {{
        if (r.dataset.sub !== subF) return;
        var st  = r.dataset.status;
        var lvl = r.dataset.level;
        var sn  = r.dataset.secName;
        if (!secs[sn]) secs[sn] = {{pass: 0, fail: 0, error: 0, score: 0}};
        if (st === 'PASS')  {{ counts.PASS++;  secs[sn].pass++;  (lvl === 'L1' ? l1 : l2).pass++;  }}
        else if (st === 'FAIL')  {{ counts.FAIL++;  secs[sn].fail++;  (lvl === 'L1' ? l1 : l2).fail++;  }}
        else if (st === 'ERROR') {{ counts.ERROR++; secs[sn].error++; (lvl === 'L1' ? l1 : l2).error++; }}
      }});
      Object.keys(secs).forEach(function(sn) {{
        var d = secs[sn];
        d.score = Math.round(d.pass / Math.max(d.pass + d.fail + d.error, 1) * 1000) / 10;
      }});
    }}
    ['d-overall', 'd-l1', 'd-l2'].forEach(function(id) {{
      var cv = document.getElementById(id);
      if (cv) cv.getContext('2d').clearRect(0, 0, cv.width, cv.height);
    }});
    drawDonut('d-overall', counts.PASS, counts.FAIL, counts.ERROR);
    drawDonut('d-l1',      l1.pass,     l1.fail,     l1.error);
    drawDonut('d-l2',      l2.pass,     l2.fail,     l2.error);
    renderSectionBreakdown(secs);

    /* Update percentage text below each donut */
    function scoreColor(s) {{ return s >= 80 ? '#16a34a' : s >= 60 ? '#d97706' : '#dc2626'; }}
    function pct(p, f, e) {{ return Math.round(p / Math.max(p + f + e, 1) * 1000) / 10; }}
    var sc  = pct(counts.PASS, counts.FAIL, counts.ERROR);
    var l1s = pct(l1.pass, l1.fail, l1.error);
    var l2s = pct(l2.pass, l2.fail, l2.error);
    [['pct-overall', sc], ['pct-l1', l1s], ['pct-l2', l2s]].forEach(function(pair) {{
      var el = document.getElementById(pair[0]);
      if (el) {{ el.textContent = pair[1] + '%'; el.style.color = scoreColor(pair[1]); }}
    }});
    var ot = counts.PASS + counts.FAIL + counts.ERROR;
    var l1t = l1.pass + l1.fail + l1.error;
    var l2t = l2.pass + l2.fail + l2.error;
    [['cnt-overall', counts.PASS, ot], ['cnt-l1', l1.pass, l1t], ['cnt-l2', l2.pass, l2t]].forEach(function(t) {{
      var el = document.getElementById(t[0]);
      if (el) el.textContent = t[1] + ' / ' + t[2] + ' pass';
    }});
  }}

  /* Draw three compliance donut charts and section breakdown */
  updateCharts();

  /* Donut ring chart: pass (green) / fail (red) / error (neutral gray — not a compliance failure) */
  function drawDonut(id, pass, fail, error) {{
    var cv = document.getElementById(id);
    if (!cv) return;
    var ctx = cv.getContext('2d');
    var cx = 55, cy = 55, r = 44, ri = 28;
    var total = pass + fail + error;
    if (total === 0) return;
    var segs = [[pass,'#16a34a'],[fail,'#dc2626'],[error,'#cbd5e1']];
    var start = -Math.PI / 2;
    segs.forEach(function(seg) {{
      if (!seg[0]) return;
      var arc = (seg[0] / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.moveTo(cx + r * Math.cos(start), cy + r * Math.sin(start));
      ctx.arc(cx, cy, r, start, start + arc);
      ctx.arc(cx, cy, ri, start + arc, start, true);
      ctx.closePath();
      ctx.fillStyle = seg[1];
      ctx.fill();
      start += arc;
    }});
    /* punch center hole white */
    ctx.beginPath();
    ctx.arc(cx, cy, ri - 1, 0, 2 * Math.PI);
    ctx.fillStyle = '#fff';
    ctx.fill();
  }}

  /* Section breakdown: horizontal stacked bars sorted worst → best */
  function renderSectionBreakdown(data) {{
    data = data || JS_SECTIONS;
    var el = document.getElementById('sec-breakdown');
    if (!el) return;
    var secs = Object.keys(data)
      .filter(function(a) {{ return data[a].pass + data[a].fail > 0; }})
      .sort(function(a,b) {{
      return data[a].score - data[b].score;
    }});
    var h = '<div class="sb-title">Section Breakdown'
          + '<span class="sb-subtitle">worst \u2192 best</span></div>';
    secs.forEach(function(sec) {{
      var d = data[sec];
      var scored = d.pass + d.fail + d.error;
      var col = d.score >= 80 ? '#16a34a' : d.score >= 60 ? '#d97706' : '#dc2626';
      var pw = scored ? Math.round(d.pass  / scored * 100) : 0;
      var fw = scored ? Math.round(d.fail  / scored * 100) : 0;
      var ew = Math.max(0, 100 - pw - fw);
      h += '<div class="sb-row">'
         + '<div class="sb-name" title="' + sec + '">' + sec + '</div>'
         + '<div class="sb-bar">'
         + '<span style="width:' + pw + '%;background:#16a34a"></span>'
         + '<span style="width:' + fw + '%;background:#dc2626"></span>'
         + '<span style="width:' + ew + '%;background:#cbd5e1"></span>'
         + '</div>'
         + '<span class="sb-pct" style="color:' + col + '">' + d.score + '%</span>'
         + '</div>';
    }});
    el.innerHTML = h;
  }}

}})();
</script>
</body>
</html>"""

    with open(output, "w", encoding="utf-8") as fh:
        fh.write(page)
    LOGGER.info("\n\u2705 Report saved: %s", Path(output).resolve())
