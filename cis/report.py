"""
cis_report.py — HTML report generation for the CIS Azure Audit Tool.

Contains generate_html() which produces a self-contained single-file HTML
report with embedded CSS, JavaScript, live filters, and export buttons.
"""

from __future__ import annotations

import datetime
import html
from pathlib import Path
from typing import Any

from cis.config import BENCHMARK_VER, LOGGER, VERSION, FAIL, INFO, MANUAL, PASS, ERROR
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
}


def generate_html(
    results: list[R],
    output: str,
    scope_info: dict[str, Any] | None = None,
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
    """
    # ── Counts and score ──────────────────────────────────────────────────────
    counts = {s: sum(1 for r in results if r.status == s) for s in [PASS, FAIL, ERROR, INFO, MANUAL]}
    total = len(results)

    # Compliance score excludes INFO (not applicable) and MANUAL (human review).
    # Score = PASS / (PASS + FAIL + ERROR) expressed as a percentage.
    denom = max(total - counts[INFO] - counts[MANUAL], 1)  # Avoid division by zero
    score = round(counts[PASS] / denom * 100, 1)

    # ── Build table rows grouped by section ───────────────────────────────────
    # Group results by their section field and sort alphabetically
    sections: dict = {}
    for r in results:
        sections.setdefault(r.section, []).append(r)

    rows = ""
    for sec in sorted(sections, key=lambda s: _ctrl_sort_key(s.split(" ")[0])):
        grp = sections[sec]
        # Count passing checks in this section (INFO and MANUAL excluded)
        sp = sum(1 for r in grp if r.status == PASS)
        rows += (
            f'<tr class="sh"><td colspan="6">'
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
            sub_stats[sn] = {PASS: 0, FAIL: 0, ERROR: 0, INFO: 0, MANUAL: 0}
        sub_stats[sn][r.status] = sub_stats[sn].get(r.status, 0) + 1

    def _sub_score(s: dict[str, int]) -> float:
        return s[PASS] / max(s[PASS] + s[FAIL] + s[ERROR], 1) * 100

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
        "<th>&#9888; Error</th><th>Info</th><th>Manual</th>"
        f"</tr></thead><tbody>{sub_rows_html}</tbody></table></div>"
        if sub_rows_html
        else ""
    )

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

/* ── Filter bar ── */
.filters {{ display: flex; align-items: center; gap: .75rem; padding: .8rem 2rem;
             background: #fff; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; }}
.filters label {{ font-weight: 600; font-size: .85rem; color: #475569; }}
.filters input, .filters select {{
    border: 1px solid #cbd5e1; border-radius: 6px; padding: .4rem .7rem;
    font-size: .85rem; outline: none; }}
.filters input {{ min-width: 220px; }}
.filters input:focus {{ border-color: #2563eb; }}

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
@media print {{ #back-top {{ display: none; }} }}

/* ── Print stylesheet ── */
@media print {{
    .filters {{ display: none; }}
    header {{ background: #1e3a5f !important; -webkit-print-color-adjust: exact; }}
    body {{ background: white; }}
    .cards .card {{ box-shadow: none; border: 1px solid #e2e8f0; }}
    table {{ box-shadow: none; }}
    tr {{ page-break-inside: avoid; }}
}}
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
</div>
<canvas id="pie" width="160" height="160" style="margin:1rem auto; display:block;"></canvas>
{sub_table}
<div class="filters">
  <label>Filter:</label>
  <input id="s" placeholder="Search control ID or title...">
  <select id="st">
    <option value="">All statuses</option>
    <option>PASS</option><option>FAIL</option><option>ERROR</option>
    <option>INFO</option><option>MANUAL</option>
  </select>
  <select id="lv">
    <option value="">All levels</option>
    <option value="L1">Level 1</option><option value="L2">Level 2</option>
  </select>
  <button id="btn-json">Copy JSON</button>
  <button id="btn-csv">Copy CSV</button>
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
  Compliance score excludes INFO and MANUAL checks.
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
  var btnJSON = document.getElementById('btn-json');
  var btnCSV  = document.getElementById('btn-csv');

  /* Counts passed from Python for chart drawing */
  var JS_COUNTS = {{PASS: {counts[PASS]}, FAIL: {counts[FAIL]}, ERROR: {counts[ERROR]}}};

  /* Active subscription filter — empty string means "show all" */
  var subF = '';

  function filter(){{
    var sv  = s.value.toLowerCase();    // Search value (lowercase for case-insensitive match)
    var stv = st.value;                 // Selected status ("PASS", "FAIL", etc. or "")
    var lvv = lv.value;                 // Selected level ("L1", "L2", or "")

    /* Show/hide data rows based on all four filters */
    document.querySelectorAll('#tb tr:not(.sh)').forEach(function(r){{
      var badge = r.querySelector('.badge');  // Status badge element
      var lb    = r.querySelector('.lv');     // Level badge element

      var ok = (!sv  || r.textContent.toLowerCase().includes(sv))    // Text search
              && (!stv || (badge && badge.textContent.includes(stv))) // Status filter
              && (!lvv || (lb    && lb.textContent === lvv))          // Level filter
              && (!subF || r.dataset.sub === subF);                   // Subscription filter

      r.style.display = ok ? '' : 'none';
    }});

    /* Hide section header rows when all their data rows are hidden */
    document.querySelectorAll('#tb tr.sh').forEach(function(h){{
      var sib = h.nextElementSibling;
      var vis = false;
      /* Walk siblings until the next section header (or end of tbody) */
      while (sib && !sib.classList.contains('sh')) {{
        if (sib.style.display !== 'none') vis = true;
        sib = sib.nextElementSibling;
      }}
      h.style.display = vis ? '' : 'none';
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
    }});
  }});

  /* Export button handlers — copy to clipboard (file:// safe) */
  function copyText(btn, text) {{
    navigator.clipboard.writeText(text).then(function() {{
      var orig = btn.textContent;
      btn.textContent = '✓ Copied!';
      setTimeout(function() {{ btn.textContent = orig; }}, 2000);
    }}).catch(function() {{
      /* Fallback: select from a temporary textarea */
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
      document.body.appendChild(ta);
      ta.focus(); ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      var orig = btn.textContent;
      btn.textContent = '✓ Copied!';
      setTimeout(function() {{ btn.textContent = orig; }}, 2000);
    }});
  }}

  btnJSON.addEventListener('click', function() {{
    var rows = document.querySelectorAll('#tb tr:not(.sh)');
    var arr = [];
    rows.forEach(function(r) {{
      if (r.style.display === 'none') return;
      arr.push({{
        control: r.cells[0].textContent.trim(),
        level: r.cells[1].textContent.trim(),
        title: r.cells[2].textContent.trim(),
        subscription: r.cells[3].textContent.trim(),
        status: r.cells[4].textContent.trim(),
        details: r.cells[5].textContent.trim()
      }});
    }});
    copyText(btnJSON, JSON.stringify(arr, null, 2));
  }});

  btnCSV.addEventListener('click', function() {{
    var rows = document.querySelectorAll('#tb tr:not(.sh)');
    var lines = ['Control,Level,Title,Subscription/Resource,Status,Details'];
    rows.forEach(function(r) {{
      if (r.style.display === 'none') return;
      var vals = [];
      for (var i = 0; i < 6; i++) {{
        var txt = r.cells[i].innerText.replace(/"/g, '""');
        vals.push('"' + txt + '"');
      }}
      lines.push(vals.join(','));
    }});
    copyText(btnCSV, lines.join('\n'));
  }});

  /* draw the compliance pie chart once the DOM is ready */
  drawPie();

  function drawPie() {{
    var canvas = document.getElementById('pie');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var data = JS_COUNTS;
    var total = data.PASS + data.FAIL + data.ERROR;
    if (total === 0) return;
    var start = 0;
    var colors = {{PASS: '#16a34a', FAIL: '#dc2626', ERROR: '#ea580c'}};
    Object.keys(data).forEach(function(k) {{
      var slice = (data[k] / total) * 2 * Math.PI;
      ctx.fillStyle = colors[k];
      ctx.beginPath();
      ctx.moveTo(80, 80);
      ctx.arc(80, 80, 60, start, start + slice);
      ctx.closePath();
      ctx.fill();
      start += slice;
    }});
  }}
}})();
</script>
</body>
</html>"""

    with open(output, "w", encoding="utf-8") as fh:
        fh.write(page)
    LOGGER.info("\n\u2705 Report saved: %s", Path(output).resolve())
