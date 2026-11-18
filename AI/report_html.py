"""
Turns generate_report()'s JSON output into an actual styled, printable HTML
page — one self-contained string, no external CSS/JS/fonts, so it works as
a browser tab, a download, or a print-to-PDF target with zero setup.

Usage:

    from report_generator import generate_report
    from report_html import render_report_html

    report = generate_report(findings)
    html = render_report_html(report, target_url="https://example.com")

In FastAPI (see the new endpoint added to main.py below this file):

    @app.get("/api/scans/{scan_id}/report/html")
    def scan_report_html(scan_id: int):
        scan = get_scan_by_id(scan_id)
        report = generate_report(scan["results"])
        html = render_report_html(report, target_url=scan["target_url"])
        return HTMLResponse(html)

Kenzy's button can just open that URL in a new tab/iframe — the page has
its own print button that calls window.print(), so "download as PDF" is
just the browser's native print-to-PDF, no extra library needed.
"""

import html as html_escape_module
from datetime import datetime


_SEVERITY_COLORS = {
    "critical": "#7c1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#1d4ed8",
}
_SEVERITY_BG = {
    "critical": "#fde8e8",
    "high": "#fef2f2",
    "medium": "#fffbeb",
    "low": "#eff6ff",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _esc(value) -> str:
    if value is None:
        return ""
    return html_escape_module.escape(str(value))


def _severity_badge(severity: str) -> str:
    severity = (severity or "low").lower()
    color = _SEVERITY_COLORS.get(severity, "#374151")
    bg = _SEVERITY_BG.get(severity, "#f3f4f6")
    return (
        f'<span class="badge" style="color:{color};background:{bg};border:1px solid {color}33;">'
        f'{_esc(severity.upper())}</span>'
    )


def _confidence_badge(confidence) -> str:
    if not confidence:
        return ""
    is_confirmed = str(confidence).lower() == "confirmed"
    color = "#065f46" if is_confirmed else "#92400e"
    bg = "#d1fae5" if is_confirmed else "#fef3c7"
    return (
        f'<span class="badge" style="color:{color};background:{bg};border:1px solid {color}33;">'
        f'{_esc(str(confidence).upper())}</span>'
    )


def _poc_block(poc: dict) -> str:
    if not poc:
        return ""
    parts = []

    raw_finding = poc.get("raw_finding")
    if raw_finding:
        parts.append(f'<div class="poc-line"><strong>Finding:</strong> {_esc(raw_finding)}</div>')

    evidence = poc.get("evidence")
    if evidence:
        parts.append(f'<pre class="poc-evidence">{_esc(evidence)}</pre>')

    payloads = poc.get("payload_suggestions") or []
    if payloads:
        items = "".join(f"<li><code>{_esc(p)}</code></li>" for p in payloads)
        parts.append(f'<div class="poc-line"><strong>Suggested payloads:</strong><ul>{items}</ul></div>')

    return "".join(parts)


def _finding_card(entry: dict) -> str:
    severity = entry.get("severity", "low")
    return f"""
    <div class="finding" style="border-left: 4px solid {_SEVERITY_COLORS.get(severity, '#374151')};">
      <div class="finding-header">
        <div class="finding-title">
          {_severity_badge(severity)}
          {_confidence_badge(entry.get("confidence"))}
          <span class="module-tag">{_esc(entry.get("module"))}</span>
        </div>
      </div>
      <div class="finding-target">{_esc(entry.get("target"))}</div>
      <div class="finding-explanation">{_esc(entry.get("explanation"))}</div>
      {f'<div class="fix"><strong>Suggested fix:</strong> {_esc(entry.get("fix_suggestion"))}</div>' if entry.get("fix_suggestion") else ""}
      <details class="poc-details">
        <summary>Proof of concept / evidence</summary>
        {_poc_block(entry.get("poc", {}))}
      </details>
    </div>
    """


def render_report_html(report: dict, target_url: str = "") -> str:
    """
    report: the dict returned by report_generator.generate_report().
    target_url: optional, just for the header — generate_report() itself
                doesn't carry the target, so pass it in from the scan row.

    Returns one complete, self-contained HTML document as a string.
    """
    summary = report.get("summary", {})
    stats = report.get("stats", {})
    findings = report.get("findings", [])
    generated_at = report.get("generated_at", datetime.utcnow().isoformat())

    by_severity = stats.get("by_severity", {})
    severity_chips = "".join(
        f'<div class="stat-chip" style="border-color:{_SEVERITY_COLORS.get(sev, "#374151")};">'
        f'<div class="stat-count" style="color:{_SEVERITY_COLORS.get(sev, "#374151")};">{count}</div>'
        f'<div class="stat-label">{_esc(sev.upper())}</div></div>'
        for sev, count in sorted(by_severity.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 99))
    )

    key_risks = summary.get("key_risks") or []
    key_risks_html = (
        "<ul>" + "".join(f"<li>{_esc(r)}</li>" for r in key_risks) + "</ul>"
        if key_risks else ""
    )

    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "low"), 99))
    findings_html = "".join(_finding_card(f) for f in sorted_findings) or (
        '<p class="empty-state">No findings to report.</p>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Penetration Test Report</title>
<style>
  :root {{
    --bg: #ffffff; --text: #111827; --muted: #6b7280; --border: #e5e7eb; --panel: #f9fafb;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      --bg: #0f1115; --text: #e5e7eb; --muted: #9ca3af; --border: #262a33; --panel: #171a21;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    background: var(--bg); color: var(--text); margin: 0; padding: 2rem;
    max-width: 900px; margin-inline: auto; line-height: 1.5;
  }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  .meta {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }}
  .print-btn {{
    position: fixed; top: 1rem; right: 1rem; padding: 0.5rem 1rem; border-radius: 6px;
    border: 1px solid var(--border); background: var(--panel); color: var(--text); cursor: pointer;
  }}
  .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; margin-bottom: 1.5rem; }}
  .panel h2 {{ font-size: 1.05rem; margin-top: 0; }}
  .stats-row {{ display: flex; gap: 0.75rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
  .stat-chip {{ border: 1px solid; border-radius: 10px; padding: 0.75rem 1rem; text-align: center; min-width: 80px; }}
  .stat-count {{ font-size: 1.4rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.75rem; color: var(--muted); letter-spacing: 0.05em; }}
  .finding {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem; }}
  .finding-title {{ display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; }}
  .badge {{ font-size: 0.7rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 999px; letter-spacing: 0.03em; }}
  .module-tag {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .finding-target {{ font-family: ui-monospace, Menlo, monospace; font-size: 0.85rem; color: var(--muted); word-break: break-all; margin-bottom: 0.5rem; }}
  .finding-explanation {{ margin-bottom: 0.5rem; }}
  .fix {{ font-size: 0.9rem; margin-bottom: 0.5rem; }}
  .poc-details summary {{ cursor: pointer; font-size: 0.85rem; color: var(--muted); }}
  .poc-line {{ font-size: 0.85rem; margin-top: 0.5rem; }}
  .poc-evidence {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.5rem;
                   font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; margin-top: 0.5rem; }}
  code {{ font-family: ui-monospace, Menlo, monospace; font-size: 0.8rem; }}
  .empty-state {{ color: var(--muted); font-style: italic; }}
  @media print {{
    .print-btn {{ display: none; }}
    body {{ padding: 0; max-width: 100%; }}
  }}
</style>
</head>
<body>
  <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>

  <h1>Penetration Test Report</h1>
  <div class="meta">
    {f"Target: {_esc(target_url)} &middot; " if target_url else ""}Generated {_esc(generated_at)}
  </div>

  <div class="stats-row">{severity_chips}</div>

  <div class="panel">
    <h2>Executive Summary</h2>
    <p>{_esc(summary.get("overview", ""))}</p>
    {f"<p><strong>Key risks:</strong></p>{key_risks_html}" if key_risks else ""}
    {f'<p><strong>Recommendation:</strong> {_esc(summary.get("overall_recommendation"))}</p>' if summary.get("overall_recommendation") else ""}
  </div>

  <h2>Findings ({len(sorted_findings)})</h2>
  {findings_html}

</body>
</html>"""
