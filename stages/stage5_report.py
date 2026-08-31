#!/usr/bin/env python3
"""
GQLRecon Stage 5: Risk Scoring and Report Generation (Part 2: HTML Report)

Takes the aggregated summary from stage5_aggregate.py and renders it as a
single self-contained HTML report, styled to match Sipar Security's other
tool outputs (black/white/green minimalist, IBM Plex Mono for data).

Usage:
    python3 stage5_report.py --stage1 ../output/stage1_dvga_test.json \\
                              --stage2 ../output/stage2_dvga_test.json \\
                              --stage3 ../output/stage3_dvga_test.json \\
                              --stage4 ../output/stage4_dvga_test.json \\
                              --output ../output/gqlrecon_report.html
"""

import argparse
import html
from datetime import datetime, timezone

from stage5_aggregate import aggregate_findings

SEVERITY_COLORS = {
    "CRITICAL": {"text": "#dc2626", "bg": "#fef2f2", "border": "#fecaca"},
    "HIGH": {"text": "#dc2626", "bg": "#fef2f2", "border": "#fecaca"},
    "MEDIUM": {"text": "#b45309", "bg": "#fffbeb", "border": "#fde68a"},
    "LOW": {"text": "#16a34a", "bg": "#f0fdf4", "border": "#bbf7d0"},
    "INFO": {"text": "#999999", "bg": "#f5f5f3", "border": "#e8e8e8"},
}

OVERALL_RISK_LABEL = {
    "CRITICAL": "Critical risk found",
    "HIGH": "High risk found",
    "MEDIUM": "Medium risk found",
    "LOW": "Low risk found",
    "INFO": "No significant risk found",
}


def render_finding_card(finding):
    colors = SEVERITY_COLORS.get(finding["severity"], SEVERITY_COLORS["INFO"])
    title = html.escape(finding["title"])
    detail = html.escape(finding["detail"])
    return f"""
    <div class="finding" style="border-left: 3px solid {colors['border']};">
      <div class="finding-header">
        <span class="severity-badge" style="background:{colors['bg']}; color:{colors['text']}; border:1px solid {colors['border']};">{finding['severity']}</span>
        <span class="finding-stage">Stage {finding['stage']}</span>
      </div>
      <div class="finding-title">{title}</div>
      <div class="finding-detail">{detail}</div>
    </div>"""


def render_report(summary, target_url_override=None):
    target_url = html.escape(target_url_override or summary.get("target_url") or "Unknown target")
    overall_risk = summary["overall_risk"]
    overall_colors = SEVERITY_COLORS.get(overall_risk, SEVERITY_COLORS["INFO"])
    overall_label = OVERALL_RISK_LABEL.get(overall_risk, overall_risk)
    counts = summary["severity_counts"]
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    findings_html = "".join(render_finding_card(f) for f in summary["findings"])
    if not summary["findings"]:
        findings_html = '<div class="no-findings">No findings to report.</div>'

    stages_run = [k.replace("stage", "Stage ") for k, v in summary["stages_included"].items() if v]
    stages_run_str = ", ".join(stages_run) if stages_run else "None"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>GQLRecon Report — {target_url}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {{
    --black: #0a0a0a; --white: #ffffff; --off: #f5f5f3; --text: #555; --light: #999; --border: #e8e8e8;
    --mono: 'IBM Plex Mono', monospace; --sans: 'Inter', sans-serif;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: var(--sans); background: var(--white); color: var(--black); -webkit-font-smoothing: antialiased; padding: 3rem 1.5rem; }}
  .wrap {{ max-width: 780px; margin: 0 auto; }}
  .report-header {{ margin-bottom: 2.5rem; }}
  .report-tool {{ font-family: var(--mono); font-size: 0.7rem; color: var(--light); letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 0.5rem; }}
  .report-title {{ font-size: 1.7rem; font-weight: 700; letter-spacing: -0.02em; margin-bottom: 0.5rem; }}
  .report-meta {{ font-family: var(--mono); font-size: 0.75rem; color: var(--light); }}
  .overall-banner {{ border-radius: 6px; padding: 1.5rem 1.75rem; margin-bottom: 2rem; background: {overall_colors['bg']}; border: 1px solid {overall_colors['border']}; }}
  .overall-label {{ font-size: 1.1rem; font-weight: 700; color: {overall_colors['text']}; margin-bottom: 0.4rem; }}
  .overall-sub {{ font-size: 0.85rem; color: var(--text); }}
  .counts-row {{ display: flex; gap: 1px; background: var(--border); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; margin-bottom: 2.5rem; }}
  .count-box {{ flex: 1; background: #fff; padding: 1.25rem 0.5rem; text-align: center; }}
  .count-n {{ font-size: 1.4rem; font-weight: 700; }}
  .count-l {{ font-family: var(--mono); font-size: 0.6rem; color: var(--light); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }}
  .section-title {{ font-size: 1.1rem; font-weight: 700; margin-bottom: 1rem; }}
  .finding {{ background: #fff; border: 1px solid var(--border); border-radius: 4px; padding: 1.25rem 1.5rem; margin-bottom: 0.85rem; }}
  .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.6rem; }}
  .severity-badge {{ font-family: var(--mono); font-size: 0.62rem; font-weight: 600; padding: 0.2rem 0.6rem; border-radius: 3px; letter-spacing: 0.04em; }}
  .finding-stage {{ font-family: var(--mono); font-size: 0.68rem; color: var(--light); }}
  .finding-title {{ font-size: 0.92rem; font-weight: 600; margin-bottom: 0.4rem; }}
  .finding-detail {{ font-size: 0.82rem; color: var(--text); line-height: 1.6; font-family: var(--mono); white-space: pre-wrap; word-break: break-word; }}
  .no-findings {{ font-size: 0.85rem; color: var(--light); font-style: italic; padding: 2rem; text-align: center; }}
  .footer-note {{ margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border); font-family: var(--mono); font-size: 0.7rem; color: var(--light); }}
</style>
</head>
<body>
<div class="wrap">
  <div class="report-header">
    <div class="report-tool">GQLRecon · Sipar Security</div>
    <div class="report-title">GraphQL Security Report</div>
    <div class="report-meta">Target: {target_url} &nbsp;·&nbsp; Generated: {timestamp} &nbsp;·&nbsp; Stages run: {stages_run_str}</div>
  </div>

  <div class="overall-banner">
    <div class="overall-label">{overall_label}</div>
    <div class="overall-sub">{len(summary['findings'])} finding(s) across {len([s for s in summary['stages_included'].values() if s])} stage(s) tested.</div>
  </div>

  <div class="counts-row">
    <div class="count-box"><div class="count-n" style="color:{SEVERITY_COLORS['CRITICAL']['text']};">{counts['CRITICAL']}</div><div class="count-l">Critical</div></div>
    <div class="count-box"><div class="count-n" style="color:{SEVERITY_COLORS['HIGH']['text']};">{counts['HIGH']}</div><div class="count-l">High</div></div>
    <div class="count-box"><div class="count-n" style="color:{SEVERITY_COLORS['MEDIUM']['text']};">{counts['MEDIUM']}</div><div class="count-l">Medium</div></div>
    <div class="count-box"><div class="count-n" style="color:{SEVERITY_COLORS['LOW']['text']};">{counts['LOW']}</div><div class="count-l">Low</div></div>
    <div class="count-box"><div class="count-n" style="color:{SEVERITY_COLORS['INFO']['text']};">{counts['INFO']}</div><div class="count-l">Info</div></div>
  </div>

  <div class="section-title">Findings</div>
  {findings_html}

  <div class="footer-note">
    Generated by GQLRecon, an open source GraphQL security fuzzer by Sipar Security.<br/>
    github.com/siparsecurity/gqlrecon
  </div>
</div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="GQLRecon Stage 5: Generate HTML report")
    parser.add_argument("--stage1", default=None)
    parser.add_argument("--stage2", default=None)
    parser.add_argument("--stage3", default=None)
    parser.add_argument("--stage4", default=None)
    parser.add_argument("--output", default="../output/gqlrecon_report.html")
    args = parser.parse_args()

    summary = aggregate_findings(args.stage1, args.stage2, args.stage3, args.stage4)
    html_out = render_report(summary)

    with open(args.output, "w") as f:
        f.write(html_out)

    print(f"[*] Report generated: {args.output}")
    print(f"[*] Overall risk: {summary['overall_risk']}")
    print(f"[*] Findings: {len(summary['findings'])}")


if __name__ == "__main__":
    main()
