"""Ransomware Readiness Report Generation Service.

Generates PDF reports for the Ransomware Readiness module using
the same HTML-to-PDF pipeline as the main report service.
"""
import json
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from api.models.rr_score import RRScore
from api.models.rr_finding import RRFinding
from scanner.ransomware_readiness.framework import (
    Domain, DOMAIN_METADATA, DOMAIN_WEIGHTS, get_rule_by_id, SCORE_LEVELS,
)

LEVEL_COLORS = {level["level"].value: level["color"] for level in SCORE_LEVELS}


async def gather_rr_report_data(db: AsyncSession, user_id: str) -> dict:
    """Gather all data needed for the RR report."""
    # Latest global score
    score_q = (
        select(RRScore)
        .where(RRScore.user_id == user_id, RRScore.scope == "global")
        .order_by(desc(RRScore.calculated_at)).limit(1)
    )
    score = (await db.execute(score_q)).scalar_one_or_none()

    if not score:
        return {"error": "No ransomware readiness assessment found. Run a scan first."}

    domain_scores = json.loads(score.domain_scores) if score.domain_scores else {}

    # Failed findings ordered by severity
    findings_q = (
        select(RRFinding)
        .where(
            RRFinding.user_id == user_id,
            RRFinding.status == "fail",
        )
        .order_by(desc(RRFinding.severity), desc(RRFinding.created_at))
        .limit(200)
    )
    findings = (await db.execute(findings_q)).scalars().all()

    # Build findings list with rule metadata
    findings_data = []
    for f in findings:
        rule = get_rule_by_id(f.rule_id)
        findings_data.append({
            "rule_id": f.rule_id,
            "rule_name": rule.name if rule else f.rule_id,
            "domain": f.domain,
            "severity": f.severity,
            "provider": f.provider,
            "account_id": f.account_id,
            "failed_resources": f.failed_resources,
            "remediation": rule.remediation if rule else {},
            "nist_category": rule.nist_category if rule else "",
        })

    # Score history for trending
    history_q = (
        select(RRScore)
        .where(RRScore.user_id == user_id, RRScore.scope == "global")
        .order_by(RRScore.calculated_at.asc())
        .limit(30)
    )
    history = (await db.execute(history_q)).scalars().all()

    return {
        "score": score.score,
        "level": score.level,
        "level_color": LEVEL_COLORS.get(score.level, "#C0392B"),
        "calculated_at": score.calculated_at.isoformat() if score.calculated_at else "",
        "checks_passed": score.checks_passed,
        "checks_failed": score.checks_failed,
        "checks_warning": score.checks_warning,
        "domain_scores": domain_scores,
        "findings": findings_data,
        "history": [{"date": h.calculated_at.strftime("%Y-%m-%d"), "score": h.score} for h in history],
        "domains_metadata": {d.value: DOMAIN_METADATA[d] for d in Domain},
        "domain_weights": {d.value: DOMAIN_WEIGHTS[d] for d in Domain},
    }


def generate_rr_executive_html(data: dict, org_name: str = "Organization") -> str:
    """Generate HTML for the RR executive report."""
    if "error" in data:
        return f"<html><body><h1>Error</h1><p>{data['error']}</p></body></html>"

    score = data["score"]
    level = data["level"]
    color = data["level_color"]
    ds = data["domain_scores"]
    findings = data["findings"]

    # Separate critical and high findings
    critical_findings = [f for f in findings if f["severity"] == "critical"]
    high_findings = [f for f in findings if f["severity"] == "high"]

    # Top 5 recommendations
    top_recs = []
    for f in (critical_findings + high_findings)[:5]:
        provider = f.get("provider", "aws")
        remediation = f.get("remediation", {}).get(provider, "See rule documentation")
        top_recs.append({"rule": f["rule_id"], "name": f["rule_name"], "remediation": remediation})

    # Domain rows
    domain_rows = ""
    for d in ["D1", "D2", "D3", "D4", "D5", "D6", "D7"]:
        ddata = ds.get(d, {})
        dname = ddata.get("name", d)
        dscore = ddata.get("final_score", 0)
        weight = data["domain_weights"].get(d, 0)
        dc = "#2D8B4E" if dscore >= 90 else "#27AE60" if dscore >= 70 else "#F39C12" if dscore >= 50 else "#E67E22" if dscore >= 30 else "#C0392B"
        domain_rows += f"""
        <tr>
            <td style="padding:8px;border-bottom:1px solid #eee;font-weight:600;">{d}</td>
            <td style="padding:8px;border-bottom:1px solid #eee;">{dname}</td>
            <td style="padding:8px;border-bottom:1px solid #eee;text-align:center;">
                <span style="background:{dc};color:#fff;padding:3px 10px;border-radius:12px;font-weight:700;font-size:13px;">{int(dscore)}</span>
            </td>
            <td style="padding:8px;border-bottom:1px solid #eee;text-align:center;">{int(weight*100)}%</td>
            <td style="padding:8px;border-bottom:1px solid #eee;text-align:center;">{ddata.get('checks_passed',0)}/{ddata.get('checks_total',0)}</td>
            <td style="padding:8px;border-bottom:1px solid #eee;text-align:center;color:#DC2626;font-weight:600;">{ddata.get('critical_fails',0)}</td>
        </tr>"""

    # Findings rows
    findings_rows = ""
    for f in (critical_findings + high_findings)[:20]:
        scolor = "#DC2626" if f["severity"] == "critical" else "#EA580C"
        findings_rows += f"""
        <tr>
            <td style="padding:6px 8px;border-bottom:1px solid #eee;font-size:12px;font-family:monospace;">{f['rule_id']}</td>
            <td style="padding:6px 8px;border-bottom:1px solid #eee;font-size:12px;">
                <span style="background:{scolor};color:#fff;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;">{f['severity'].upper()}</span>
            </td>
            <td style="padding:6px 8px;border-bottom:1px solid #eee;font-size:12px;">{f['rule_name']}</td>
            <td style="padding:6px 8px;border-bottom:1px solid #eee;font-size:12px;text-transform:uppercase;">{f['provider']}</td>
            <td style="padding:6px 8px;border-bottom:1px solid #eee;font-size:12px;text-align:center;">{f['failed_resources']}</td>
        </tr>"""

    # Recommendations
    recs_html = ""
    for i, r in enumerate(top_recs, 1):
        recs_html += f"""
        <div style="margin-bottom:12px;padding:12px;background:#f8f9fa;border-left:4px solid #012169;border-radius:4px;">
            <p style="margin:0 0 4px;font-weight:700;color:#012169;font-size:13px;">{i}. {r['rule']} — {r['name']}</p>
            <p style="margin:0;font-size:12px;color:#555;">{r['remediation']}</p>
        </div>"""

    date_str = datetime.utcnow().strftime("%B %d, %Y")

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
body {{ font-family: 'Helvetica Neue', Arial, sans-serif; color: #333; margin: 0; padding: 40px; }}
h1 {{ color: #012169; margin-bottom: 4px; }}
h2 {{ color: #012169; border-bottom: 2px solid #012169; padding-bottom: 6px; margin-top: 30px; }}
table {{ width: 100%; border-collapse: collapse; }}
th {{ background: #012169; color: #fff; padding: 8px; text-align: left; font-size: 12px; }}
</style></head>
<body>
<div style="text-align:center;margin-bottom:40px;">
    <h1 style="font-size:28px;margin-bottom:4px;">Ransomware Readiness Report</h1>
    <p style="color:#666;font-size:14px;">{org_name} &mdash; {date_str}</p>
    <div style="display:inline-block;margin:20px auto;padding:20px 40px;border-radius:16px;background:{color};">
        <span style="font-size:48px;font-weight:800;color:#fff;">{score}</span>
        <span style="font-size:18px;color:#fff;display:block;">{level}</span>
    </div>
    <p style="color:#888;font-size:12px;">Based on NIST CSF 2.0 | NISTIR 8374 | CIS Benchmarks</p>
</div>

<h2>Executive Summary</h2>
<p>The organization's Ransomware Readiness Score is <strong>{score}/100 ({level})</strong>.
The assessment evaluated <strong>{data['checks_passed'] + data['checks_failed'] + data['checks_warning']}</strong> controls across
7 security domains. <strong>{data['checks_passed']}</strong> controls passed, <strong>{data['checks_failed']}</strong> failed,
and <strong>{data['checks_warning']}</strong> require attention.
There are <strong>{len(critical_findings)}</strong> critical and <strong>{len(high_findings)}</strong> high severity findings requiring immediate action.</p>

<h2>Domain Scores</h2>
<table>
<tr><th>ID</th><th>Domain</th><th>Score</th><th>Weight</th><th>Pass/Total</th><th>Critical</th></tr>
{domain_rows}
</table>

<h2>Top Recommendations</h2>
{recs_html if recs_html else '<p style="color:#2D8B4E;font-weight:600;">All critical and high checks are passing. Excellent posture!</p>'}

<h2>Critical & High Findings</h2>
<table>
<tr><th>Rule</th><th>Severity</th><th>Name</th><th>Provider</th><th>Affected</th></tr>
{findings_rows if findings_rows else '<tr><td colspan="5" style="padding:12px;text-align:center;color:#2D8B4E;">No critical or high findings.</td></tr>'}
</table>

<h2>NIST CSF 2.0 Coverage</h2>
<p style="font-size:13px;">This assessment maps to the following NIST CSF 2.0 PROTECT categories:</p>
<ul style="font-size:12px;">
    <li><strong>PR.AA</strong> — Identity Management, Authentication, Access Control (D1)</li>
    <li><strong>PR.DS</strong> — Data Security (D2, D3)</li>
    <li><strong>PR.IR</strong> — Incident Response / Technology Infrastructure Resilience (D3, D4)</li>
    <li><strong>PR.PS</strong> — Platform Security (D5, D6)</li>
    <li><strong>PR.AT</strong> — Awareness & Training (D7)</li>
    <li><strong>GV</strong> — Governance (D7)</li>
</ul>

<div style="margin-top:40px;padding-top:20px;border-top:1px solid #ddd;text-align:center;color:#999;font-size:11px;">
    Generated by D-ARCA &mdash; Asset Risk & Cloud Analysis &mdash; {date_str}
</div>
</body></html>"""
