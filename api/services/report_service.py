"""PDF report generation service for executive and technical reports."""
import io
import json
from datetime import datetime
from typing import Optional

from fpdf import FPDF

# ── Color palette (matching ARCA brand) ────────────────────────────
BRAND_NAVY = (15, 23, 42)
BRAND_GREEN = (34, 197, 94)
BRAND_GRAY = (100, 116, 139)
BRAND_LIGHT = (241, 245, 249)
WHITE = (255, 255, 255)

SEV_COLORS = {
    "critical": (220, 38, 38),
    "high": (234, 88, 12),
    "medium": (234, 179, 8),
    "low": (59, 130, 246),
    "informational": (107, 114, 128),
}


class ARCAReport(FPDF):
    """Base PDF class with ARCA branding."""

    def __init__(self, report_type: str = "executive", **kwargs):
        super().__init__(**kwargs)
        self.report_type = report_type
        self.set_auto_page_break(auto=True, margin=25)

    def header(self):
        # Navy header bar
        self.set_fill_color(*BRAND_NAVY)
        self.rect(0, 0, 210, 18, "F")
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 11)
        self.set_xy(10, 4)
        self.cell(0, 10, "ARCA  |  Cloud Security Posture Management", ln=False)
        self.set_font("Helvetica", "", 8)
        self.set_xy(150, 4)
        rtype = "Executive Report" if self.report_type == "executive" else "Technical Report"
        self.cell(50, 10, rtype, ln=False, align="R")
        self.ln(18)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*BRAND_GRAY)
        self.cell(0, 10, f"ARCA Report  |  Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", ln=False)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", ln=False, align="R")

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*BRAND_NAVY)
        self.cell(0, 10, title, ln=True)
        # Green underline
        self.set_draw_color(*BRAND_GREEN)
        self.set_line_width(0.8)
        self.line(self.get_x(), self.get_y(), self.get_x() + 60, self.get_y())
        self.ln(4)

    def sub_title(self, title: str):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*BRAND_NAVY)
        self.cell(0, 8, title, ln=True)
        self.ln(2)

    def body_text(self, text: str):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(51, 65, 85)
        self.multi_cell(0, 5, text)
        self.ln(2)

    def severity_badge(self, severity: str, x: float, y: float):
        color = SEV_COLORS.get(severity, SEV_COLORS["informational"])
        self.set_fill_color(*color)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 7)
        w = self.get_string_width(severity.upper()) + 6
        self.set_xy(x, y)
        self.cell(w, 5, severity.upper(), fill=True, align="C")

    def stat_box(self, x: float, y: float, w: float, h: float,
                 label: str, value: str, color=BRAND_NAVY):
        self.set_fill_color(*BRAND_LIGHT)
        self.rect(x, y, w, h, "F")
        self.set_draw_color(226, 232, 240)
        self.rect(x, y, w, h, "D")
        # Value
        self.set_xy(x, y + 4)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(*color)
        self.cell(w, 10, str(value), align="C")
        # Label
        self.set_xy(x, y + 16)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*BRAND_GRAY)
        self.cell(w, 5, label, align="C")

    def severity_bar(self, x: float, y: float, width: float,
                     counts: dict, total: int):
        """Draw a horizontal stacked severity bar."""
        if total == 0:
            return
        cur_x = x
        for sev in ["critical", "high", "medium", "low", "informational"]:
            count = counts.get(sev, 0)
            if count == 0:
                continue
            seg_w = (count / total) * width
            color = SEV_COLORS.get(sev, SEV_COLORS["informational"])
            self.set_fill_color(*color)
            self.rect(cur_x, y, seg_w, 8, "F")
            if seg_w > 12:
                self.set_xy(cur_x, y)
                self.set_font("Helvetica", "B", 6)
                self.set_text_color(*WHITE)
                self.cell(seg_w, 8, str(count), align="C")
            cur_x += seg_w


def generate_executive_report(
    overview: dict,
    findings_by_severity: dict,
    findings_by_service: dict,
    compliance_summary: Optional[dict],
    attack_paths_summary: Optional[dict],
    provider_info: dict,
    filters: dict,
) -> bytes:
    """Generate an executive summary PDF report."""
    pdf = ARCAReport(report_type="executive")
    pdf.alias_nb_pages()
    pdf.add_page()

    # ── Cover section ──────────────────────────────────────────────
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*BRAND_NAVY)
    pdf.cell(0, 15, "Security Posture Executive Summary", ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*BRAND_GRAY)
    generated = datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC")
    pdf.cell(0, 6, f"Generated: {generated}", ln=True)

    if filters.get("provider_type"):
        pdf.cell(0, 6, f"Cloud Provider: {filters['provider_type'].upper()}", ln=True)
    if filters.get("account_id"):
        pdf.cell(0, 6, f"Account: {filters['account_id']}", ln=True)

    pdf.ln(8)

    # ── Key Metrics ────────────────────────────────────────────────
    pdf.section_title("Key Metrics")

    total_findings = overview.get("total_findings", 0)
    pass_rate = overview.get("pass_rate", 0)
    total_scans = overview.get("total_scans", 0)
    total_providers = overview.get("total_cloud_providers", 0) + overview.get("total_saas_connections", 0)

    y = pdf.get_y()
    box_w = 43
    gap = 4
    pdf.stat_box(10, y, box_w, 26, "Total Findings", str(total_findings))
    pdf.stat_box(10 + box_w + gap, y, box_w, 26, "Pass Rate",
                 f"{pass_rate}%", BRAND_GREEN if pass_rate >= 70 else SEV_COLORS["high"])
    pdf.stat_box(10 + 2 * (box_w + gap), y, box_w, 26, "Scans Run", str(total_scans))
    pdf.stat_box(10 + 3 * (box_w + gap), y, box_w, 26, "Providers", str(total_providers))
    pdf.set_y(y + 32)

    # ── Risk Overview ──────────────────────────────────────────────
    pdf.section_title("Risk Overview")

    sev_counts = overview.get("severity_breakdown", {})
    pdf.body_text(
        f"Out of {total_findings} total findings, "
        f"{sev_counts.get('critical', 0)} are critical, "
        f"{sev_counts.get('high', 0)} are high severity, "
        f"{sev_counts.get('medium', 0)} are medium, and "
        f"{sev_counts.get('low', 0)} are low."
    )

    # Severity distribution bar
    y = pdf.get_y()
    pdf.severity_bar(10, y, 190, sev_counts, total_findings)
    pdf.set_y(y + 14)

    # Severity legend
    pdf.set_font("Helvetica", "", 7)
    x = 10
    for sev in ["critical", "high", "medium", "low", "informational"]:
        color = SEV_COLORS[sev]
        pdf.set_fill_color(*color)
        pdf.rect(x, pdf.get_y(), 4, 4, "F")
        pdf.set_xy(x + 5, pdf.get_y())
        pdf.set_text_color(*BRAND_GRAY)
        label = f"{sev.title()} ({sev_counts.get(sev, 0)})"
        pdf.cell(30, 4, label)
        x += 38
    pdf.ln(10)

    # ── Top Affected Services ──────────────────────────────────────
    if findings_by_service:
        pdf.section_title("Top Affected Services")
        sorted_services = sorted(findings_by_service.items(), key=lambda x: x[1], reverse=True)[:10]
        max_count = sorted_services[0][1] if sorted_services else 1

        for svc, count in sorted_services:
            y = pdf.get_y()
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*BRAND_NAVY)
            pdf.cell(35, 6, svc, ln=False)
            bar_w = (count / max_count) * 120
            pdf.set_fill_color(*BRAND_GREEN)
            pdf.rect(50, y + 1, bar_w, 4, "F")
            pdf.set_xy(50 + bar_w + 3, y)
            pdf.set_text_color(*BRAND_GRAY)
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(20, 6, str(count))
            pdf.ln(7)
        pdf.ln(4)

    # ── Attack Paths Summary ───────────────────────────────────────
    if attack_paths_summary and attack_paths_summary.get("total_paths", 0) > 0:
        pdf.section_title("Attack Path Analysis")
        aps = attack_paths_summary
        pdf.body_text(
            f"ARCA discovered {aps['total_paths']} attack path(s) across your environment. "
            f"{aps.get('critical_paths', 0)} are critical severity with an average risk score "
            f"of {aps.get('avg_risk_score', 0)}."
        )
        y = pdf.get_y()
        pdf.stat_box(10, y, 35, 24, "Total Paths", str(aps["total_paths"]))
        pdf.stat_box(49, y, 35, 24, "Critical", str(aps.get("critical_paths", 0)),
                     SEV_COLORS["critical"])
        pdf.stat_box(88, y, 35, 24, "High", str(aps.get("high_paths", 0)),
                     SEV_COLORS["high"])
        pdf.stat_box(127, y, 35, 24, "Avg Score",
                     str(aps.get("avg_risk_score", 0)), BRAND_NAVY)
        pdf.set_y(y + 30)

    # ── Compliance Summary ─────────────────────────────────────────
    if compliance_summary and compliance_summary.get("frameworks"):
        pdf.section_title("Compliance Status")
        for fw in compliance_summary["frameworks"][:5]:
            y = pdf.get_y()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*BRAND_NAVY)
            fw_name = fw.get("name", fw.get("framework", ""))
            pdf.cell(60, 6, fw_name, ln=False)
            # Compliance score bar
            score = fw.get("pass_rate", fw.get("score", 0))
            bar_color = BRAND_GREEN if score >= 70 else SEV_COLORS["high"] if score >= 40 else SEV_COLORS["critical"]
            pdf.set_fill_color(226, 232, 240)
            pdf.rect(75, y + 1, 80, 4, "F")
            pdf.set_fill_color(*bar_color)
            pdf.rect(75, y + 1, max(score * 0.8, 0), 4, "F")
            pdf.set_xy(160, y)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*bar_color)
            pdf.cell(20, 6, f"{score:.0f}%", align="R")
            pdf.ln(8)
        pdf.ln(4)

    # ── Providers ──────────────────────────────────────────────────
    if provider_info.get("providers"):
        pdf.section_title("Connected Providers")
        for p in provider_info["providers"]:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*BRAND_NAVY)
            ptype = p.get("provider_type", "").upper()
            alias = p.get("alias", "")
            acct = p.get("account_id", "") or ""
            pdf.cell(0, 6, f"{ptype}  -  {alias}  ({acct})", ln=True)
        pdf.ln(4)

    # ── Recommendations ────────────────────────────────────────────
    pdf.section_title("Top Recommendations")
    recommendations = _generate_recommendations(sev_counts, findings_by_service, attack_paths_summary)
    for i, rec in enumerate(recommendations[:7], 1):
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*BRAND_NAVY)
        pdf.cell(0, 6, f"{i}. {rec['title']}", ln=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*BRAND_GRAY)
        pdf.multi_cell(0, 4, f"   {rec['description']}")
        pdf.ln(2)

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def generate_technical_report(
    overview: dict,
    findings: list[dict],
    findings_by_severity: dict,
    findings_by_service: dict,
    compliance_summary: Optional[dict],
    attack_paths: list[dict],
    provider_info: dict,
    filters: dict,
) -> bytes:
    """Generate a detailed technical PDF report."""
    pdf = ARCAReport(report_type="technical")
    pdf.alias_nb_pages()
    pdf.add_page()

    # ── Cover ──────────────────────────────────────────────────────
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*BRAND_NAVY)
    pdf.cell(0, 12, "Technical Security Assessment Report", ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*BRAND_GRAY)
    generated = datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC")
    pdf.cell(0, 6, f"Generated: {generated}", ln=True)

    if filters.get("provider_type"):
        pdf.cell(0, 6, f"Cloud Provider: {filters['provider_type'].upper()}", ln=True)
    if filters.get("account_id"):
        pdf.cell(0, 6, f"Account: {filters['account_id']}", ln=True)
    if filters.get("scan_id"):
        pdf.cell(0, 6, f"Scan ID: {filters['scan_id']}", ln=True)

    pdf.ln(8)

    # ── Summary Statistics ─────────────────────────────────────────
    pdf.section_title("Assessment Summary")

    total = overview.get("total_findings", 0)
    sev_counts = overview.get("severity_breakdown", {})
    pass_rate = overview.get("pass_rate", 0)

    y = pdf.get_y()
    pdf.stat_box(10, y, 37, 26, "Total Findings", str(total))
    pdf.stat_box(51, y, 37, 26, "Critical", str(sev_counts.get("critical", 0)),
                 SEV_COLORS["critical"])
    pdf.stat_box(92, y, 37, 26, "High", str(sev_counts.get("high", 0)),
                 SEV_COLORS["high"])
    pdf.stat_box(133, y, 37, 26, "Pass Rate",
                 f"{pass_rate}%", BRAND_GREEN if pass_rate >= 70 else SEV_COLORS["high"])
    pdf.set_y(y + 32)

    # Severity bar
    y = pdf.get_y()
    pdf.severity_bar(10, y, 190, sev_counts, total)
    pdf.set_y(y + 14)

    # ── Findings by Service Table ──────────────────────────────────
    if findings_by_service:
        pdf.section_title("Findings by Service")
        _draw_table(pdf, ["Service", "Count", "% of Total"],
                    [[svc, str(cnt), f"{(cnt/total*100):.1f}%" if total else "0%"]
                     for svc, cnt in sorted(findings_by_service.items(),
                                            key=lambda x: x[1], reverse=True)[:15]],
                    col_widths=[70, 30, 30])
        pdf.ln(6)

    # ── Detailed Findings ──────────────────────────────────────────
    pdf.section_title("Detailed Findings")

    failed_findings = [f for f in findings if f.get("status") == "FAIL"]
    failed_sorted = sorted(failed_findings,
                           key=lambda f: ["critical", "high", "medium", "low",
                                          "informational"].index(f.get("severity", "low")))

    sev_filter = filters.get("severity")
    service_filter = filters.get("service")
    if sev_filter:
        failed_sorted = [f for f in failed_sorted if f["severity"] == sev_filter]
    if service_filter:
        failed_sorted = [f for f in failed_sorted if f["service"] == service_filter]

    for i, finding in enumerate(failed_sorted[:100]):
        if pdf.get_y() > 250:
            pdf.add_page()

        y = pdf.get_y()

        # Severity badge
        pdf.severity_badge(finding["severity"], 10, y)

        # Finding title
        badge_w = pdf.get_string_width(finding["severity"].upper()) + 8
        pdf.set_xy(10 + badge_w + 2, y)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*BRAND_NAVY)
        title = finding.get("check_title", "")[:80]
        pdf.cell(0, 5, title, ln=True)

        # Details
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*BRAND_GRAY)
        service = finding.get("service", "")
        region = finding.get("region", "")
        resource = finding.get("resource_name") or finding.get("resource_id", "")
        pdf.cell(0, 4, f"Service: {service}   |   Region: {region}   |   Resource: {resource[:60]}", ln=True)

        # Status extended
        status_ext = finding.get("status_extended", "")
        if status_ext:
            pdf.set_x(10)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(71, 85, 105)
            pdf.multi_cell(190, 3.5, status_ext[:200])

        # Remediation
        remediation = finding.get("remediation", "")
        if remediation:
            pdf.set_x(10)
            pdf.set_font("Helvetica", "I", 7)
            pdf.set_text_color(*BRAND_GREEN)
            pdf.multi_cell(190, 3.5, f"Remediation: {remediation[:200]}")

        pdf.ln(3)

    if not failed_sorted:
        pdf.body_text("No failed findings matching the selected filters.")

    # ── Attack Paths Detail ────────────────────────────────────────
    if attack_paths:
        pdf.add_page()
        pdf.section_title("Attack Path Analysis")

        for ap in attack_paths[:10]:
            if pdf.get_y() > 230:
                pdf.add_page()

            pdf.sub_title(ap.get("title", ""))
            pdf.severity_badge(ap.get("severity", "medium"), 10, pdf.get_y())
            pdf.set_xy(10, pdf.get_y() + 7)
            pdf.body_text(ap.get("description", ""))

            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*BRAND_GRAY)
            pdf.cell(0, 5,
                     f"Risk Score: {ap.get('risk_score', 0)}   |   "
                     f"Nodes: {ap.get('node_count', 0)}   |   "
                     f"Edges: {ap.get('edge_count', 0)}   |   "
                     f"Entry: {ap.get('entry_point', '')}  ->  Target: {ap.get('target', '')}",
                     ln=True)

            techniques = ap.get("techniques", [])
            if techniques:
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(*BRAND_NAVY)
                pdf.cell(0, 5, "Techniques:", ln=True)
                pdf.set_font("Helvetica", "", 7)
                pdf.set_text_color(*BRAND_GRAY)
                for t in techniques:
                    pdf.cell(0, 4, f"  - {t}", ln=True)

            remediation = ap.get("remediation", [])
            if remediation:
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(*BRAND_GREEN)
                pdf.cell(0, 5, "Remediation:", ln=True)
                pdf.set_font("Helvetica", "", 7)
                pdf.set_text_color(71, 85, 105)
                for r in remediation:
                    pdf.cell(0, 4, f"  - {r}", ln=True)

            pdf.ln(6)

    # ── Compliance Detail ──────────────────────────────────────────
    if compliance_summary and compliance_summary.get("frameworks"):
        pdf.add_page()
        pdf.section_title("Compliance Assessment Detail")
        for fw in compliance_summary["frameworks"]:
            if pdf.get_y() > 240:
                pdf.add_page()
            fw_name = fw.get("name", fw.get("framework", ""))
            score = fw.get("pass_rate", fw.get("score", 0))
            pdf.sub_title(f"{fw_name} - {score:.0f}% Compliant")

            controls = fw.get("controls", [])
            if controls:
                rows = [[c.get("id", ""), c.get("title", "")[:50],
                         c.get("status", ""), f"{c.get('pass_rate', 0):.0f}%"]
                        for c in controls[:20]]
                _draw_table(pdf, ["ID", "Control", "Status", "Score"],
                            rows, col_widths=[25, 80, 30, 25])
            pdf.ln(6)

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def _draw_table(pdf: ARCAReport, headers: list[str], rows: list[list[str]],
                col_widths: Optional[list[int]] = None):
    """Draw a simple table."""
    if not col_widths:
        col_widths = [int(190 / len(headers))] * len(headers)

    # Header
    pdf.set_fill_color(*BRAND_NAVY)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 8)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 7, h, border=1, fill=True, align="C")
    pdf.ln()

    # Rows
    pdf.set_font("Helvetica", "", 7)
    for row_idx, row in enumerate(rows):
        if pdf.get_y() > 265:
            pdf.add_page()
            # Re-draw header
            pdf.set_fill_color(*BRAND_NAVY)
            pdf.set_text_color(*WHITE)
            pdf.set_font("Helvetica", "B", 8)
            for i, h in enumerate(headers):
                pdf.cell(col_widths[i], 7, h, border=1, fill=True, align="C")
            pdf.ln()
            pdf.set_font("Helvetica", "", 7)

        bg = BRAND_LIGHT if row_idx % 2 == 0 else WHITE
        pdf.set_fill_color(*bg)
        pdf.set_text_color(51, 65, 85)
        for i, cell in enumerate(row):
            pdf.cell(col_widths[i], 6, str(cell)[:40], border=1, fill=True)
        pdf.ln()


def _generate_recommendations(sev_counts: dict, by_service: dict,
                              attack_paths: Optional[dict]) -> list[dict]:
    """Generate smart recommendations based on findings data."""
    recs = []

    critical = sev_counts.get("critical", 0)
    high = sev_counts.get("high", 0)

    if critical > 0:
        recs.append({
            "title": f"Address {critical} Critical Findings Immediately",
            "description": "Critical findings represent the highest risk to your environment. "
                           "Prioritize remediation of these issues within 24-48 hours.",
        })

    if high > 5:
        recs.append({
            "title": f"Remediate {high} High Severity Findings",
            "description": "High severity findings should be addressed within 1-2 weeks. "
                           "Create a remediation plan and assign owners.",
        })

    iam_count = sum(v for k, v in by_service.items() if "iam" in k.lower() or "identity" in k.lower())
    if iam_count > 0:
        recs.append({
            "title": "Strengthen Identity & Access Management",
            "description": f"{iam_count} IAM-related findings detected. Review permissions, "
                           "enforce MFA, and apply least-privilege principles.",
        })

    storage_count = sum(v for k, v in by_service.items()
                        if any(s in k.lower() for s in ["s3", "storage", "objectstorage"]))
    if storage_count > 0:
        recs.append({
            "title": "Secure Data Storage Resources",
            "description": f"{storage_count} storage-related findings. Ensure encryption at rest, "
                           "block public access, and enable versioning.",
        })

    network_count = sum(v for k, v in by_service.items()
                        if any(s in k.lower() for s in ["vpc", "network", "nsg", "firewall"]))
    if network_count > 0:
        recs.append({
            "title": "Harden Network Security Controls",
            "description": f"{network_count} network findings. Restrict inbound rules, enable "
                           "flow logs, and use private endpoints where possible.",
        })

    if attack_paths and attack_paths.get("critical_paths", 0) > 0:
        recs.append({
            "title": f"Break {attack_paths['critical_paths']} Critical Attack Paths",
            "description": "Critical attack paths show multi-step chains an attacker could exploit. "
                           "Focus on breaking the chain at the earliest point.",
        })

    recs.append({
        "title": "Enable Continuous Monitoring",
        "description": "Schedule regular scans and enable cloud-native monitoring services "
                       "to detect configuration drift and new vulnerabilities.",
    })

    return recs
