"""
وحدة توليد التقارير
تنشئ ملف PDF يحتوي على تفاصيل نتيجة الفحص (رابط / ملف / IP)
ليتم إرساله للمستخدم بعد كل عملية فحص.
"""

import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_RIGHT, TA_CENTER

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


def _get_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="TitleAr", fontSize=18, alignment=TA_CENTER,
        spaceAfter=14, textColor=colors.HexColor("#1a1a2e")
    ))
    styles.add(ParagraphStyle(
        name="BodyAr", fontSize=11, alignment=TA_RIGHT, spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name="HeaderAr", fontSize=13, alignment=TA_RIGHT,
        spaceAfter=8, textColor=colors.HexColor("#0f3460")
    ))
    return styles


def _status_color(is_malicious: bool, suspicious: int = 0):
    if is_malicious:
        return colors.HexColor("#e63946")
    if suspicious:
        return colors.HexColor("#f4a261")
    return colors.HexColor("#2a9d8f")


def generate_url_report(result: dict, scan_id: int) -> str:
    """توليد تقرير PDF لفحص رابط، يرجع مسار الملف"""
    file_path = os.path.join(REPORTS_DIR, f"url_report_{scan_id}.pdf")
    styles = _get_styles()
    doc = SimpleDocTemplate(file_path, pagesize=A4,
                             topMargin=2*cm, bottomMargin=2*cm)
    elements = []

    elements.append(Paragraph("تقرير فحص رابط", styles["TitleAr"]))
    elements.append(Spacer(1, 0.3*cm))

    status_text = "ضار ⚠️" if result["is_malicious"] else "آمن ✅"
    status_color = _status_color(result["is_malicious"], result["suspicious_count"])

    info_data = [
        ["القيمة", "الحقل"],
        [result["url"], "الرابط"],
        [status_text, "الحالة"],
        [str(result["malicious_count"]), "عدد المحركات التي صنّفته ضاراً"],
        [str(result["suspicious_count"]), "عدد المحركات المشتبهة"],
        [str(result["harmless_count"]), "عدد المحركات التي صنّفته سليماً"],
        [str(result["total_engines"]), "إجمالي محركات الفحص"],
        [datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), "تاريخ الفحص"],
    ]

    table = Table(info_data, colWidths=[10*cm, 6*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 2), (0, 2), status_color),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 0.5*cm))

    if result["flagged_engines"]:
        elements.append(Paragraph("محركات الفحص التي صنّفت الرابط كخطر:", styles["HeaderAr"]))
        engines_text = "، ".join(result["flagged_engines"][:15])
        elements.append(Paragraph(engines_text, styles["BodyAr"]))

    elements.append(Spacer(1, 0.5*cm))
    elements.append(Paragraph(f"رابط التقرير الكامل: {result['vt_link']}", styles["BodyAr"]))

    doc.build(elements)
    return file_path


def generate_file_report(result: dict, scan_id: int) -> str:
    """توليد تقرير PDF لفحص ملف، يرجع مسار الملف"""
    file_path = os.path.join(REPORTS_DIR, f"file_report_{scan_id}.pdf")
    styles = _get_styles()
    doc = SimpleDocTemplate(file_path, pagesize=A4,
                             topMargin=2*cm, bottomMargin=2*cm)
    elements = []

    elements.append(Paragraph("تقرير فحص ملف", styles["TitleAr"]))
    elements.append(Spacer(1, 0.3*cm))

    status_text = "ضار ⚠️" if result["is_malicious"] else "آمن ✅"
    status_color = _status_color(result["is_malicious"], result["suspicious_count"])
    size_kb = result["file_size"] / 1024 if result["file_size"] else 0

    info_data = [
        ["القيمة", "الحقل"],
        [result["file_name"], "اسم الملف"],
        [result["file_type"], "نوع الملف"],
        [f"{size_kb:.1f} KB", "الحجم"],
        [result["sha256"], "SHA256"],
        [status_text, "الحالة"],
        [str(result["malicious_count"]), "عدد المحركات التي صنّفته ضاراً"],
        [str(result["suspicious_count"]), "عدد المحركات المشتبهة"],
        [str(result["total_engines"]), "إجمالي محركات الفحص"],
        [result.get("popular_threat_names") or "—", "نوع التهديد المحتمل"],
        [datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), "تاريخ الفحص"],
    ]

    table = Table(info_data, colWidths=[10*cm, 6*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 5), (0, 5), status_color),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 0.5*cm))

    if result["flagged_engines"]:
        elements.append(Paragraph("تفاصيل المحركات التي رصدت تهديداً:", styles["HeaderAr"]))
        detail_rows = [["النتيجة", "المحرك"]]
        for eng in result["flagged_engines"][:20]:
            detail_rows.append([eng["result"] or "—", eng["engine"]])
        detail_table = Table(detail_rows, colWidths=[10*cm, 6*cm])
        detail_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e63946")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(detail_table)

    elements.append(Spacer(1, 0.5*cm))
    elements.append(Paragraph(f"رابط التقرير الكامل: {result['vt_link']}", styles["BodyAr"]))

    doc.build(elements)
    return file_path


def generate_ip_report(result: dict, scan_id: int) -> str:
    """توليد تقرير PDF لفحص IP، يرجع مسار الملف"""
    file_path = os.path.join(REPORTS_DIR, f"ip_report_{scan_id}.pdf")
    styles = _get_styles()
    doc = SimpleDocTemplate(file_path, pagesize=A4,
                             topMargin=2*cm, bottomMargin=2*cm)
    elements = []

    elements.append(Paragraph("تقرير فحص عنوان IP", styles["TitleAr"]))
    elements.append(Spacer(1, 0.3*cm))

    info_data = [
        ["القيمة", "الحقل"],
        [result["ip"], "عنوان IP"],
        [f"{result['country']} ({result['country_code']})", "الدولة"],
        [result["city"] or "—", "المدينة"],
        [result["region"] or "—", "المنطقة"],
        [result["timezone"] or "—", "المنطقة الزمنية"],
        [result["isp"] or "—", "مزود الخدمة"],
        [result.get("org") or "—", "المؤسسة"],
        ["نعم" if result.get("is_proxy_or_vpn") else "لا", "يستخدم VPN/Proxy"],
        ["نعم" if result.get("is_hosting") else "لا", "خادم استضافة"],
        [datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), "تاريخ الفحص"],
    ]

    table = Table(info_data, colWidths=[10*cm, 6*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 0.5*cm))
    elements.append(Paragraph(
        "ملاحظة: هذا موقع تقريبي على مستوى المدينة/مزود الخدمة وليس موقعاً دقيقاً لجهاز أو شخص.",
        styles["BodyAr"]
    ))

    doc.build(elements)
    return file_path
