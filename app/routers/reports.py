from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from app.templates_config import templates
from app.database import get_db_connection
from app.auth import get_current_user
import os
from datetime import datetime

router = APIRouter(prefix="/reports")


@router.get("/executive", response_class=HTMLResponse)
async def executive_report(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login?next=/reports/executive", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT value FROM system_settings WHERE key = 'company_name'")
    comp_row = cursor.fetchone()
    company_name = comp_row[0] if comp_row else "Kurumsal Siber Güvenlik"

    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    total_vulns = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'Açık'")
    open_vulns = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'Kapatıldı'")
    closed_vulns = cursor.fetchone()[0]

    cursor.execute("SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity")
    sev_counts = {"Kritik": 0, "Yüksek": 0, "Orta": 0, "Düşük": 0, "Bilgi": 0}
    for row in cursor.fetchall():
        sev_counts[row["severity"]] = row["cnt"]

    cursor.execute("""
        SELECT target_host, target_os, COUNT(*) as vuln_count,
               SUM(CASE WHEN severity = 'Kritik' THEN 1 ELSE 0 END) as critical_count,
               SUM(CASE WHEN severity = 'Yüksek' THEN 1 ELSE 0 END) as high_count,
               department
        FROM vulnerabilities
        GROUP BY target_host
        ORDER BY critical_count DESC, high_count DESC, vuln_count DESC
    """)
    targets = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT tool_source, COUNT(*) as count 
        FROM vulnerabilities 
        GROUP BY tool_source
    """)
    tools = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT department, COUNT(*) as count,
               SUM(CASE WHEN severity IN ('Kritik', 'Yüksek') THEN 1 ELSE 0 END) as severe_count
        FROM vulnerabilities
        WHERE department != ''
        GROUP BY department
        ORDER BY count DESC
    """)
    departments = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT * FROM vulnerabilities
        ORDER BY cvss_score DESC, id DESC
    """)
    all_vulns = [dict(row) for row in cursor.fetchall()]

    key_findings = [v for v in all_vulns if v["severity"] in ["Kritik", "Yüksek"]]
    if not key_findings:
        key_findings = all_vulns[:5]

    conn.close()

    risk_index = round(min(100.0, (sev_counts["Kritik"] * 25 + sev_counts["Yüksek"] * 10 + sev_counts["Orta"] * 3) / max(1, total_vulns) * 10), 1)

    return templates.TemplateResponse(request=request, name="executive_report.html", context={
        "page_title": "Yönetici Özeti & Zaafiyet Değerlendirme Raporu",
        "current_user": current_user,
        "company_name": company_name,
        "report_date": datetime.now().strftime("%d.%m.%Y"),
        "total_vulns": total_vulns,
        "open_vulns": open_vulns,
        "closed_vulns": closed_vulns,
        "sev_counts": sev_counts,
        "risk_index": risk_index,
        "targets": targets,
        "tools": tools,
        "departments": departments,
        "key_findings": key_findings,
        "all_vulns": all_vulns
    })
