from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from app.templates_config import templates
from app.database import get_db_connection
from app.auth import get_current_user
import os
from datetime import datetime

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard_view(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Total and counts by status
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    total_vulns = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('Açık', 'Open')")
    open_vulns = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('İnceleniyor', 'Investigating')")
    investigating_vulns = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('Aksiyon Alındı', 'Action Taken')")
    in_action_vulns = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('Kapatıldı', 'Closed')")
    closed_vulns = cursor.fetchone()[0]

    # Severity distribution
    cursor.execute("""
        SELECT severity, COUNT(*) as cnt 
        FROM vulnerabilities 
        GROUP BY severity
    """)
    sev_rows = cursor.fetchall()
    sev_counts = {"Kritik": 0, "Yüksek": 0, "Orta": 0, "Düşük": 0, "Bilgi": 0}
    for row in sev_rows:
        sev = row["severity"]
        if sev == "Critical": sev = "Kritik"
        elif sev == "High": sev = "Yüksek"
        elif sev == "Medium": sev = "Orta"
        elif sev == "Low": sev = "Düşük"
        elif sev == "Info": sev = "Bilgi"
        sev_counts[sev] = sev_counts.get(sev, 0) + row["cnt"]

    # Overdue termin count
    today_str = datetime.now().strftime("%Y-%m-%d")
    cursor.execute("""
        SELECT COUNT(*) FROM vulnerabilities 
        WHERE due_date < ? AND status NOT IN ('Kapatıldı', 'Closed', 'Yanlış Pozitif', 'False Positive')
    """, (today_str,))
    overdue_count = cursor.fetchone()[0]

    # Department distribution
    cursor.execute("""
        SELECT department, COUNT(*) as count,
               SUM(CASE WHEN severity IN ('Kritik', 'Critical') THEN 1 ELSE 0 END) as critical_count
        FROM vulnerabilities
        WHERE department != ''
        GROUP BY department
        ORDER BY count DESC
    """)
    department_stats = [dict(row) for row in cursor.fetchall()]

    # Scan tool distribution
    cursor.execute("""
        SELECT tool_source, COUNT(*) as count 
        FROM vulnerabilities 
        GROUP BY tool_source
    """)
    tool_stats = [dict(row) for row in cursor.fetchall()]

    # Key findings (Top critical and high open vulnerabilities)
    cursor.execute("""
        SELECT * FROM vulnerabilities 
        WHERE status NOT IN ('Kapatıldı', 'Closed')
        ORDER BY cvss_score DESC, id DESC 
        LIMIT 5
    """)
    key_findings = [dict(row) for row in cursor.fetchall()]

    # Target host distribution
    cursor.execute("""
        SELECT target_host, COUNT(*) as vuln_count,
               SUM(CASE WHEN severity IN ('Kritik', 'Critical') THEN 1 ELSE 0 END) as critical_cnt,
               target_os
        FROM vulnerabilities
        GROUP BY target_host
        ORDER BY vuln_count DESC
        LIMIT 6
    """)
    target_stats = [dict(row) for row in cursor.fetchall()]

    # ── Çalışan Aksiyon Takibi (Worker Action Timeline for Admin & Team) ──
    cursor.execute("""
        SELECT r.*, v.record_no, v.title, v.severity, u.role as author_role, u.department as author_dept
        FROM responses r
        JOIN vulnerabilities v ON r.vuln_id = v.id
        LEFT JOIN users u ON r.user_id = u.id
        ORDER BY r.id DESC LIMIT 10
    """)
    recent_activities = [dict(row) for row in cursor.fetchall()]

    # My claimed / assigned vulnerabilities (if worker or admin)
    cursor.execute("""
        SELECT * FROM vulnerabilities
        WHERE (assignee_user_id = ? OR assignee_email = ?) AND status != 'Kapatıldı'
        ORDER BY cvss_score DESC LIMIT 5
    """, (current_user["id"], current_user["email"]))
    my_active_vulns = [dict(row) for row in cursor.fetchall()]

    # Team members overview for Admin
    cursor.execute("""
        SELECT u.id, u.full_name, u.email, u.department, u.role,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE (v.assignee_user_id = u.id OR v.assignee_email = u.email) AND v.status != 'Kapatıldı') as open_tasks,
               (SELECT COUNT(*) FROM responses r WHERE r.user_id = u.id) as total_actions
        FROM users u
        WHERE u.is_active = 1
        ORDER BY total_actions DESC, open_tasks DESC
        LIMIT 6
    """)
    team_members = [dict(row) for row in cursor.fetchall()]

    # SLA Compliance rate
    resolved_count = closed_vulns
    sla_rate = round((resolved_count / total_vulns * 100), 1) if total_vulns > 0 else 100.0

    conn.close()

    return templates.TemplateResponse(request=request, name="dashboard.html", context={
        "page_title": "Security Operations Dashboard",
        "current_user": current_user,
        "total_vulns": total_vulns,
        "open_vulns": open_vulns,
        "investigating_vulns": investigating_vulns,
        "in_action_vulns": in_action_vulns,
        "closed_vulns": closed_vulns,
        "overdue_count": overdue_count,
        "sev_counts": sev_counts,
        "department_stats": department_stats,
        "tool_stats": tool_stats,
        "key_findings": key_findings,
        "target_stats": target_stats,
        "recent_activities": recent_activities,
        "my_active_vulns": my_active_vulns,
        "team_members": team_members,
        "sla_rate": sla_rate,
        "today": today_str
    })
