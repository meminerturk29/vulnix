from fastapi import APIRouter, Request, Form, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.database import (
    get_db_connection, generate_next_record_no, calculate_severity_from_cvss,
    UPLOAD_DIR
)
from app.auth import get_current_user
from app.email_service import notify_assignee_about_vulnerability, notify_sla_reminder
import os
import shutil
from datetime import datetime
from typing import Optional

router = APIRouter(prefix="/vulnerabilities")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"))


@router.get("", response_class=HTMLResponse)
async def list_vulnerabilities(
    request: Request,
    q: Optional[str] = "",
    severity: Optional[str] = "",
    department: Optional[str] = "",
    status: Optional[str] = "",
    overdue_only: Optional[bool] = False,
    my_only: Optional[bool] = False,
    msg: Optional[str] = None
):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url=f"/login?next={request.url.path}", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM vulnerabilities WHERE 1=1"
    params = []

    if q:
        query += " AND (title LIKE ? OR record_no LIKE ? OR target_host LIKE ? OR assignee_name LIKE ? OR cve_id LIKE ?)"
        search_term = f"%{q}%"
        params.extend([search_term, search_term, search_term, search_term, search_term])

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    if department:
        query += " AND department = ?"
        params.append(department)

    if status:
        query += " AND status = ?"
        params.append(status)

    today_str = datetime.now().strftime("%Y-%m-%d")
    if overdue_only:
        query += " AND due_date < ? AND status != 'Kapatıldı' AND status != 'Yanlış Pozitif'"
        params.append(today_str)

    if my_only:
        query += " AND (assignee_user_id = ? OR assignee_email = ?)"
        params.extend([current_user["id"], current_user["email"]])

    query += " ORDER BY CASE severity WHEN 'Kritik' THEN 1 WHEN 'Yüksek' THEN 2 WHEN 'Orta' THEN 3 WHEN 'Düşük' THEN 4 ELSE 5 END, id DESC"

    cursor.execute(query, params)
    vulns = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT DISTINCT department FROM vulnerabilities WHERE department != '' ORDER BY department")
    departments = [row[0] for row in cursor.fetchall()]

    conn.close()

    return templates.TemplateResponse(request=request, name="vulnerabilities_list.html", context={
        "page_title": "Zaafiyet Yönetim Tablosu",
        "current_user": current_user,
        "vulns": vulns,
        "departments": departments,
        "selected_q": q,
        "selected_severity": severity,
        "selected_department": department,
        "selected_status": status,
        "overdue_only": overdue_only,
        "my_only": my_only,
        "today": today_str,
        "msg": msg
    })


@router.get("/new", response_class=HTMLResponse)
async def new_vulnerability_form(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login?next=/vulnerabilities/new", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT department FROM vulnerabilities WHERE department != '' ORDER BY department")
    departments = [row[0] for row in cursor.fetchall()]

    # Fetch users for assignee selector
    cursor.execute("SELECT id, full_name, email, department FROM users WHERE is_active = 1 ORDER BY full_name")
    system_users = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(request=request, name="vulnerability_form.html", context={
        "page_title": "Yeni Zaafiyet Kaydı Ekle",
        "current_user": current_user,
        "vuln": None,
        "departments": departments,
        "system_users": system_users,
        "today": datetime.now().strftime("%Y-%m-%d")
    })


@router.post("/new")
async def create_vulnerability(
    request: Request,
    title: str = Form(...),
    cvss_score: float = Form(0.0),
    cvss_vector: str = Form(""),
    department: str = Form(...),
    assignee_name: str = Form(...),
    assignee_email: str = Form(...),
    assignee_user_id: Optional[int] = Form(None),
    status: str = Form("Açık"),
    due_date: str = Form(...),
    tool_source: str = Form("Manuel"),
    target_host: str = Form(...),
    target_port: str = Form(""),
    target_os: str = Form(""),
    description: str = Form(...),
    threat_assessment: str = Form(...),
    remediation: str = Form(...),
    cve_id: str = Form(""),
    notes: str = Form(""),
    send_email_now: Optional[bool] = Form(False),
    image_file: Optional[UploadFile] = File(None)
):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    # If assignee_user_id was not explicitly given, try to resolve by email
    if not assignee_user_id and assignee_email:
        cursor.execute("SELECT id FROM users WHERE email = ?", (assignee_email.strip().lower(),))
        u_row = cursor.fetchone()
        if u_row:
            assignee_user_id = u_row[0]

    record_no = generate_next_record_no(conn)
    severity = calculate_severity_from_cvss(cvss_score)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    image_path = ""
    if image_file and image_file.filename:
        filename = f"{record_no}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{image_file.filename}"
        file_location = os.path.join(UPLOAD_DIR, filename)
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(image_file.file, file_object)
        image_path = f"/static/uploads/{filename}"

    closed_date = datetime.now().strftime("%Y-%m-%d") if status == "Kapatıldı" else None

    cursor.execute("""
    INSERT INTO vulnerabilities (
        record_no, title, severity, cvss_score, cvss_vector, department,
        assignee_name, assignee_email, assignee_user_id, status, due_date, closed_date,
        created_at, updated_at, tool_source, target_host, target_port,
        target_os, description, threat_assessment, remediation, image_path,
        cve_id, notes
    ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
    """, (
        record_no, title, severity, cvss_score, cvss_vector, department,
        assignee_name, assignee_email, assignee_user_id, status, due_date, closed_date,
        now_str, now_str, tool_source, target_host, target_port,
        target_os, description, threat_assessment, remediation, image_path,
        cve_id, notes
    ))

    vuln_id = cursor.lastrowid

    # Record creation in timeline with user reference
    cursor.execute("""
    INSERT INTO responses (vuln_id, user_id, author_name, action_type, message, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        vuln_id,
        current_user["id"],
        current_user["full_name"],
        "Kayıt Açıldı",
        f"Kayıt {current_user['full_name']} tarafından oluşturuldu ve {assignee_name} ({department}) üzerine atandı. Termin: {due_date}",
        now_str
    ))

    conn.commit()

    if send_email_now:
        cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
        vuln_row = dict(cursor.fetchone())
        base_url = str(request.base_url).rstrip("/")
        notify_assignee_about_vulnerability(vuln_row, base_url, sender_user_id=current_user["id"])

    conn.close()
    return RedirectResponse(url=f"/vulnerabilities/{vuln_id}?msg=created", status_code=303)


@router.get("/{vuln_id}", response_class=HTMLResponse)
async def vulnerability_detail(request: Request, vuln_id: int, msg: Optional[str] = None):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url=f"/login?next={request.url.path}", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Zaafiyet kaydı bulunamadı")

    vuln = dict(row)

    # Responses / history with author role/department if available
    cursor.execute("""
        SELECT r.*, u.role as author_role, u.department as author_department
        FROM responses r
        LEFT JOIN users u ON r.user_id = u.id
        WHERE r.vuln_id = ?
        ORDER BY r.id DESC
    """, (vuln_id,))
    responses = [dict(r) for r in cursor.fetchall()]

    # Email logs for this vuln
    cursor.execute("SELECT * FROM email_logs WHERE vuln_id = ? ORDER BY id DESC", (vuln_id,))
    email_logs = [dict(e) for e in cursor.fetchall()]

    conn.close()

    today_str = datetime.now().strftime("%Y-%m-%d")
    is_overdue = (vuln["due_date"] < today_str and vuln["status"] not in ["Kapatıldı", "Yanlış Pozitif"]) if vuln["due_date"] else False

    # Check if current user can claim
    is_assigned_to_me = (vuln.get("assignee_user_id") == current_user["id"] or vuln.get("assignee_email") == current_user["email"])

    return templates.TemplateResponse(request=request, name="vulnerability_detail.html", context={
        "page_title": f"{vuln['record_no']} - {vuln['title']}",
        "current_user": current_user,
        "vuln": vuln,
        "responses": responses,
        "email_logs": email_logs,
        "is_overdue": is_overdue,
        "is_assigned_to_me": is_assigned_to_me,
        "today": today_str,
        "msg": msg
    })


@router.post("/{vuln_id}/claim")
async def claim_vulnerability(request: Request, vuln_id: int):
    """
    Worker self-assignment: 'Bu açığı ben hallediyorum'.
    """
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Zaafiyet bulunamadı")
    vuln = dict(row)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # If status was 'Açık', change to 'İnceleniyor'
    new_status = "İnceleniyor" if vuln["status"] == "Açık" else vuln["status"]

    cursor.execute("""
        UPDATE vulnerabilities SET
            assignee_user_id = ?,
            assignee_name = ?,
            assignee_email = ?,
            department = COALESCE(NULLIF(department, ''), ?),
            status = ?,
            updated_at = ?
        WHERE id = ?
    """, (
        current_user["id"],
        current_user["full_name"],
        current_user["email"],
        current_user.get("department", "Sistem Yönetimi"),
        new_status,
        now_str,
        vuln_id
    ))

    # Log action to response history
    cursor.execute("""
        INSERT INTO responses (vuln_id, user_id, author_name, action_type, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        vuln_id,
        current_user["id"],
        current_user["full_name"],
        "Zaafiyet Üstlenildi",
        f"Çalışan ({current_user['full_name']} - {current_user.get('department', '')}) bu zaafiyeti üzerine aldı: 'Bu açığı ben hallediyorum, inceleme ve çözüm süreci başlatıldı.'",
        now_str
    ))

    conn.commit()
    conn.close()

    return RedirectResponse(url=f"/vulnerabilities/{vuln_id}?msg=claimed", status_code=303)


@router.get("/{vuln_id}/edit", response_class=HTMLResponse)
async def edit_vulnerability_form(request: Request, vuln_id: int):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url=f"/login?next={request.url.path}", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Zaafiyet bulunamadı")
    vuln = dict(row)

    cursor.execute("SELECT DISTINCT department FROM vulnerabilities WHERE department != '' ORDER BY department")
    departments = [r[0] for r in cursor.fetchall()]

    cursor.execute("SELECT id, full_name, email, department FROM users WHERE is_active = 1 ORDER BY full_name")
    system_users = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return templates.TemplateResponse(request=request, name="vulnerability_form.html", context={
        "page_title": f"Düzenle: {vuln['record_no']}",
        "current_user": current_user,
        "vuln": vuln,
        "departments": departments,
        "system_users": system_users,
        "today": datetime.now().strftime("%Y-%m-%d")
    })


@router.post("/{vuln_id}/edit")
async def update_vulnerability(
    request: Request,
    vuln_id: int,
    title: str = Form(...),
    cvss_score: float = Form(0.0),
    cvss_vector: str = Form(""),
    department: str = Form(...),
    assignee_name: str = Form(...),
    assignee_email: str = Form(...),
    assignee_user_id: Optional[int] = Form(None),
    status: str = Form(...),
    due_date: str = Form(...),
    tool_source: str = Form(...),
    target_host: str = Form(...),
    target_port: str = Form(""),
    target_os: str = Form(""),
    description: str = Form(...),
    threat_assessment: str = Form(...),
    remediation: str = Form(...),
    cve_id: str = Form(""),
    notes: str = Form(""),
    image_file: Optional[UploadFile] = File(None)
):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT image_path, status, closed_date FROM vulnerabilities WHERE id = ?", (vuln_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Zaafiyet bulunamadı")

    image_path = existing["image_path"]
    if image_file and image_file.filename:
        filename = f"VULN_{vuln_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{image_file.filename}"
        file_location = os.path.join(UPLOAD_DIR, filename)
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(image_file.file, file_object)
        image_path = f"/static/uploads/{filename}"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity = calculate_severity_from_cvss(cvss_score)

    closed_date = existing["closed_date"]
    if status == "Kapatıldı" and not closed_date:
        closed_date = datetime.now().strftime("%Y-%m-%d")
    elif status != "Kapatıldı":
        closed_date = None

    cursor.execute("""
    UPDATE vulnerabilities SET
        title = ?, severity = ?, cvss_score = ?, cvss_vector = ?, department = ?,
        assignee_name = ?, assignee_email = ?, assignee_user_id = ?, status = ?,
        due_date = ?, closed_date = ?, updated_at = ?, tool_source = ?,
        target_host = ?, target_port = ?, target_os = ?, description = ?,
        threat_assessment = ?, remediation = ?, image_path = ?, cve_id = ?, notes = ?
    WHERE id = ?
    """, (
        title, severity, cvss_score, cvss_vector, department,
        assignee_name, assignee_email, assignee_user_id, status,
        due_date, closed_date, now_str, tool_source,
        target_host, target_port, target_os, description,
        threat_assessment, remediation, image_path, cve_id, notes, vuln_id
    ))

    if existing["status"] != status:
        cursor.execute("""
        INSERT INTO responses (vuln_id, user_id, author_name, action_type, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            vuln_id,
            current_user["id"],
            current_user["full_name"],
            "Durum Güncellendi",
            f"Zaafiyet durumu '{existing['status']}' -> '{status}' olarak güncellendi.",
            now_str
        ))

    conn.commit()
    conn.close()

    return RedirectResponse(url=f"/vulnerabilities/{vuln_id}?msg=updated", status_code=303)


@router.post("/{vuln_id}/response")
async def add_vulnerability_response(
    request: Request,
    vuln_id: int,
    action_type: str = Form(...),
    message: str = Form(...),
    new_status: Optional[str] = Form(None),
    response_file: Optional[UploadFile] = File(None)
):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    attachment_path = ""
    if response_file and response_file.filename:
        filename = f"RESP_{vuln_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{response_file.filename}"
        file_location = os.path.join(UPLOAD_DIR, filename)
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(response_file.file, file_object)
        attachment_path = f"/static/uploads/{filename}"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
    INSERT INTO responses (vuln_id, user_id, author_name, action_type, message, attachment_path, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (vuln_id, current_user["id"], current_user["full_name"], action_type, message, attachment_path, now_str))

    if new_status:
        closed_date = datetime.now().strftime("%Y-%m-%d") if new_status == "Kapatıldı" else None
        cursor.execute("""
        UPDATE vulnerabilities 
        SET status = ?, closed_date = ?, updated_at = ?
        WHERE id = ?
        """, (new_status, closed_date, now_str, vuln_id))

    conn.commit()
    conn.close()

    return RedirectResponse(url=f"/vulnerabilities/{vuln_id}?msg=response_added", status_code=303)


@router.post("/{vuln_id}/send-email")
async def trigger_email_notification(
    request: Request,
    vuln_id: int,
    email_type: str = Form("assignment")
):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Zaafiyet bulunamadı")

    vuln = dict(row)
    base_url = str(request.base_url).rstrip("/")

    if email_type == "sla_reminder":
        success, msg = notify_sla_reminder(vuln, base_url, sender_user_id=current_user["id"])
        action_msg = "Termin hatırlatma e-postası gönderildi."
    else:
        success, msg = notify_assignee_about_vulnerability(vuln, base_url, sender_user_id=current_user["id"])
        action_msg = "Zaafiyet atama e-postası gönderildi."

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO responses (vuln_id, user_id, author_name, action_type, message, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        vuln_id,
        current_user["id"],
        current_user["full_name"],
        "E-Posta Bildirimi",
        f"{action_msg} Alıcı: {vuln['assignee_name']} ({vuln['assignee_email']}). Sonuç: {msg}",
        now_str
    ))

    conn.commit()
    conn.close()

    return RedirectResponse(url=f"/vulnerabilities/{vuln_id}?msg=email_sent", status_code=303)


@router.post("/{vuln_id}/delete")
async def delete_vulnerability(request: Request, vuln_id: int):
    current_user = await get_current_user(request)
    if not current_user or current_user["role"] != "admin":
        return RedirectResponse(url="/vulnerabilities?error=Yalnizca+admin+silebilir", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
    cursor.execute("DELETE FROM responses WHERE vuln_id = ?", (vuln_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/vulnerabilities?msg=deleted", status_code=303)
