from fastapi import APIRouter, Request, Form, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from app.templates_config import templates
from app.database import get_db_connection, generate_next_record_no, clear_all_vulnerabilities
from app.auth import get_current_user
from app.parsers.openvas_parser import parse_openvas_xml, parse_generic_json
from app.parsers.nessus_parser import parse_nessus_xml
from app.parsers.api_clients import OpenVASApiClient, NessusApiClient
from datetime import datetime
import os

router = APIRouter(prefix="/import")
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "samples")


@router.get("", response_class=HTMLResponse)
async def import_page(request: Request, msg: str = None, count: int = 0, error: str = None):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login?next=/import", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM system_settings")
    settings = {row["key"]: row["value"] for row in cursor.fetchall()}
    conn.close()

    return templates.TemplateResponse(request=request, name="import.html", context={
        "page_title": "OpenVAS / Greenbone Tarama Senkronizasyonu",
        "current_user": current_user,
        "settings": settings,
        "msg": msg,
        "count": count,
        "error": error
    })


def insert_imported_vulns(vulns_list: list, author_name: str = "OpenVAS Otomasyonu", user_id: int = None) -> tuple:
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    imported_count = 0
    existing_count = 0

    for v in vulns_list:
        # Check if identical open vulnerability already exists
        cursor.execute("""
            SELECT id FROM vulnerabilities 
            WHERE title = ? AND target_host = ? AND target_port = ? AND status != 'Kapatıldı'
        """, (v["title"], v["target_host"], v.get("target_port", "")))
        if cursor.fetchone():
            existing_count += 1
            continue

        record_no = generate_next_record_no(conn)
        cursor.execute("""
        INSERT INTO vulnerabilities (
            record_no, title, severity, cvss_score, cvss_vector, department,
            assignee_name, assignee_email, status, due_date, closed_date,
            created_at, updated_at, tool_source, target_host, target_port,
            target_os, description, threat_assessment, remediation, image_path,
            cve_id, notes
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """, (
            record_no, v["title"], v["severity"], v["cvss_score"], v.get("cvss_vector", ""),
            v["department"], v["assignee_name"], v["assignee_email"], v.get("status", "Açık"),
            v["due_date"], None, now_str, now_str, v["tool_source"], v["target_host"],
            v.get("target_port", ""), v.get("target_os", ""), v["description"],
            v["threat_assessment"], v["remediation"], "", v.get("cve_id", ""), v.get("notes", "")
        ))

        vuln_id = cursor.lastrowid
        cursor.execute("""
        INSERT INTO responses (vuln_id, user_id, author_name, action_type, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            vuln_id,
            user_id,
            author_name,
            "Kayıt Açıldı",
            f"Zaafiyet {v['tool_source']} taramasından içe aktarıldı. Atanan birim: {v['department']} ({v['assignee_name']}). Termin: {v['due_date']}.",
            now_str
        ))
        imported_count += 1

    conn.commit()
    conn.close()
    return imported_count, existing_count


@router.post("/openvas-sync")
async def live_openvas_sync(
    request: Request,
    server_url: str = Form("https://10.10.1.12"),
    username: str = Form("admin"),
    password: str = Form(""),
    include_logs: bool = Form(False)
):
    """
    Connects directly to OpenVAS (e.g. at 10.10.1.12 on NAT) and pulls live findings.
    Even if 0 findings are present, it gracefully updates status.
    """
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    # Save credentials into system_settings if given
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_url'", (server_url.strip(),))
    cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_username'", (username.strip(),))
    if password.strip():
        cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_password'", (password.strip(),))
    else:
        # Load saved password if empty
        cursor.execute("SELECT value FROM system_settings WHERE key = 'openvas_password'")
        row = cursor.fetchone()
        if row and row["value"]:
            password = row["value"]
    conn.commit()
    conn.close()

    from app.scheduler import scheduler
    ok, summary, new_count, total_findings = scheduler.perform_sync(trigger_source=f"Senkronizasyon ({current_user['full_name']})")

    if not ok:
        return RedirectResponse(url=f"/import?error={summary}", status_code=303)

    return RedirectResponse(url=f"/import?msg={summary}&count={new_count}", status_code=303)


@router.post("/save-timer-settings")
async def save_timer_settings(
    request: Request,
    server_url: str = Form("https://10.10.1.12"),
    username: str = Form("admin"),
    password: str = Form(""),
    auto_sync: str = Form("0"),
    sync_interval: str = Form("15"),
    include_logs: str = Form("0")
):
    """
    Saves the timer configuration and credentials permanently.
    """
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_url'", (server_url.strip(),))
    cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_username'", (username.strip(),))
    if password.strip():
        cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_password'", (password.strip(),))
    
    cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_auto_sync'", ("1" if auto_sync == "1" else "0",))
    cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_sync_interval'", (str(int(sync_interval) if sync_interval.isdigit() else 15),))
    cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_include_logs'", ("1" if include_logs == "1" else "0",))
    conn.commit()
    conn.close()

    from app.scheduler import scheduler
    scheduler.wake_now()

    msg = "Zamanlayıcı ve OpenVAS ayarları başarıyla kaydedildi."
    if auto_sync == "1":
        msg += f" Otomatik kontrol her {sync_interval} dakikada bir çalışacak."
    else:
        msg += " Otomatik zamanlayıcı duraklatıldı."

    return RedirectResponse(url=f"/import?msg={msg}", status_code=303)


@router.post("/trigger-sync")
async def trigger_sync_now(request: Request):
    """
    One-click immediate sync using permanently stored credentials.
    No need to type password ever again!
    """
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    from app.scheduler import scheduler
    ok, summary, new_count, total = scheduler.perform_sync(trigger_source=f"Hızlı Senkron ({current_user['full_name']})")
    
    if ok:
        return RedirectResponse(url=f"/import?msg={summary}&count={new_count}", status_code=303)
    else:
        return RedirectResponse(url=f"/import?error={summary}", status_code=303)


@router.post("/clear-vulnerabilities")
async def clear_vulnerabilities_action(request: Request):
    """
    Purges all test/dummy vulnerabilities per user request.
    """
    current_user = await get_current_user(request)
    if not current_user or current_user["role"] != "admin":
        return RedirectResponse(url="/vulnerabilities?error=Yalnizca+admin+zaafiyetleri+temizleyebilir", status_code=303)

    clear_all_vulnerabilities()
    return RedirectResponse(url="/vulnerabilities?msg=cleared", status_code=303)


@router.post("/upload")
async def handle_file_upload(
    request: Request,
    tool_type: str = Form(...),
    scan_file: UploadFile = File(...)
):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    try:
        content_bytes = await scan_file.read()
        content_str = content_bytes.decode("utf-8", errors="replace")

        if tool_type == "openvas":
            vulns = parse_openvas_xml(content_str)
        elif tool_type == "nessus":
            vulns = parse_nessus_xml(content_str)
        elif tool_type == "json":
            vulns = parse_generic_json(content_str)
        else:
            raise HTTPException(status_code=400, detail="Geçersiz araç türü")

        if not vulns:
            return RedirectResponse(url="/import?error=Dosyada+uygun+zaafiyet+bulunamadi", status_code=303)

        new_count, exist_count = insert_imported_vulns(vulns, author_name=f"OpenVAS Raporu ({current_user['full_name']})", user_id=current_user["id"])
        return RedirectResponse(url=f"/import?msg=success&count={new_count}", status_code=303)

    except Exception as e:
        return RedirectResponse(url=f"/import?error={str(e)}", status_code=303)


@router.post("/test-api")
async def test_api_connection(
    request: Request,
    api_type: str = Form(...),
    server_url: str = Form(...),
    username: str = Form(""),
    password: str = Form(""),
    access_key: str = Form(""),
    secret_key: str = Form("")
):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if api_type == "openvas":
        client = OpenVASApiClient(server_url, username, password)
        ok, msg = client.test_connection()
    else:
        client = NessusApiClient(server_url, access_key, secret_key)
        ok, msg = client.test_connection()

    url_msg = f"?msg={msg}" if ok else f"?error={msg}"
    return RedirectResponse(url=f"/import{url_msg}", status_code=303)
