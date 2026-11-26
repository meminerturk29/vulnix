from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from app.templates_config import templates
from app.database import get_db_connection, DB_PATH
from app.auth import get_current_user
from app.email_service import send_email
import os
import platform
import sys

router = APIRouter(prefix="/settings")


@router.get("", response_class=HTMLResponse)
async def settings_view(request: Request, msg: str = None, error: str = None):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login?next=/settings", status_code=303)
    if current_user["role"] != "admin":
        return RedirectResponse(url="/?error=Sistem+ayarlarina+yalnizca+yonetici+erisebilir", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT key, value FROM system_settings")
    settings = {row["key"]: row["value"] for row in cursor.fetchall()}

    cursor.execute("""
        SELECT e.*, u.full_name as sender_name
        FROM email_logs e
        LEFT JOIN users u ON e.sent_by_user_id = u.id
        ORDER BY e.id DESC LIMIT 50
    """)
    email_logs = [dict(r) for r in cursor.fetchall()]

    conn.close()

    db_size_kb = round(os.path.getsize(DB_PATH) / 1024, 1) if os.path.exists(DB_PATH) else 0

    system_info = {
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python_version": sys.version.split(" ")[0],
        "db_size": f"{db_size_kb} KB",
        "db_path": DB_PATH
    }

    return templates.TemplateResponse(request=request, name="settings.html", context={
        "page_title": "System & SMTP Settings",
        "current_user": current_user,
        "settings": settings,
        "email_logs": email_logs,
        "system_info": system_info,
        "msg": msg,
        "error": error
    })


@router.post("/save")
async def save_settings(
    request: Request,
    company_name: str = Form(""),
    smtp_host: str = Form(""),
    smtp_port: str = Form("587"),
    smtp_user: str = Form(""),
    smtp_pass: str = Form(""),
    smtp_from: str = Form(""),
    smtp_tls: str = Form("0"),
    openvas_url: str = Form(""),
    openvas_username: str = Form(""),
    openvas_password: str = Form(""),
    nessus_url: str = Form(""),
    nessus_access_key: str = Form(""),
    nessus_secret_key: str = Form("")
):
    current_user = await get_current_user(request)
    if not current_user or current_user["role"] != "admin":
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    configs = {
        "company_name": company_name.strip(),
        "smtp_host": smtp_host.strip(),
        "smtp_port": smtp_port.strip(),
        "smtp_user": smtp_user.strip(),
        "smtp_pass": smtp_pass.strip(),
        "smtp_from": smtp_from.strip(),
        "smtp_tls": smtp_tls,
        "openvas_url": openvas_url.strip(),
        "openvas_username": openvas_username.strip(),
        "openvas_password": openvas_password.strip(),
        "nessus_url": nessus_url.strip(),
        "nessus_access_key": nessus_access_key.strip(),
        "nessus_secret_key": nessus_secret_key.strip()
    }

    for key, val in configs.items():
        cursor.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", (key, val))

    conn.commit()
    conn.close()

    return RedirectResponse(url="/settings?msg=Ayarlar+basariyla+kaydedildi", status_code=303)


@router.post("/test-email")
async def test_email_send(
    request: Request,
    test_email_addr: str = Form(...)
):
    current_user = await get_current_user(request)
    if not current_user or current_user["role"] != "admin":
        return RedirectResponse(url="/login", status_code=303)

    subject = "VMS Test E-Postası (Gerçek SMTP Doğrulama)"
    html = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 24px; border: 1px solid #0284c7; border-radius: 12px; max-width: 600px; background: #ffffff;">
        <h2 style="color: #0284c7; margin-top: 0;">Kurumsal Zaafiyet Yönetim Sistemi E-Posta Testi</h2>
        <p>Tebrikler! Zaafiyet Yönetim Sistemi (VMS) SMTP mail sunucu entegrasyonu başarıyla doğrulanmıştır.</p>
        <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 16px 0;">
        <p><strong>Alıcı Test Adresi:</strong> {test_email_addr}</p>
        <p><strong>Testi Gönderen Yönetici:</strong> {current_user['full_name']} ({current_user['email']})</p>
        <p><strong>Zaman:</strong> {os.environ.get('USERNAME', 'Sistem')}</p>
    </div>
    """
    ok, msg = send_email(test_email_addr, "Test Kullanıcısı", subject, html, sender_user_id=current_user["id"])
    if ok:
        return RedirectResponse(url=f"/settings?msg={msg}", status_code=303)
    else:
        return RedirectResponse(url=f"/settings?error={msg}", status_code=303)
