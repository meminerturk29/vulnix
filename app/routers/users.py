from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.auth import get_current_user, hash_password
from app.database import get_db_connection
import os
from datetime import datetime

router = APIRouter(prefix="/users")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"))


@router.get("", response_class=HTMLResponse)
async def list_users(request: Request, msg: str = None, error: str = None):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login?next=/users", status_code=303)
    if current_user["role"] != "admin":
        return RedirectResponse(url="/?error=Bu+sayfaya+yalnizca+yonetici+erisebilir", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get users with counts of assigned vulnerabilities and responses they made
    cursor.execute("""
        SELECT u.*,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.assignee_user_id = u.id OR v.assignee_email = u.email) as assigned_count,
               (SELECT COUNT(*) FROM responses r WHERE r.user_id = u.id) as actions_count
        FROM users u
        ORDER BY u.role DESC, u.full_name ASC
    """)
    users = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT DISTINCT department FROM users WHERE department != ''")
    departments = [r[0] for r in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(request=request, name="users_list.html", context={
        "page_title": "Kullanıcı ve Ekip Yönetimi",
        "current_user": current_user,
        "users": users,
        "departments": departments,
        "msg": msg,
        "error": error
    })


@router.post("/new")
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    email: str = Form(...),
    role: str = Form("user"),
    department: str = Form("")
):
    current_user = await get_current_user(request)
    if not current_user or current_user["role"] != "admin":
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if username or email already exists
    cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username.strip().lower(), email.strip().lower()))
    if cursor.fetchone():
        conn.close()
        return RedirectResponse(url="/users?error=Bu+kullanici+adi+veya+eposta+zaten+kayitli", status_code=303)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pw_hash = hash_password(password)

    cursor.execute("""
        INSERT INTO users (username, password_hash, full_name, email, role, department, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
    """, (username.strip().lower(), pw_hash, full_name.strip(), email.strip().lower(), role, department.strip(), now_str, now_str))

    conn.commit()
    conn.close()

    return RedirectResponse(url="/users?msg=Yeni+kullanici+basariyla+eklendi", status_code=303)


@router.post("/{user_id}/toggle-active")
async def toggle_user_active(request: Request, user_id: int):
    current_user = await get_current_user(request)
    if not current_user or current_user["role"] != "admin":
        return RedirectResponse(url="/login", status_code=303)

    if current_user["id"] == user_id:
        return RedirectResponse(url="/users?error=Kendi+hesabinizi+devre+disi+birakamazsiniz", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_active FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if row:
        new_status = 0 if row["is_active"] == 1 else 1
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?", (new_status, now_str, user_id))
        conn.commit()
    conn.close()

    return RedirectResponse(url="/users?msg=Kullanici+durumu+guncellendi", status_code=303)


@router.post("/{user_id}/reset-password")
async def reset_user_password(request: Request, user_id: int, new_password: str = Form(...)):
    current_user = await get_current_user(request)
    if not current_user or current_user["role"] != "admin":
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()
    pw_hash = hash_password(new_password)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", (pw_hash, now_str, user_id))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/users?msg=Parola+basariyla+degistirildi", status_code=303)


@router.post("/{user_id}/delete")
async def delete_user(request: Request, user_id: int):
    current_user = await get_current_user(request)
    if not current_user or current_user["role"] != "admin":
        return RedirectResponse(url="/login", status_code=303)

    if current_user["id"] == user_id:
        return RedirectResponse(url="/users?error=Kendi+hesabinizi+silemezsiniz", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/users?msg=Kullanici+sistemden+silindi", status_code=303)
