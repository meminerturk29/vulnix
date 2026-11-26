from fastapi import APIRouter, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from app.templates_config import templates
from app.auth import (
    authenticate_user, create_session, delete_session,
    get_current_user, SESSION_COOKIE_NAME, SESSION_DURATION_HOURS
)
from app.security import (
    check_login_rate_limit, record_login_failure, record_login_success
)
import os
import asyncio

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None, msg: str = None, next: str = "/"):
    current_user = await get_current_user(request)
    if current_user:
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(request=request, name="login.html", context={
        "page_title": "Sign In",
        "error": error,
        "msg": "You have been successfully signed out." if msg == "logged_out" else msg,
        "next": next
    })


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/")
):
    client_ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "127.0.0.1")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # 1. Brute-Force Rate Limiting Check
    allowed, limit_msg = check_login_rate_limit(client_ip, username)
    if not allowed:
        return templates.TemplateResponse(request=request, name="login.html", context={
            "page_title": "Sign In",
            "error": limit_msg,
            "next": next,
            "entered_username": username
        }, status_code=429)

    # 2. Authenticate credentials
    user = authenticate_user(username.strip(), password)
    if not user:
        record_login_failure(client_ip, username)
        await asyncio.sleep(0.2)
        return templates.TemplateResponse(request=request, name="login.html", context={
            "page_title": "Sign In",
            "error": "Invalid username or password! Please try again.",
            "next": next,
            "entered_username": username
        }, status_code=400)

    # 3. Successful authentication: clear failure count
    record_login_success(client_ip, username)

    session_id = create_session(user["id"])
    redirect_url = next if next and next.startswith("/") else "/"
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_DURATION_HOURS * 3600,
        httponly=True,
        samesite="lax"
    )
    return response


@router.get("/logout")
@router.post("/logout")
async def logout(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        delete_session(session_id)
    response = RedirectResponse(url="/login?msg=logged_out", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response
