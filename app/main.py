from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from app.database import init_db
from app.scheduler import scheduler
from app.routers import auth, dashboard, vulnerabilities, imports, reports, settings, users
import os
import uvicorn

app = FastAPI(
    title="VULNIX - Kurumsal Zaafiyet Yönetim Sistemi",
    description="OpenVAS Destekli, Kullanıcı ve Rol Yetkilendirmeli Kurumsal Zaafiyet Yönetim Platformu",
    version="2.0.0"
)

# Static files setup
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "uploads"), exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "img"), exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Include Routers
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(vulnerabilities.router)
app.include_router(users.router)
app.include_router(imports.router)
app.include_router(reports.router)
app.include_router(settings.router)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.get("/set-lang/{lang}")
async def set_language(request: Request, lang: str):
    target_lang = "tr" if lang.lower() == "tr" else "en"
    referer = request.headers.get("referer", "/")
    # Avoid redirect loop if referer was /set-lang
    if "/set-lang" in referer:
        referer = "/"
    from fastapi.responses import RedirectResponse
    response = RedirectResponse(url=referer, status_code=303)
    response.set_cookie("vulnix_lang", target_lang, max_age=365 * 24 * 3600, samesite="lax")
    return response


@app.on_event("startup")
async def on_startup():
    init_db()
    scheduler.start()


@app.on_event("shutdown")
async def on_shutdown():
    scheduler.stop()


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
