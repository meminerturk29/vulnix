@echo off
chcp 65001 >nul
title VULNIX - Zaafiyet Yonetim Sistemi

echo ==========================================================
echo   VULNIX - Kurumsal Zaafiyet Yonetim Sistemi
echo   Windows 10 / 11 / Server Uyumlu
echo ==========================================================

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Hata: Python bulunamadi.
    echo [!] Lutfen python.org adresinden Python 3 yukleyip 'Add to PATH' secenegini isaretleyin.
    pause
    exit /b 1
)

if not exist "venv" (
    echo [*] Sanal ortam hazirlaniyor...
    python -m venv venv 2>nul
)

if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

echo [*] Bagimliliklar kontrol ediliyor...
pip install -r requirements.txt --quiet

echo [+] VMS Shield baslatiliyor...
python run.py %*
pause
