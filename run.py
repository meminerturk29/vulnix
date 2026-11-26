#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import uvicorn
import sys
import os
import argparse
from app.database import init_db

BANNER = r"""
 __      ___    _ _      _   _ _______   __
 \ \    / / |  | | |    | \ | |_   _\ \ / /
  \ \  / /| |  | | |    |  \| | | |  \ V / 
   \ \/ / | |  | | |    | . ` | | |   > <  
    \  /  | |__| | |____| |\  |_| |_ / . \ 
     \/    \____/|______|_| \_|_____/_/ \_\
                                           
       VULNIX - Kurumsal Zaafiyet Yönetim Sistemi
       OpenVAS GSAD 27 API & Otomatik Zamanlayıcı Motoru
       Kali Linux & Windows Uyumlu
"""

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Management System (VMS) Başlatıcı")
    parser.add_argument("--host", default="0.0.0.0", help="Dinlenecek Host IP (varsayılan: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Çalışma Portu (varsayılan: 8000)")
    parser.add_argument("--reload", action="store_true", default=True, help="Otomatik yenileme (Geliştirici Modu)")

    args = parser.parse_args()

    print(BANNER)
    print("[*] Veritabanı ve tablolar kontrol ediliyor...")
    init_db()
    print("[+] Veritabanı hazır!")
    print(f"[*] Sunucu başlatılıyor -> http://127.0.0.1:{args.port}")
    print(f"[*] Ağdan erişim adresi -> http://{args.host}:{args.port}")
    print("[*] Durdurmak için Ctrl+C tuşlarına basınız.\n")

    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)

if __name__ == "__main__":
    main()
