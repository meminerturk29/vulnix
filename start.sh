#!/usr/bin/env bash
# ==============================================================================
# VMS SHIELD - Kurumsal Zaafiyet Yönetim Sistemi Başlatıcı (Linux / Kali / Ubuntu)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "  VULNIX - Kurumsal Zaafiyet Yönetim Sistemi"
echo "  Kali Linux & Ubuntu & Debian Destekli"
echo "=========================================================="

if ! command -v python3 &> /dev/null; then
    echo "[!] Hata: python3 bulunamadı."
    echo "[!] Lütfen 'sudo apt update && sudo apt install -y python3 python3-pip python3-venv' çalıştırın."
    exit 1
fi

# Sanal ortam kontrolü (Opsiyonel / İsteğe bağlı)
if [ ! -d "venv" ]; then
    echo "[*] Sanal ortam (venv) hazırlanıyor..."
    python3 -m venv venv 2>/dev/null || echo "[*] Sistem python3 ortamı kullanılacak."
fi

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    PIP="pip"
    PYTHON="python"
else
    PIP="python3 -m pip"
    PYTHON="python3"
fi

echo "[*] Bağımlılıklar kontrol ediliyor..."
$PIP install -r requirements.txt --quiet

echo "[+] VMS Shield başlatılıyor..."
exec $PYTHON run.py "$@"
