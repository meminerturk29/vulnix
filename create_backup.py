import os
import shutil
import zipfile
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUPS_DIR = os.path.join(ROOT_DIR, "backups")
os.makedirs(BACKUPS_DIR, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
backup_name = f"vms_shield_v2.0_stable_{timestamp}"
backup_folder = os.path.join(BACKUPS_DIR, backup_name)
zip_filename = os.path.join(BACKUPS_DIR, f"{backup_name}.zip")
latest_zip = os.path.join(BACKUPS_DIR, "vms_shield_v2.0_stable_latest.zip")

EXCLUDE_DIRS = {"venv", ".venv", "__pycache__", ".git", "backups", "scratch"}
EXCLUDE_EXTS = {".pyc", ".pyo", ".pyd"}

print(f"[*] Stabil sürüm yedeği alınıyor...")
print(f"[*] Kaynak Dizin: {ROOT_DIR}")
print(f"[*] Hedef Arşiv: {zip_filename}")

# Create Zip Archive
with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(ROOT_DIR):
        # Exclude directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for file in files:
            if any(file.endswith(ext) for ext in EXCLUDE_EXTS):
                continue
            if file in {"check_db.py", "find_keywords.py", "test_openvas_live.py", "test_timer_and_credentials.py"}:
                continue
            abs_path = os.path.join(root, file)
            rel_path = os.path.relpath(abs_path, ROOT_DIR)
            zipf.write(abs_path, rel_path)

# Also create a copy as latest.zip for easy access
shutil.copy2(zip_filename, latest_zip)

# Also create an uncompressed folder backup for immediate code diff / inspection
if os.path.exists(backup_folder):
    shutil.rmtree(backup_folder)
os.makedirs(backup_folder, exist_ok=True)

with zipfile.ZipFile(zip_filename, 'r') as zipf:
    zipf.extractall(backup_folder)

size_mb = os.path.getsize(zip_filename) / (1024 * 1024)
print(f"[+] Yedek başarıyla tamamlandı!")
print(f"[+] Zip Boyutu: {size_mb:.2f} MB")
print(f"[+] Zip Dosyası: {zip_filename}")
print(f"[+] Sabit Kopya: {latest_zip}")
print(f"[+] Klasör Kopyası: {backup_folder}")
