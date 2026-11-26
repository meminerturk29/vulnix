import asyncio
import logging
from datetime import datetime
from typing import Tuple, Dict, Any
from app.database import get_db_connection
from app.parsers.api_clients import OpenVASApiClient
from app.routers.imports import insert_imported_vulns

logger = logging.getLogger("vms.scheduler")
logging.basicConfig(level=logging.INFO)


class OpenVASScheduler:
    def __init__(self):
        self._task = None
        self._running = False
        self._wake_event = asyncio.Event()

    def get_settings(self) -> Dict[str, str]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM system_settings WHERE key LIKE 'openvas%'")
        settings = {row["key"]: row["value"] for row in cursor.fetchall()}
        conn.close()
        return settings

    def update_sync_status(self, status: str, findings_count: int = 0):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_last_sync'", (now_str,))
        cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_last_status'", (status,))
        cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'openvas_last_findings_count'", (str(findings_count),))
        conn.commit()
        conn.close()

    def perform_sync(self, trigger_source: str = "Zamanlayıcı") -> Tuple[bool, str, int, int]:
        """
        Executes a live sync against the OpenVAS host using stored credentials.
        Returns: (success, message, new_vuln_count, total_findings)
        """
        settings = self.get_settings()
        url = settings.get("openvas_url", "https://10.10.1.12")
        username = settings.get("openvas_username", "admin")
        password = settings.get("openvas_password", "admin")
        include_logs = settings.get("openvas_include_logs", "0") == "1"

        if not url or not username or not password:
            msg = "OpenVAS kimlik bilgileri eksik (URL, kullanıcı adı veya parola bulunamadı)."
            self.update_sync_status(f"Hata: {msg}")
            return False, msg, 0, 0

        logger.info(f"[OpenVAS Scheduler] Canlı tarama kontrol ediliyor: {url} ({username}) [Tetikleyici: {trigger_source}]")
        client = OpenVASApiClient(base_url=url, username=username, password=password)
        ok, vulns, msg = client.fetch_live_vulnerabilities(username=username, password=password, include_logs=include_logs)

        if not ok:
            logger.warning(f"[OpenVAS Scheduler] Bağlantı/sorgu hatası: {msg}")
            self.update_sync_status(f"Hata: {msg}")
            return False, msg, 0, 0

        total_findings = len(vulns)
        new_count = 0
        exist_count = 0

        if vulns:
            new_count, exist_count = insert_imported_vulns(
                vulns, 
                author_name=f"OpenVAS Otomasyonu ({trigger_source})"
            )
            if new_count > 0:
                summary = f"Başarılı: {total_findings} bulgu tarandı ({new_count} yeni zaafiyet sisteme eklendi)."
            else:
                summary = f"Başarılı: {total_findings} bulgunun tamamı ({exist_count} kayıt) zaten güncel."
        else:
            summary = "Başarılı: OpenVAS sunucusunda yeni/aktif risk bulgusu bulunmuyor."

        self.update_sync_status(summary, total_findings)
        logger.info(f"[OpenVAS Scheduler] {summary}")
        return True, summary, new_count, total_findings

    async def _run_loop(self):
        logger.info("[OpenVAS Scheduler] Otomatik zamanlayıcı arka plan görevi başlatıldı.")
        
        # Initial small sleep to let server boot up completely
        await asyncio.sleep(5)

        while self._running:
            try:
                settings = self.get_settings()
                is_enabled = settings.get("openvas_auto_sync", "1") == "1"
                try:
                    interval_minutes = int(settings.get("openvas_sync_interval", "15"))
                except ValueError:
                    interval_minutes = 15

                if is_enabled:
                    # Run sync in threadpool to avoid blocking async event loop
                    await asyncio.to_thread(self.perform_sync, "Periyodik Zamanlayıcı")

                # Wait for interval or until manually awakened
                wait_seconds = max(interval_minutes * 60, 30)
                self._wake_event.clear()
                try:
                    await asyncio.wait_for(self._wake_event.wait(), timeout=wait_seconds)
                except asyncio.TimeoutError:
                    pass

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[OpenVAS Scheduler] Beklenmeyen hata: {e}", exc_info=True)
                await asyncio.sleep(60)

        logger.info("[OpenVAS Scheduler] Arka plan zamanlayıcı döngüsü sonlandı.")

    def start(self):
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._run_loop())

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()

    def wake_now(self):
        """Signals the background loop to run immediately."""
        self._wake_event.set()


# Global singleton instance
scheduler = OpenVASScheduler()
