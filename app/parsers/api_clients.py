import requests
import xml.etree.ElementTree as ET
import urllib3
from typing import List, Dict, Any, Tuple
from app.parsers.nessus_parser import parse_nessus_xml
from app.parsers.openvas_parser import parse_openvas_xml

# Suppress insecure SSL warnings for local pentest appliances
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OpenVASApiClient:
    def __init__(self, base_url: str = "https://10.10.1.12", username: str = "admin", password: str = "", verify_ssl: bool = False):
        self.base_url = (base_url or "https://10.10.1.12").rstrip("/")
        self.username = username or "admin"
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.token = ""

    def test_connection(self) -> Tuple[bool, str]:
        if not self.base_url:
            return False, "OpenVAS / Greenbone sunucu adresi belirtilmedi."
        try:
            resp = self.session.get(f"{self.base_url}/config.js", timeout=5)
            if resp.status_code == 200:
                return True, f"OpenVAS (Greenbone OS) sunucusuna ({self.base_url}) başarıyla erişildi! Port 443 aktif."
            # Fallback check root
            resp_root = self.session.get(self.base_url, timeout=5)
            if resp_root.status_code in [200, 301, 302, 401]:
                return True, f"OpenVAS sunucusuna ({self.base_url}) erişim sağlandı (HTTP {resp_root.status_code})."
            return False, f"Sunucu HTTP {resp.status_code} döndürdü."
        except requests.exceptions.ConnectTimeout:
            return False, f"OpenVAS sunucusuna ({self.base_url}) bağlanırken zaman aşımı oluştu. Cihazın IP adresini ve ağ bağlantınızı kontrol ediniz."
        except requests.exceptions.ConnectionError:
            return False, f"OpenVAS sunucusuna bağlanılamadı ({self.base_url}). Sunucu çalışıyor mu?"
        except Exception as e:
            return False, f"Bağlantı hatası: {str(e)}"

    def login(self, username: str = None, password: str = None) -> Tuple[bool, str]:
        user = username or self.username
        pw = password if password is not None else self.password
        try:
            url = f"{self.base_url}/login"
            resp = self.session.post(url, data={"login": user, "password": pw}, timeout=10)
            if "<envelope>" in resp.text:
                root = ET.fromstring(resp.text)
                token_el = root.find("token")
                msg_el = root.find(".//message")
                msg = msg_el.text if msg_el is not None else ""

                if token_el is not None and token_el.text:
                    self.token = token_el.text
                    return True, "OpenVAS oturum açma başarılı (Token alındı)."
                else:
                    return False, f"Giriş başarısız: {msg or 'Kullanıcı adı veya parola hatalı.'}"
            elif resp.status_code == 200:
                return True, "Giriş başarılı!"
            else:
                return False, f"HTTP {resp.status_code} yanıtı: {resp.text[:150]}"
        except Exception as e:
            return False, f"Oturum açma hatası: {str(e)}"

    def fetch_live_vulnerabilities(self, username: str = None, password: str = None, include_logs: bool = False) -> Tuple[bool, List[Dict[str, Any]], str]:
        """
        Connects to OpenVAS, queries tasks and results, and returns parsed vulnerabilities.
        """
        # Test connection first
        ok, msg = self.test_connection()
        if not ok:
            return False, [], msg

        # Try to authenticate if credentials provided
        if password or self.password:
            login_ok, login_msg = self.login(username, password)
            if not login_ok:
                return False, [], login_msg

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            # 1. Primary method for Greenbone OS 25 (GSAD 27.x): GET /gmp?cmd=get_results&details=1&filter=rows=-1&token=...
            params = {
                "token": self.token,
                "cmd": "get_results",
                "details": "1",
                "filter": "rows=-1"
            }
            resp = self.session.get(f"{self.base_url}/gmp", params=params, timeout=25)

            # 2. Fallback to POST /gmp with form data if GET not 200
            if resp.status_code != 200 or "<get_results" not in resp.text:
                resp = self.session.post(f"{self.base_url}/gmp", data={"token": self.token, "cmd": "get_results", "details": "1", "filter": "rows=-1"}, timeout=25)

            # 3. Check for unauthorized / token missing
            if resp.status_code == 401 or "Token missing" in resp.text:
                return False, [], "OpenVAS oturum hatası: Lütfen OpenVAS kullanıcı adı ve parolanızı kontrol ediniz."

            if "<get_results" in resp.text:
                vulns = parse_openvas_xml(resp.text, include_logs=include_logs)
                if vulns:
                    return True, vulns, f"OpenVAS üzerinden {len(vulns)} adet canlı zaafiyet başarıyla çekildi."
                else:
                    return True, [], "OpenVAS sunucusuna bağlanıldı. Taramada kritik/yüksek/orta seviyeli aktif bulgu tespit edilmedi."

            # Fallback check get_tasks
            resp_tasks = self.session.get(f"{self.base_url}/gmp", params={"token": self.token, "cmd": "get_tasks"}, timeout=15)
            if "<get_tasks" in resp_tasks.text:
                return True, [], f"OpenVAS ({self.base_url}) sunucusuna bağlanıldı. Henüz tamamlanmış zaafiyetli bir tarama görevi bulunmuyor."

            return False, [], f"OpenVAS sunucusu beklenmeyen yanıt döndürdü (HTTP {resp.status_code})."
        except Exception as e:
            return False, [], f"Veri çekme hatası: {str(e)}"


class NessusApiClient:
    def __init__(self, base_url: str = "", access_key: str = "", secret_key: str = "", verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.verify_ssl = verify_ssl

    def get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.access_key and self.secret_key:
            headers["X-ApiKeys"] = f"accessKey={self.access_key}; secretKey={self.secret_key};"
        return headers

    def test_connection(self) -> Tuple[bool, str]:
        if not self.base_url:
            return False, "Nessus sunucu URL adresi belirtilmedi."
        try:
            url = f"{self.base_url}/server/status"
            resp = requests.get(url, headers=self.get_headers(), verify=self.verify_ssl, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return True, f"Nessus bağlantısı başarılı! Sunucu Durumu: {data.get('status', 'Ready')}"
            else:
                return False, f"Nessus API yanıt verdi ancak durum kodu {resp.status_code}: {resp.text[:200]}"
        except requests.exceptions.ConnectionError:
            return False, f"Nessus sunucusuna bağlanılamadı ({self.base_url}). Sunucu çalışıyor mu?"
        except Exception as e:
            return False, f"Hata: {str(e)}"
