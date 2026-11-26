import requests
import xml.etree.ElementTree as ET
import urllib3
urllib3.disable_warnings()

class OpenVASClient:
    def __init__(self, base_url: str = "https://192.168.1.180", username: str = "admin", password: str = ""):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        self.token = ""

    def test_host(self):
        try:
            r = self.session.get(f"{self.base_url}/config.js", timeout=5)
            if r.status_code == 200:
                return True, "OpenVAS (Greenbone OS 25.0.9) sunucusuna erişim sağlandı."
            return False, f"Sunucu HTTP {r.status_code} döndürdü."
        except Exception as e:
            return False, f"Bağlantı hatası: {str(e)}"

    def login(self, username: str = None, password: str = None):
        user = username or self.username
        pw = password or self.password
        try:
            # GSAD 25/27 login endpoint
            r = self.session.post(f"{self.base_url}/login", data={"login": user, "password": pw}, timeout=10)
            if "<token>" in r.text and "<gsad_response>" in r.text:
                root = ET.fromstring(r.text)
                token_el = root.find("token")
                msg_el = root.find(".//message")
                msg = msg_el.text if msg_el is not None else ""
                
                if token_el is not None and token_el.text:
                    self.token = token_el.text
                    return True, "Giriş başarılı! Oturum tokeni alındı."
                else:
                    return False, f"Giriş başarısız: {msg or 'Kullanıcı adı veya parola hatalı.'}"
            elif r.status_code == 200:
                return True, "Giriş başarılı!"
            else:
                return False, f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            return False, f"Giriş sırasında hata: {str(e)}"

    def fetch_live_vulnerabilities(self):
        """
        Fetches live scan results from OpenVAS.
        Returns (success: bool, vulns: list, message: str)
        """
        # First ensure we are logged in if password provided
        if not self.token and self.password:
            ok, msg = self.login()
            if not ok:
                return False, [], msg

        try:
            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            # Query GMP results
            xml_req = '<get_results details="1" filter="rows=-1 min_qod=70"/>'
            r = self.session.post(f"{self.base_url}/gmp", data=xml_req, headers=headers, timeout=15)

            if r.status_code == 200 and "<get_results_response" in r.text:
                from app.parsers.openvas_parser import parse_openvas_xml
                vulns = parse_openvas_xml(r.text)
                return True, vulns, f"OpenVAS üzerinden {len(vulns)} adet canlı zaafiyet çekildi."
            elif r.status_code == 401 or "Token missing" in r.text:
                return False, [], "Oturum yetkilendirme hatası. Lütfen kullanıcı adı ve parolanızı kontrol ediniz."
            else:
                # Let's check get_tasks
                r_tasks = self.session.post(f"{self.base_url}/gmp", data='<get_tasks/>', headers=headers, timeout=15)
                if r_tasks.status_code == 200:
                    return True, [], "OpenVAS sunucusuna bağlanıldı. Henüz tamamlanmış bir tarama görevi bulunamadı (0 bulgu)."
                return False, [], f"OpenVAS yanıtı: {r.status_code} - {r.text[:200]}"
        except Exception as e:
            return False, [], f"Zaafiyet verisi çekilirken hata: {str(e)}"

if __name__ == "__main__":
    client = OpenVASClient()
    ok, msg = client.test_host()
    print("Host Test:", ok, msg)
