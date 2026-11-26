import os
import sys
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db, get_db_connection, clear_all_vulnerabilities
from app.auth import SESSION_COOKIE_NAME

def run_tests():
    print("=" * 60)
    print("[*] SİSTEM VE KULLANICI DOĞRULAMA TESTLERİ BAŞLIYOR...")
    print("=" * 60)

    init_db()
    client = TestClient(app)

    # 1. Unauthenticated access to / should redirect to /login
    print("\n[TEST 1] Kimlik doğrulamasız ana sayfa erişimi...")
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and "/login" in r.headers["location"], f"Beklenen 303 /login, gelen: {r.status_code}"
    print("[OK] Giriş yapmamış kullanıcı /login sayfasına yönlendirildi.")

    # 2. Login Page Check
    print("\n[TEST 2] /login sayfası kontrolü...")
    r = client.get("/login")
    assert r.status_code == 200, f"Giriş sayfası açılamadı: {r.status_code}"
    assert "VULNIX" in r.text
    print("[OK] Giriş sayfası (HTTP 200) başarıyla render edildi.")

    # 3. Invalid Login Check
    print("\n[TEST 3] Hatalı parola denemesi...")
    r = client.post("/login", data={"username": "admin", "password": "wrongpassword"}, follow_redirects=False)
    assert r.status_code == 400
    print("[OK] Hatalı parola doğru şekilde reddedildi (HTTP 400).")

    # 4. Successful Admin Login
    print("\n[TEST 4] Admin girişi (admin / admin123)...")
    r = client.post("/login", data={"username": "admin", "password": "admin123", "next": "/"}, follow_redirects=False)
    assert r.status_code == 303
    assert SESSION_COOKIE_NAME in r.cookies
    admin_session = r.cookies[SESSION_COOKIE_NAME]
    print(f"[OK] Admin girişi başarılı! Oturum Cookie'si: {admin_session[:12]}...")

    admin_client = TestClient(app, cookies={SESSION_COOKIE_NAME: admin_session})

    # 5. Access Dashboard as Admin
    print("\n[TEST 5] Admin olarak Dashboard erişimi...")
    r = admin_client.get("/")
    assert r.status_code == 200
    assert "Vulnerability Management Dashboard" in r.text or "Zaafiyet Yönetim Paneli" in r.text
    print("[OK] Admin Dashboard başarıyla açıldı (Vulnerability Management Dashboard mevcut).")

    # 6. Admin User Management (/users)
    print("\n[TEST 6] Admin Kullanıcı Yönetimi (/users)...")
    r = admin_client.get("/users")
    assert r.status_code == 200
    assert "User" in r.text and "Management" in r.text
    print("[OK] Kullanıcı yönetim paneli görüntülendi.")

    # 7. Add New User
    print("\n[TEST 7] Yeni çalışan ekleme (/users/new)...")
    new_user_data = {
        "username": "selin.bulut",
        "password": "user1234",
        "full_name": "Selin Bulut",
        "email": "selin.bulut@sirket.com",
        "role": "user",
        "department": "Yazılım Geliştirme"
    }
    r = admin_client.post("/users/new", data=new_user_data, follow_redirects=False)
    assert r.status_code == 303
    print("[OK] Yeni çalışan (Selin Bulut) başarıyla eklendi.")

    # 8. Login as Worker (selin.bulut)
    print("\n[TEST 8] Çalışan olarak giriş (selin.bulut / user1234)...")
    r = client.post("/login", data={"username": "selin.bulut", "password": "user1234", "next": "/"}, follow_redirects=False)
    assert r.status_code == 303
    worker_session = r.cookies[SESSION_COOKIE_NAME]
    worker_client = TestClient(app, cookies={SESSION_COOKIE_NAME: worker_session})
    print("[OK] Çalışan oturumu oluşturuldu.")

    # 9. Verify Worker CANNOT access /users (Admin Only Check)
    print("\n[TEST 9] Çalışanın /users yetki kontrolü...")
    r = worker_client.get("/users", follow_redirects=False)
    assert r.status_code == 303, "Çalışan admin sayfasına erişememeliydi!"
    print("[OK] Çalışanın yetkisiz erişimi engellendi (Doğru yönlendirme yapıldı).")

    # 10. Worker Claims Vulnerability: "Ben Hallediyorum"
    print("\n[TEST 10] Zaafiyet Üstlenme: 'Bu açığı ben hallediyorum' testi...")
    # Insert a temporary vulnerability for functional test
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM vulnerabilities WHERE id = 9999")
    c.execute("""
        INSERT INTO vulnerabilities (
            id, record_no, title, severity, cvss_score, department,
            assignee_name, assignee_email, status, description, threat_assessment,
            remediation, target_host, due_date, created_at, updated_at
        ) VALUES (
            9999, 'VULN-9999', 'Test Güvenlik Açığı (Heartbleed)', 'Yüksek', 7.5,
            'Sistem Yönetimi', 'Atanmamış', '', 'Açık', 'Test Açıklama',
            'Test Tehdit Analizi', 'Yama uygulayın', '192.168.1.180', '2026-11-20',
            datetime('now'), datetime('now')
        )
    """)
    conn.commit()
    conn.close()

    r = worker_client.post("/vulnerabilities/9999/claim", follow_redirects=False)
    assert r.status_code == 303
    print("[OK] Üstlenme isteği başarıyla tamamlandı (HTTP 303).")

    # Verify DB update
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT assignee_name, status FROM vulnerabilities WHERE id = 9999")
    row = c.fetchone()
    assert row["assignee_name"] == "Selin Bulut", f"Atanan kişi Selin Bulut olmalıydı, gelen: {row['assignee_name']}"
    print(f"[OK] Veritabanı doğrulandı -> Atanan: {row['assignee_name']}, Durum: {row['status']}")

    # 11. Worker adds response note
    print("\n[TEST 11] Çalışanın yanıt (response) girmesi...")
    resp_data = {
        "action_type": "Yama Uygulandı",
        "message": "OpenSSL paketi güncellendi ve servis yeniden başlatıldı.",
        "new_status": "Aksiyon Alındı"
    }
    r = worker_client.post("/vulnerabilities/9999/response", data=resp_data, follow_redirects=False)
    assert r.status_code == 303
    print("[OK] Müdahale notu başarıyla kaydedildi.")

    # 12. Admin checks Worker Actions on Dashboard
    print("\n[TEST 12] Admin Dashboard'da çalışan aksiyonunu görme...")
    r = admin_client.get("/")
    assert "OpenSSL paketi güncellendi" in r.text or "OpenSSL package updated" in r.text
    assert "Selin Bulut" in r.text
    print("[OK] Admin paneli çalışanın aksiyonunu canlı akışta gösteriyor!")

    # 13. OpenVAS XML Upload Test
    print("\n[TEST 13] OpenVAS XML Dosyası Aktarımı (/import/upload)...")
    sample_xml_path = os.path.join(os.path.dirname(__file__), "samples", "openvas_report.xml")
    if os.path.exists(sample_xml_path):
        with open(sample_xml_path, "rb") as f:
            files = {"scan_file": ("openvas_report.xml", f, "text/xml")}
            data = {"tool_type": "openvas"}
            r = admin_client.post("/import/upload", data=data, files=files, follow_redirects=False)
            assert r.status_code == 303
            print("[OK] OpenVAS XML dosyası başarıyla analiz edilip sisteme aktarıldı.")
    else:
        print("[SKIP] samples/openvas_report.xml bulunamadı.")

    # 14. Executive Report Access
    print("\n[TEST 14] Yönetici Özeti Raporu (/reports/executive)...")
    r = admin_client.get("/reports/executive")
    assert r.status_code == 200
    assert "Executive Summary" in r.text or "Yönetici Özeti" in r.text
    print("[OK] Yönetici Raporu (C-Level) başarıyla render edildi.")

    # 15. Bilingual Language Switching Test (EN & TR with Flags)
    print("\n[TEST 15] Çift Dilli Dil Değiştirme ve Bayrak Testi (/set-lang)...")
    # Switch to Turkish
    r_tr = admin_client.get("/set-lang/tr", follow_redirects=False)
    assert r_tr.status_code == 303
    assert r_tr.cookies.get("vulnix_lang") == "tr"
    
    # Request dashboard with TR cookie
    admin_tr_client = TestClient(app, cookies={SESSION_COOKIE_NAME: admin_session, "vulnix_lang": "tr"})
    page_tr = admin_tr_client.get("/")
    assert page_tr.status_code == 200
    assert "Zaafiyet Listesi" in page_tr.text
    assert "🇹🇷" in page_tr.text and "🇬🇧" in page_tr.text
    print("[OK] Türkçe diline geçiş ve bayraklar başarıyla doğrulandı.")

    # Switch back to English
    admin_en_client = TestClient(app, cookies={SESSION_COOKIE_NAME: admin_session, "vulnix_lang": "en"})
    page_en = admin_en_client.get("/")
    assert page_en.status_code == 200
    assert "Vulnerability Matrix" in page_en.text
    assert "🇬🇧" in page_en.text and "🇹🇷" in page_en.text
    print("[OK] İngilizce diline geçiş ve bayraklar başarıyla doğrulandı.")

    # 16. Clean up test vulnerabilities to ensure database remains 100% clean
    clear_all_vulnerabilities()
    print("[OK] Test sonrasi veritabani sifirlandi (0 zaafiyet durumu saglandi).")

    print("\n" + "=" * 60)
    print("TÜM İSTEKLER VE SİSTEM TESTLERİ EKSİKSİZ BAŞARIYLA TAMAMLANDI!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
