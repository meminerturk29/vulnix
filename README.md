# VULNIX - Kurumsal Zaafiyet Yönetim Sistemi
### Vulnerability Management & Incident Response System (v2.0)

OpenVAS / Greenbone GSAD API ve XML tarama raporlarıyla entegre çalışan, rol tabanlı kullanıcı yetkilendirme (Admin / Analist), otomatik arka plan zamanlayıcısı (*Background Scheduler*), çalışan aksiyon takibi, zaafiyet üstlenme ("Görevi Üstlen"), termin (SLA) takvimi, SMTP e-posta bildirim motoru ve C-Level yönetici raporlaması sunan tam teşekküllü kurumsal zaafiyet yönetim platformu.

**Kali Linux**, **Ubuntu/Debian** ve **Windows (10/11/Server)** üzerinde tamamen yerel ve bağımsız olarak Python ile çalışır.

---

## 🚀 Hızlı Başlatma (Quick Start)

### 🐧 Kali Linux / Ubuntu / Debian:
```bash
chmod +x start.sh run.py
./start.sh
```
*veya doğrudan:*
```bash
python3 -m pip install -r requirements.txt
python3 run.py
```

### 🪟 Windows (10 / 11 / Server):
`start.bat` dosyasına çift tıklayarak çalıştırabilir veya CMD/PowerShell üzerinden:
```cmd
python -m pip install -r requirements.txt
python run.py
```

Tarayıcınızdan **`http://localhost:8000`** adresine giderek sisteme erişebilirsiniz.

---

## 🔑 Varsayılan Kullanıcı Giriş Bilgileri

Sistem ilk açılışta güvenli PBKDF2 hashlenmiş hazır kullanıcıları otomatik oluşturur:

| Kullanıcı Adı | Parola | Rol | Birim | Yetkiler |
| :--- | :--- | :--- | :--- | :--- |
| **`admin`** | **`admin123`** | **Yönetici (Admin)** | Bilgi Güvenliği | Tüm zaafiyetleri yönetme, kullanıcı ekleme/çıkarma, zamanlayıcı & SMTP ayarları |
| **`ahmet.yilmaz`** | **`user123`** | **Analist / Çalışan** | Yazılım Geliştirme | Zaafiyet üstlenme, müdahale notu & yama kanıtı ekleme |
| **`burak.demir`** | **`user123`** | **Analist / Çalışan** | Sistem Yönetimi | Görev üstlenme, durum güncelleme |
| **`canan.kaya`** | **`user123`** | **Analist / Çalışan** | Veritabanı | Görev üstlenme, durum güncelleme |
| **`deniz.arslan`** | **`user123`** | **Analist / Çalışan** | Network / Ağ | Görev üstlenme, durum güncelleme |
| **`eren.yildiz`** | **`user123`** | **Analist / Çalışan** | DevOps | Görev üstlenme, durum güncelleme |

---

## 🛡️ Öne Çıkan Kurumsal Yetenekler

### 1. Canlı OpenVAS / Greenbone Entegrasyonu & Kalıcı Kimlik
- Greenbone OS 25 / GSAD 27 API ile doğrudan HTTPS oturumu kurulur.
- Parola kalıcı olarak saklandığı için kullanıcıdan **tekrar tekrar şifre istenmez**. Tek tıkla canlı veriler çekilir.
- Mükerrer kayıt koruması (*deduplication*) sayesinde mevcut açıklar yinelenmez.

### 2. Otomatik Zaafiyet Zamanlayıcısı (Background Scheduler)
- Arka planda belirlenen periyotta (5 dk, 15 dk, 30 dk, 1 saat vb.) OpenVAS'ı otomatik sorgular.
- Yeni bulunan riskleri otomatik olarak sisteme kaydeder.
- Canlı durum göstergesi, son kontrol zamanı ve bulgu sayısı arayüzden anlık izlenebilir.

### 3. Modern Dark SOC & Minimalist Arayüz
- Dikkat dağıtıcı yapay metinler ve gereksiz açıklamalar tamamen temizlenmiştir.
- Kurumsal güvenlik operasyon merkezlerine uygun derin siyah/lacivert palet (`#080c15`), `Plus Jakarta Sans` ve `JetBrains Mono` tipografisi.
- Üst barda kullanıcı durum ibresi ve güvenli oturum kapatma (**Çıkış Yap**) butonu.

### 4. 8 Sütunlu Standart Zaafiyet Yönetim Tablosu
1. **Kayıt No** (`VULN-2026-XXXX`)
2. **Başlık & Hedef IP/Port**
3. **Seviye** (Kritik / Yüksek / Orta / Düşük)
4. **Birim** (Sistem, Yazılım, Network, SOC vb.)
5. **İlgili Kişi** (Sorumlu personel)
6. **Durum Analizi** (Açık, İnceleniyor, Aksiyon Alındı, Kapatıldı)
7. **Termin (SLA)**
8. **Kapanış Tarihi**

---

## 📦 Proje Dizin Yapısı

```
vulnerability-management-project/
├── app/
│   ├── main.py                     # FastAPI ana giriş noktası
│   ├── database.py                 # SQLite şeması ve migration
│   ├── auth.py                     # PBKDF2 oturum ve kullanıcı yönetimi
│   ├── scheduler.py                # Arka plan otomatik zamanlayıcı
│   ├── email_service.py            # SMTP bildirim motoru
│   ├── parsers/
│   │   ├── api_clients.py          # OpenVAS GSAD 27 & Nessus API istemcisi
│   │   ├── openvas_parser.py       # OpenVAS XML / GMP ayrıştırıcı
│   │   └── nessus_parser.py        # Nessus XML ayrıştırıcı
│   ├── routers/                    # Endpoint yönlendiricileri (dashboard, vulns, users...)
│   └── templates/                  # Modern Jinja2 HTML şablonları
├── backups/                        # Kararlı sürüm yedekleri (.zip ve klasör)
├── samples/                        # Örnek tarama raporları
├── requirements.txt                # Platform bağımsız Python kütüphaneleri
├── run.py                          # Çapraz platform başlatıcı
├── start.sh                        # Linux / Kali Linux başlatıcı script
├── start.bat                       # Windows başlatıcı script
└── test_system.py                  # 14 adımlı otomatik doğrulama test paketi
```
