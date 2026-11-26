<p align="center">
  <img src="app/static/img/vulnix_logo.svg" alt="VULNIX Logo" width="120" height="120">
</p>

<h1 align="center">VULNIX</h1>
<p align="center">
  <strong>Enterprise Vulnerability Management & Incident Response Platform</strong><br>
  <em>OpenVAS / Greenbone GSAD 27 API Integration • Autonomous Background Scheduler • RBAC Incident Triage • Cross-Platform (Kali Linux & Windows)</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-brightgreen" alt="Platform">
  <img src="https://img.shields.io/badge/Scanner-OpenVAS%20%2F%20Greenbone%20OS%2025-orange" alt="OpenVAS">
  <img src="https://img.shields.io/badge/Architecture-Asyncio%20Scheduler-purple" alt="Async Scheduler">
</p>

---

## 🌐 English Documentation

### 📌 Overview
**VULNIX** is an independent, lightweight, self-hosted Vulnerability Management and Incident Response platform built for corporate SOC, Blue Team, and DevSecOps environments. 

Rather than relying on clunky, expensive enterprise monoliths or disconnected spreadsheet trackers, VULNIX connects directly to network vulnerability scanners (**OpenVAS / Greenbone OS 25 / GSAD 27** and Nessus XML) over authenticated HTTPS, ingests live findings, eliminates duplicate entries, automates team task delegation, and tracks remediations across strict SLA deadlines.

---

### 🛡️ Key Enterprise Features

1. **Direct OpenVAS / Greenbone GSAD 27 Integration**:
   - Communicates with live Greenbone instances (e.g. running on VMware NAT, isolated lab subnets, or corporate LAN).
   - Ingests CVE identifiers, CVSS v3.1 scores, attack vectors, threat impact assessments, and vendor remediation advice.
   - **Persistent Credentials**: Eliminates repetitive password prompts by securely storing encrypted connection settings.

2. **Autonomous Background Scheduler**:
   - An asynchronous engine running continuously in the background.
   - Queries vulnerability scanners at customizable intervals (**5m, 15m, 30m, 1h, 6h, 24h**).
   - **Intelligent Deduplication**: Guarantees existing open findings are not duplicated upon re-scans.
   - Real-time status heartbeat and scan telemetry badge in the UI.

3. **Role-Based Access Control (RBAC) & Triage Workflow**:
   - **Administrator**: Full system visibility, user management (`/users`), scanner API & SMTP configuration, and audit logs.
   - **Security Analyst**: Inspects assigned vulnerabilities, claims open unassigned issues with one click (*"Claim Vulnerability"*), uploads patch verification PoC screenshots, and records immutable response logs.

4. **Strict 8-Column Enterprise SLA Tracking Table**:
   - `Record ID` (`VULN-2026-XXXX`) • `Title & Target Host:Port` • `Severity (Critical/High/Medium/Low)` • `Department` • `Assignee` • `Status Analysis` • `SLA Due Date` • `Closed Date`.
   - Real-time overdue alerts for breaches of remediation deadlines.

5. **C-Level Executive Reporting**:
   - One-click boardroom-ready security assessment reports (`/reports/executive`).
   - Dark-mode preview with clean white print/PDF stylesheet formatting for executive presentations and compliance audits.

6. **100% Cross-Platform & Zero Cloud Dependency**:
   - Runs natively on **Kali Linux**, **Ubuntu/Debian**, and **Windows (10/11/Server)** without requiring external cloud accounts or compiled C++ dependencies.

---

### 🚀 Quick Start Guide

#### 🐧 Linux (Kali Linux, Ubuntu, Debian):
```bash
# Clone the repository
git clone https://github.com/meminerturk29/vulnix.git
cd vulnix

# Make launchers executable and run
chmod +x start.sh run.py
./start.sh
```
*Or run manually using Python:*
```bash
python3 -m pip install -r requirements.txt
python3 run.py
```

#### 🪟 Windows (10 / 11 / Server):
Double-click `start.bat` or run from PowerShell / CMD:
```cmd
git clone https://github.com/meminerturk29/vulnix.git
cd vulnix
pip install -r requirements.txt
python run.py
```

Navigate to **`http://localhost:8000`** in your browser.

---

### 🔑 Default Credentials & Accounts

| Username | Password | Role | Department | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| **`admin`** | **`admin123`** | **Administrator** | InfoSec / SOC | Full management, user control, scanner API, SMTP settings |
| **`ahmet.yilmaz`** | **`user123`** | **Analyst** | Software Dev | Claim vulnerabilities, submit patches & PoC evidence |
| **`burak.demir`** | **`user123`** | **Analyst** | Systems Admin | Task assignment, status updates |
| **`canan.kaya`** | **`user123`** | **Analyst** | Database Admin | Task assignment, status updates |
| **`deniz.arslan`** | **`user123`** | **Analyst** | Network Security | Task assignment, status updates |
| **`eren.yildiz`** | **`user123`** | **Analyst** | DevOps & Cloud | Task assignment, status updates |

---

<br>

## 🇹🇷 Türkçe Dokümantasyon

### 📌 Genel Bakış
**VULNIX**, kurumsal bilgi güvenliği operasyonlarında zafiyet tarama araçlarının (OpenVAS/Greenbone, Nessus vb.) ürettiği bulguları merkezi olarak yönetmek, sorumlu teknik birimlere paylaştırmak ve SLA süreleri içinde kapatılmasını denetlemek için geliştirilmiş **açık kaynaklı ve bağımsız bir Zaafiyet Yönetim Platformudur**.

---

### 🛡️ Öne Çıkan Yetenekler

1. **Canlı OpenVAS / Greenbone GSAD 27 API Entegrasyonu**:
   - GSAD 27 API protokolü ile doğrudan çift yönlü HTTPS senkronizasyonu kurulur.
   - Kimlik bilgileri kalıcı olarak saklandığı için kullanıcıdan **tekrar tekrar şifre istenmez**; tek tıkla canlı veriler çekilir.
   - CVSS v3.1 puanı, CVE referansları, tehdit değerlendirmesi ve çözüm adımları otomatik ayrıştırılır.

2. **Otomatik Zaafiyet Zamanlayıcısı (Background Scheduler)**:
   - Arka planda belirlenen periyotlarda (**5 dk, 15 dk, 30 dk, 1 saat**) OpenVAS'ı otomatik sorgular.
   - Yeni bulunan riskleri sisteme aktarır; **akıllı mükerrer kayıt koruması (*deduplication*)** sayesinde mevcut açıklar yinelenmez.

3. **Rol Tabanlı Yetkilendirme (RBAC) & Ekip Triage Akışı**:
   - **Yönetici (Admin)**: Tüm zaafiyetleri görme/düzenleme/silme, yeni personel ekleme (`/users`), zamanlayıcı ve SMTP ayarları.
   - **Analist / Çalışan**: Birime atanan açıkları filtreleme, tek tıkla **"Görevi Üstlen"** butonuna basarak işi üzerine alma, yama kanıtı/PoC görseli yükleme ve müdahale notu kaydetme.

4. **Standart 8 Sütunlu Kurumsal Zaafiyet Tablosu**:
   - `Kayıt No` • `Başlık & Hedef IP/Port` • `Seviye` • `Birim` • `İlgili Kişi` • `Durum Analizi` • `Termin (SLA)` • `Kapanış Tarihi`.
   - SLA termin süresi geçen açıkları anında tespit eden dinamik gecikme uyarıları.

5. **C-Level Yönetici Özeti Raporu**:
   - Tek tıkla yönetim kurullarına ve denetimlere sunulabilecek, PDF/Baskı formatına tam uyumlu kurumsal risk değerlendirme raporu üretimi (`/reports/executive`).

6. **Çapraz Platform ve Sıfır Bulut Bağımlılığı**:
   - Dışarıya veri sızdırmaz, tamamen yerel ağda çalışır.
   - Hem **Kali Linux** hem de **Windows** üzerinde tek tıkla çalışır (`./start.sh` veya `start.bat`).

---

### 📦 Proje Dizin Yapısı

```
vulnix/
├── app/
│   ├── main.py                     # FastAPI ana giriş noktası
│   ├── database.py                 # SQLite şeması ve migration motoru
│   ├── auth.py                     # PBKDF2 oturum ve kullanıcı kimlik doğrulama
│   ├── scheduler.py                # Arka plan otomatik zaafiyet zamanlayıcısı
│   ├── email_service.py            # SMTP bildirim ve hatırlatma motoru
│   ├── parsers/
│   │   ├── api_clients.py          # OpenVAS GSAD 27 & Nessus API istemcileri
│   │   ├── openvas_parser.py       # OpenVAS XML / GMP ayrıştırıcı
│   │   └── nessus_parser.py        # Nessus XML ayrıştırıcı
│   ├── routers/                    # Web endpoint yönlendiricileri (dashboard, vulns, users...)
│   └── templates/                  # Modern Dark SOC Jinja2 şablonları
├── samples/                        # Örnek tarama raporları
├── requirements.txt                # Platform bağımsız Python bağımlılıkları
├── run.py                          # Çapraz platform başlatıcı
├── start.sh                        # Linux / Kali Linux başlatıcı betiği
├── start.bat                       # Windows tek tık başlatıcı betiği
└── test_system.py                  # 14 adımlı otomatik sistem doğrulama test paketi
```

---

## 📄 Lisans
Bu proje açık kaynaklıdır ve kurumsal güvenlik operasyonlarının geliştirilmesi amacıyla paylaşılmıştır.
