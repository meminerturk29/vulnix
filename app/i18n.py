"""
Internationalization (i18n) Engine for VULNIX Platform.
Provides bilingual support (English & Turkish) with seamless cookie persistence.
"""
from typing import Dict, Any

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "en": {
        # Brand & Nav
        "brand_name": "VULNIX",
        "brand_tag": "SEC",
        "brand_sub": "SECURITY OPERATIONS",
        "nav_heading": "Navigation",
        "nav_dashboard": "Dashboard",
        "nav_vulns": "Vulnerability Matrix",
        "nav_my_tasks": "My Tasks",
        "nav_new_vuln": "New Vulnerability",
        "nav_integrations": "Integrations",
        "nav_openvas": "OpenVAS Sync",
        "nav_reports": "Executive Report",
        "nav_admin": "Administration",
        "nav_users": "User Management",
        "nav_settings": "System Settings",
        "role_admin": "Admin",
        "role_analyst": "Analyst",
        "btn_logout": "Sign Out",
        "btn_login": "Sign In",
        "quick_openvas": "OpenVAS Sync",
        "quick_add_vuln": "Add Vuln",

        # Dashboard
        "dash_title": "Vulnerability Management Dashboard",
        "dash_sub": "Real-time threat landscape, CVSS scoring, and incident remediation tracking.",
        "dash_new_btn": "New Vulnerability",
        "dash_exec_btn": "Executive Summary",
        "dash_empty_title": "No Vulnerabilities Recorded",
        "dash_empty_sub": "Pull live scan findings directly from your OpenVAS / Greenbone nodes.",
        "dash_empty_btn": "Pull Data from OpenVAS",
        "kpi_total": "Total Vulnerabilities",
        "kpi_critical": "Critical",
        "kpi_high": "High",
        "kpi_med_low": "Medium & Low",
        "kpi_remediated": "Remediated",
        "sla_breach_alert": "vulnerability records have exceeded their SLA remediation deadline.",
        "sla_breach_review": "Review",
        "my_assigned_title": "Assigned to Me",
        "my_assigned_all": "All",
        "remediation_due": "Due",
        "btn_take_action": "Respond",
        "action_feed_title": "Remediation & Action Timeline",
        "action_feed_empty": "No remediation actions recorded yet.",
        "chart_risk_dist": "Risk Distribution",
        "chart_dept_dist": "Department Workload",
        "chart_workload": "Workload",
        "team_status_title": "Team Status",
        "view_all": "All",
        "records": "Records",

        # Vulnerabilities List
        "list_title": "Vulnerability Management Matrix",
        "list_sub": "Department routing, SLA compliance, and remediation lifecycle tracking.",
        "filter_search": "Search",
        "filter_search_ph": "Title, IP, Record ID or CVE...",
        "filter_severity": "Severity",
        "filter_all_sev": "All Severities",
        "filter_dept": "Department",
        "filter_all_dept": "All Departments",
        "filter_status": "Status",
        "filter_all_status": "All Statuses",
        "filter_my_only": "My Tasks Only",
        "filter_overdue": "SLA Overdue Only",
        "filter_reset": "Reset",
        "filter_apply": "Filter",
        "col_record_no": "Record ID",
        "col_title": "Vulnerability Title",
        "col_severity": "Severity",
        "col_dept": "Department",
        "col_assignee": "Assignee",
        "col_status": "Status Analysis",
        "col_due": "SLA Due Date",
        "col_closed": "Closed Date",
        "col_action": "Action",
        "btn_detail": "Detail",
        "badge_overdue": "OVERDUE",
        "list_empty": "No vulnerabilities match the selected filters.",

        # Vulnerability Detail
        "detail_threat": "Threat & Impact Assessment",
        "detail_desc": "Technical Description",
        "detail_cvss_vector": "CVSS Vector",
        "detail_remediation": "Recommended Remediation Steps",
        "detail_poc": "Proof of Concept (PoC) Evidence",
        "detail_poc_full": "Full Size",
        "detail_poc_empty": "No visual evidence attached.",
        "detail_assignment": "Assignment & Lifecycle",
        "detail_target": "Target Host",
        "detail_port": "Port / Service",
        "btn_claim": "Claim Vulnerability",
        "badge_assigned_me": "Assigned to You",
        "btn_send_email": "Send Email Alert",
        "btn_edit": "Edit",
        "btn_delete": "Delete",
        "form_action_title": "Add Remediation Response",
        "form_action_type": "Action Type",
        "form_action_status": "Update Status",
        "form_action_keep": "Do not change status",
        "form_action_note": "Response Note *",
        "form_action_file": "Evidence File / Screenshot (Optional)",
        "btn_save_response": "Record Response",
        "timeline_title": "Audit & Response Timeline",
        "timeline_empty": "No action responses recorded yet.",

        # Form (New / Edit)
        "form_nav_crumb": "Vulnerability Matrix",
        "form_edit_crumb": "Edit Record",
        "form_new_crumb": "New Record",
        "form_edit_title": "Edit Vulnerability Record",
        "form_new_title": "New Vulnerability Record",
        "sec_basic_title": "Basic Information & Risk Score",
        "field_title": "Vulnerability Title *",
        "field_cvss": "CVSS v3.1 Score (0.0 - 10.0) *",
        "field_risk_calc": "Calculated Severity",
        "field_cve": "CVE Identifier",
        "field_vector": "CVSS Vector String (Optional)",
        "sec_assign_title": "Department Routing & SLA Due Date",
        "quick_user_pick": "Quick Pick from Registered Personnel:",
        "pick_user_default": "-- Select Personnel --",
        "field_dept": "Responsible Department *",
        "field_status": "Status *",
        "field_assignee_name": "Assignee Name *",
        "field_assignee_email": "Assignee Email *",
        "field_due_date": "SLA Due Date *",
        "sec_target_title": "Target System & Scanner Source",
        "field_target_host": "Target IP / Hostname *",
        "field_target_port": "Port / Service",
        "field_tool_source": "Scanner Source *",
        "sec_details_title": "Technical Details & Remediation",
        "field_tech_desc": "Technical Description *",
        "field_threat_eval": "Threat Evaluation (Impact Analysis) *",
        "field_remediation_rec": "Remediation & Patching Steps *",
        "sec_poc_title": "PoC Evidence Screenshot (Optional)",
        "chk_send_email_now": "Dispatch email alert to assigned personnel upon saving",
        "btn_cancel": "Cancel",
        "btn_save_changes": "Save Changes",
        "btn_save_record": "Save Vulnerability",

        # Import & OpenVAS
        "import_title": "OpenVAS Integration & Scheduler",
        "import_sub": "Autonomous vulnerability scanning, scheduler intervals, and report ingestion.",
        "import_reset_btn": "Purge Database",
        "timer_card_title": "Autonomous Vulnerability Scheduler",
        "timer_active_badge": "Active",
        "timer_paused_badge": "Paused",
        "timer_card_sub": "Periodically queries OpenVAS scanner nodes; newly identified vulnerabilities are ingested automatically.",
        "btn_sync_now": "Sync Now (Instant)",
        "metric_target": "Target Node",
        "metric_cred": "Credentials",
        "metric_last_sync": "Last Scan Time",
        "metric_status": "Last Status",
        "cred_saved_tag": "Saved (Encrypted)",
        "never_run": "Never Run",
        "ready_status": "Ready",
        "timer_settings_title": "Scheduler & Persistent Connection Settings",
        "field_openvas_url": "OpenVAS URL (Host / NAT IP)",
        "field_username": "Username",
        "field_password": "Password",
        "pwd_saved_hint": "● Saved permanently",
        "pwd_ph": "•••••••• (Leave blank to keep saved password)",
        "field_auto_sync_chk": "Enable Autonomous Background Scheduler",
        "field_frequency": "Scan Frequency:",
        "freq_5m": "Every 5 Minutes",
        "freq_15m": "Every 15 Minutes (Recommended)",
        "freq_30m": "Every 30 Minutes",
        "freq_1h": "Every 1 Hour",
        "freq_6h": "Every 6 Hours",
        "freq_24h": "Once a Day",
        "field_include_logs": "Include Log / Informational (CVSS 0.0) findings",
        "btn_save_timer": "Save Scheduler & Credentials",
        "manual_xml_title": "Upload Manual XML Report",
        "btn_upload_xml": "Ingest from File",
        "net_test_title": "Network Connectivity Test",
        "btn_test_net": "Test Port & Reachability",

        # Users Management
        "users_title": "User & Team Management",
        "users_sub": "Security personnel, role assignments, and activity tracking.",
        "add_user_title": "Add New User",
        "field_fullname": "Full Name *",
        "field_email": "Email Address *",
        "field_role": "System Role *",
        "role_analyst_opt": "Analyst (Technical Personnel)",
        "role_admin_opt": "Administrator (Full Access)",
        "btn_save_user": "Create User",
        "reg_users_title": "Registered Users",
        "col_user": "User",
        "col_assigned_tasks": "Assigned",
        "col_actions_done": "Actions",

        # Settings & SMTP
        "settings_title": "System & SMTP Settings",
        "settings_sub": "Email dispatch, SMTP relay configuration, and runtime environment.",
        "os_title": "Operating System",
        "python_title": "Python Version",
        "db_title": "Database",
        "smtp_status_title": "SMTP Dispatch",
        "smtp_sim_mode": "Simulation Mode",
        "smtp_live_mode": "Live Server",
        "smtp_config_title": "SMTP Relay Configuration",
        "field_comp_name": "Company / Organization Name",
        "field_smtp_host": "SMTP Host / IP",
        "field_smtp_port": "Port",
        "field_smtp_user": "SMTP Username / Email",
        "field_smtp_pass": "SMTP Password",
        "field_smtp_from": "From Header",
        "chk_starttls": "STARTTLS Encryption",
        "chk_sim_mode": "Simulation Mode (Writes to local Outbox without dispatching)",
        "btn_save_settings": "Save Settings",
        "test_email_title": "Test Email Dispatch",
        "field_test_recipient": "Recipient Email Address",
        "btn_test_send": "Dispatch Test Email",
        "outbox_title": "Email Transmission Log (Outbox)",
        "col_date": "Date",
        "col_recipient": "Recipient",
        "col_subject": "Subject",
        "col_result": "Status",
        "col_detail": "Detail",
        "outbox_empty": "No email transmissions recorded yet.",

        # Login
        "login_heading": "Sign In",
        "login_user": "Username",
        "login_pass": "Password",
        "login_btn": "Sign In",
        "logged_out_msg": "You have been successfully signed out.",

        # Executive Report
        "exec_title": "Executive Vulnerability & Risk Assessment Report",
        "exec_sub": "Information Systems Infrastructure Security Audit & Exposure Analysis",
        "exec_back_btn": "Return to Dashboard",
        "exec_print_btn": "Print / Export as PDF",
        "exec_company": "Organization:",
        "exec_date": "Report Date:",
        "exec_confidential": "CONFIDENTIAL / INTERNAL USE ONLY",
        "exec_summary_heading": "Executive Summary",
        "exec_summary_text": "This report provides a high-level summary of identified vulnerabilities, exposure vectors, and actionable remediation roadmaps discovered across corporate servers, networks, and cloud infrastructures.",
        "exec_risk_posture": "Overall Security Posture",
        "exec_posture_critical": "CRITICAL RISK: Urgent remediation required.",
        "exec_posture_high": "ELEVATED RISK: Prioritized patching recommended.",
        "exec_posture_good": "HEALTHY: No active high-severity vulnerabilities.",
        "exec_findings_heading": "Prioritized Vulnerability Findings",
        "exec_remed_heading": "Strategic Remediation Roadmap",
        "exec_sign_heading": "Audit Sign-off",
        "exec_lead_auditor": "Lead Security Auditor",
        "exec_ciso": "Chief Information Security Officer (CISO)",
    },

    "tr": {
        # Brand & Nav
        "brand_name": "VULNIX",
        "brand_tag": "SEC",
        "brand_sub": "SECURITY OPERATIONS",
        "nav_heading": "Navigasyon",
        "nav_dashboard": "Dashboard",
        "nav_vulns": "Zaafiyet Listesi",
        "nav_my_tasks": "Görevlerim",
        "nav_new_vuln": "Yeni Zaafiyet",
        "nav_integrations": "Entegrasyon",
        "nav_openvas": "OpenVAS Senkronizasyon",
        "nav_reports": "Yönetici Raporu",
        "nav_admin": "Yönetim",
        "nav_users": "Kullanıcı Yönetimi",
        "nav_settings": "Sistem Ayarları",
        "role_admin": "Yönetici",
        "role_analyst": "Analist",
        "btn_logout": "Çıkış Yap",
        "btn_login": "Giriş Yap",
        "quick_openvas": "OpenVAS Senkron",
        "quick_add_vuln": "Zaafiyet Ekle",

        # Dashboard
        "dash_title": "Zaafiyet Yönetim Paneli",
        "dash_sub": "Tespit edilen güvenlik açıkları, risk skorları ve müdahale takibi.",
        "dash_new_btn": "Yeni Zaafiyet",
        "dash_exec_btn": "Yönetici Özeti",
        "dash_empty_title": "Sistemde Kayıtlı Zaafiyet Bulunmuyor",
        "dash_empty_sub": "OpenVAS üzerinden canlı tarama verilerini hemen çekebilirsiniz.",
        "dash_empty_btn": "OpenVAS'tan Verileri Çek",
        "kpi_total": "Toplam Zaafiyet",
        "kpi_critical": "Kritik",
        "kpi_high": "Yüksek",
        "kpi_med_low": "Orta & Düşük",
        "kpi_remediated": "Giderilen",
        "sla_breach_alert": "adet zaafiyetin SLA termin süresi geçmiş durumda.",
        "sla_breach_review": "İncele",
        "my_assigned_title": "Üzerime Atanan Açıklar",
        "my_assigned_all": "Tümü",
        "remediation_due": "Termin",
        "btn_take_action": "Müdahale",
        "action_feed_title": "Aksiyon ve Müdahale Günlüğü",
        "action_feed_empty": "Henüz kaydedilmiş bir müdahale aksiyonu bulunmuyor.",
        "chart_risk_dist": "Risk Dağılımı",
        "chart_dept_dist": "Birim Dağılımı",
        "chart_workload": "Görev Yükü",
        "team_status_title": "Ekip Durumu",
        "view_all": "Tümü",
        "records": "Kayıt",

        # Vulnerabilities List
        "list_title": "Zaafiyet Yönetim Tablosu",
        "list_sub": "Sorumlu birim atamaları, termin takibi ve durum analizi.",
        "filter_search": "Arama",
        "filter_search_ph": "Başlık, IP, Kayıt No veya CVE...",
        "filter_severity": "Seviye",
        "filter_all_sev": "Tüm Seviyeler",
        "filter_dept": "Sorumlu Birim",
        "filter_all_dept": "Tüm Birimler",
        "filter_status": "Durum",
        "filter_all_status": "Tüm Durumlar",
        "filter_my_only": "Yalnızca Görevlerim",
        "filter_overdue": "SLA Aşımı (Gecikenler)",
        "filter_reset": "Sıfırla",
        "filter_apply": "Filtrele",
        "col_record_no": "Kayıt No",
        "col_title": "Başlık",
        "col_severity": "Seviye",
        "col_dept": "Birim",
        "col_assignee": "İlgili Kişi",
        "col_status": "Durum Analizi",
        "col_due": "Termin",
        "col_closed": "Kapanış Tarihi",
        "col_action": "İşlem",
        "btn_detail": "Detay",
        "badge_overdue": "GECİKTİ",
        "list_empty": "Kriterlere uygun zaafiyet bulunamadı.",

        # Vulnerability Detail
        "detail_threat": "Tehdit ve Etki Değerlendirmesi",
        "detail_desc": "Teknik Açıklama",
        "detail_cvss_vector": "CVSS Vektörü",
        "detail_remediation": "Önerilen Çözüm ve İyileştirme Adımları",
        "detail_poc": "Kanıt / Ekran Görüntüsü (PoC)",
        "detail_poc_full": "Tam Boyut",
        "detail_poc_empty": "Görsel kanıt eklenmemiş.",
        "detail_assignment": "Atama ve Süreç",
        "detail_target": "Hedef Cihaz",
        "detail_port": "Port / Servis",
        "btn_claim": "Görevi Üstlen",
        "badge_assigned_me": "Üzerinizde Aktif",
        "btn_send_email": "E-Posta Bildirimi",
        "btn_edit": "Düzenle",
        "btn_delete": "Sil",
        "form_action_title": "Müdahale / Aksiyon Yanıtı Ekle",
        "form_action_type": "Aksiyon Türü",
        "form_action_status": "Durumu Güncelle",
        "form_action_keep": "Durumu Değiştirme",
        "form_action_note": "Açıklama / Yanıt Notu *",
        "form_action_file": "Kanıt Dosyası / Ekran Görüntüsü (İsteğe Bağlı)",
        "btn_save_response": "Yanıtı Kaydet",
        "timeline_title": "Aksiyon ve Süreç Günlüğü",
        "timeline_empty": "Henüz kaydedilmiş bir aksiyon yanıtı bulunmuyor.",

        # Form (New / Edit)
        "form_nav_crumb": "Zaafiyet Tablosu",
        "form_edit_crumb": "Düzenle",
        "form_new_crumb": "Yeni Kayıt",
        "form_edit_title": "Zaafiyet Kaydını Düzenle",
        "form_new_title": "Yeni Zaafiyet Kaydı",
        "sec_basic_title": "Temel Bilgiler ve Risk Skoru",
        "field_title": "Zaafiyet Başlığı *",
        "field_cvss": "CVSS v3 Puanı (0.0 - 10.0) *",
        "field_risk_calc": "Risk Seviyesi",
        "field_cve": "CVE Numarası",
        "field_vector": "CVSS Vektörü (Opsiyonel)",
        "sec_assign_title": "Sorumlu Birim ve Termin",
        "quick_user_pick": "Kayıtlı Personel Listesinden Seç:",
        "pick_user_default": "-- Personel Seçiniz --",
        "field_dept": "Sorumlu Birim *",
        "field_status": "Durum *",
        "field_assignee_name": "İlgili Kişi *",
        "field_assignee_email": "E-Posta Adresi *",
        "field_due_date": "Termin Tarihi *",
        "sec_target_title": "Hedef Sistem Bilgileri",
        "field_target_host": "Hedef IP / Host *",
        "field_target_port": "Port / Servis",
        "field_tool_source": "Tarama Kaynağı *",
        "sec_details_title": "Detaylar ve Çözüm Adımları",
        "field_tech_desc": "Teknik Açıklama *",
        "field_threat_eval": "Tehdit Değerlendirmesi *",
        "field_remediation_rec": "Önerilen Çözüm (Remediation) *",
        "sec_poc_title": "Kanıt Dosyası / PoC (İsteğe Bağlı)",
        "chk_send_email_now": "Kayıt oluşturulduğunda ilgili personele bildirim e-postası ilet",
        "btn_cancel": "İptal",
        "btn_save_changes": "Değişiklikleri Kaydet",
        "btn_save_record": "Zaafiyeti Kaydet",

        # Import & OpenVAS
        "import_title": "OpenVAS Entegrasyonu & Zamanlayıcı",
        "import_sub": "Otomatik periyodik zaafiyet kontrolü ve canlı tarama senkronizasyonu.",
        "import_reset_btn": "Veritabanını Sıfırla",
        "timer_card_title": "Otomatik Zaafiyet Zamanlayıcısı",
        "timer_active_badge": "Aktif",
        "timer_paused_badge": "Duraklatıldı",
        "timer_card_sub": "OpenVAS sunucusu periyodik olarak sorgulanır, yeni bulunan riskler otomatik aktarılır.",
        "btn_sync_now": "Hemen Senkronize Et",
        "metric_target": "Hedef Sunucu",
        "metric_cred": "Kayıtlı Kimlik",
        "metric_last_sync": "Son Kontrol Zamanı",
        "metric_status": "Son Durum / Sonuç",
        "cred_saved_tag": "Parola Kayıtlı",
        "never_run": "Henüz Çalışmadı",
        "ready_status": "Hazır",
        "timer_settings_title": "Zamanlayıcı ve Kalıcı Bağlantı Ayarları",
        "field_openvas_url": "OpenVAS URL (NAT IP)",
        "field_username": "Kullanıcı Adı",
        "field_password": "Giriş Parolası",
        "pwd_saved_hint": "● Kayıtlı",
        "pwd_ph": "•••••••• (Kayıtlı, değiştirmek için yazın)",
        "field_auto_sync_chk": "Arka Planda Otomatik Zamanlayıcıyı Etkinleştir",
        "field_frequency": "Kontrol Sıklığı:",
        "freq_5m": "5 Dakikada Bir",
        "freq_15m": "15 Dakikada Bir (Önerilen)",
        "freq_30m": "30 Dakikada Bir",
        "freq_1h": "1 Saatte Bir",
        "freq_6h": "6 Saatte Bir",
        "freq_24h": "Günde 1 Kez",
        "field_include_logs": "Bilgi / Log seviyesindeki (CVSS 0.0) kayıtları da dahil et",
        "btn_save_timer": "Zamanlayıcı ve Parolayı Kaydet",
        "manual_xml_title": "Manuel XML Raporu Yükle",
        "btn_upload_xml": "Dosyadan İçe Aktar",
        "net_test_title": "Ağ Bağlantı Testi",
        "btn_test_net": "Port ve Erişimi Test Et",

        # Users Management
        "users_title": "Kullanıcı ve Ekip Yönetimi",
        "users_sub": "Sistem kullanıcıları, rolleri ve müdahale aksiyon takibi.",
        "add_user_title": "Yeni Kullanıcı Ekle",
        "field_fullname": "Ad Soyad *",
        "field_email": "E-Posta *",
        "field_role": "Rol *",
        "role_analyst_opt": "Çalışan (Teknik Personel)",
        "role_admin_opt": "Yönetici (Admin)",
        "btn_save_user": "Kullanıcıyı Kaydet",
        "reg_users_title": "Kayıtlı Kullanıcılar",
        "col_user": "Personel",
        "col_assigned_tasks": "Atanan Görev",
        "col_actions_done": "Aksiyon",

        # Settings & SMTP
        "settings_title": "Sistem ve SMTP Ayarları",
        "settings_sub": "E-posta bildirimleri ve sistem parametreleri.",
        "os_title": "İşletim Sistemi",
        "python_title": "Python Sürümü",
        "db_title": "Veritabanı",
        "smtp_status_title": "SMTP Durumu",
        "smtp_sim_mode": "Simülasyon Modu",
        "smtp_live_mode": "Canlı Sunucu",
        "smtp_config_title": "SMTP Sunucu Yapılandırması",
        "field_comp_name": "Kurum / Şirket Adı",
        "field_smtp_host": "SMTP Host / IP",
        "field_smtp_port": "Port",
        "field_smtp_user": "Kullanıcı Adı / E-Posta",
        "field_smtp_pass": "Parola",
        "field_smtp_from": "Gönderici Adı (From Header)",
        "chk_starttls": "STARTTLS Şifreleme",
        "chk_sim_mode": "Simülasyon Modu (E-postaları dahili Outbox günlüğüne kaydeder)",
        "btn_save_settings": "Ayarları Kaydet",
        "test_email_title": "Test E-Postası",
        "field_test_recipient": "Alıcı E-Posta Adresi",
        "btn_test_send": "Test Gönder",
        "outbox_title": "E-Posta İletim Günlüğü",
        "col_date": "Tarih",
        "col_recipient": "Alıcı",
        "col_subject": "Konu",
        "col_result": "Durum",
        "col_detail": "Açıklama",
        "outbox_empty": "Kayıtlı e-posta gönderimi bulunmuyor.",

        # Login
        "login_heading": "Giriş Yap",
        "login_user": "Kullanıcı Adı",
        "login_pass": "Parola",
        "login_btn": "Giriş Yap",
        "logged_out_msg": "Oturumunuz başarıyla kapatıldı.",

        # Executive Report
        "exec_title": "Yönetici Özeti & Zaafiyet Değerlendirme Raporu",
        "exec_sub": "Bilgi Sistemleri Altyapısı Güvenlik Taramaları ve Risk Analiz Raporu",
        "exec_back_btn": "Paneline Geri Dön",
        "exec_print_btn": "Raporu Yazdır / PDF Olarak Kaydet",
        "exec_company": "Kurum:",
        "exec_date": "Rapor Tarihi:",
        "exec_confidential": "HASSAS / KURUM İÇİ",
        "exec_summary_heading": "Yönetici Özeti (Executive Summary)",
        "exec_summary_text": "Bu rapor, kurum bünyesinde barındırılan sunucular, web uygulamaları, ağ bileşenleri ve veritabanı altyapısında gerçekleştirilen güvenlik taramaları (Nessus, OpenVAS ve Manuel Pentest testleri) sonucunda elde edilen risklerin ve çözüm önerilerinin üst düzey bir özetidir.",
        "exec_risk_posture": "Genel Risk Seviyesi",
        "exec_posture_critical": "KRİTİK RİSK: Acil müdahale gerektirir.",
        "exec_posture_high": "YÜKSEK RİSK: Öncelikli yama planı önerilir.",
        "exec_posture_good": "GÜVENLİ: Aktif kritik seviyede bulgu bulunmuyor.",
        "exec_findings_heading": "Öncelikli Risk Bulguları",
        "exec_remed_heading": "Önerilen İyileştirme Yol Haritası",
        "exec_sign_heading": "Rapor Onayı ve Yetkili İmzaları",
        "exec_lead_auditor": "Kıdemli Siber Güvenlik Uzmanı",
        "exec_ciso": "Bilgi Güvenliği Direktörü (CISO)",
    }
}

SEVERITY_MAP = {
    "en": {
        "Kritik": "Critical",
        "Yüksek": "High",
        "Orta": "Medium",
        "Düşük": "Low",
        "Bilgi": "Info",
        "Critical": "Critical",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Info": "Info",
    },
    "tr": {
        "Critical": "Kritik",
        "High": "Yüksek",
        "Medium": "Orta",
        "Low": "Düşük",
        "Info": "Bilgi",
        "Kritik": "Kritik",
        "Yüksek": "Yüksek",
        "Orta": "Orta",
        "Düşük": "Düşük",
        "Bilgi": "Bilgi",
    }
}

STATUS_MAP = {
    "en": {
        "Açık": "Open",
        "İnceleniyor": "Investigating",
        "Aksiyon Alındı": "Action Taken",
        "Kapatıldı": "Closed",
        "Kabul Edilen Risk": "Risk Accepted",
        "Kayıt Açıldı": "Record Created",
        "Yama Uygulandı": "Patch Applied",
        "Konfigürasyon Değiştirildi": "Configuration Changed",
        "İnceleme Başlatıldı": "Investigation Started",
        "Test Edildi ve Doğrulandı": "Tested & Verified",
        "Yanlış Pozitif (False Positive)": "False Positive",
        "Diğer": "Other",
        "Üstlendi": "Claimed",
        "Üstlenildi": "Claimed",
        "Open": "Open",
        "Investigating": "Investigating",
        "Action Taken": "Action Taken",
        "Closed": "Closed",
        "Risk Accepted": "Risk Accepted",
        "Record Created": "Record Created",
        "Patch Applied": "Patch Applied",
        "Configuration Changed": "Configuration Changed",
        "Investigation Started": "Investigation Started",
        "Tested & Verified": "Tested & Verified",
        "False Positive": "False Positive",
        "Other": "Other",
        "Claimed": "Claimed",
    },
    "tr": {
        "Record Created": "Kayıt Açıldı",
        "Patch Applied": "Yama Uygulandı",
        "Configuration Changed": "Konfigürasyon Değiştirildi",
        "Investigation Started": "İnceleme Başlatıldı",
        "Tested & Verified": "Test Edildi ve Doğrulandı",
        "False Positive": "Yanlış Pozitif",
        "Other": "Diğer",
        "Claimed": "Üstlenildi",
        "Open": "Açık",
        "Investigating": "İnceleniyor",
        "Action Taken": "Aksiyon Alındı",
        "Closed": "Kapatıldı",
        "Risk Accepted": "Kabul Edilen Risk",
        "Açık": "Açık",
        "İnceleniyor": "İnceleniyor",
        "Aksiyon Alındı": "Aksiyon Alındı",
        "Kapatıldı": "Kapatıldı",
        "Kabul Edilen Risk": "Kabul Edilen Risk",
        "Kayıt Açıldı": "Kayıt Açıldı",
        "Yama Uygulandı": "Yama Uygulandı",
        "Konfigürasyon Değiştirildi": "Konfigürasyon Değiştirildi",
        "İnceleme Başlatıldı": "İnceleme Başlatıldı",
        "Test Edildi ve Doğrulandı": "Test Edildi ve Doğrulandı",
        "Yanlış Pozitif (False Positive)": "Yanlış Pozitif (False Positive)",
        "Diğer": "Diğer",
        "Üstlendi": "Üstlendi",
        "Üstlenildi": "Üstlenildi",
    }
}

DEPARTMENT_MAP = {
    "en": {
        "Sistem Yönetimi": "System Administration",
        "Yazılım Geliştirme": "Software Development",
        "Network/Ağ Güvenliği": "Network / Infrastructure",
        "Network / Ağ Güvenliği": "Network / Infrastructure",
        "Veritabanı Yönetimi": "Database Administration",
        "DevOps": "DevOps & Cloud",
        "DevOps & Bulut": "DevOps & Cloud",
        "Bilgi Güvenliği": "Cyber Security / SOC",
        "Bilgi Güvenliği / SOC": "Cyber Security / SOC",
        "Genel": "General",
        "Atanmamış": "Unassigned",
        "Atanmadı": "Unassigned",
        "System Administration": "System Administration",
        "Software Development": "Software Development",
        "Network / Infrastructure": "Network / Infrastructure",
        "Database Administration": "Database Administration",
        "DevOps & Cloud": "DevOps & Cloud",
        "Cyber Security / SOC": "Cyber Security / SOC",
        "Cyber Security": "Cyber Security / SOC",
        "Information Security": "Cyber Security / SOC",
        "General": "General",
        "Unassigned": "Unassigned",
    },
    "tr": {
        "System Administration": "Sistem Yönetimi",
        "Software Development": "Yazılım Geliştirme",
        "Network / Infrastructure": "Network / Ağ Güvenliği",
        "Database Administration": "Veritabanı Yönetimi",
        "DevOps & Cloud": "DevOps & Bulut",
        "DevOps": "DevOps",
        "Cyber Security / SOC": "Bilgi Güvenliği / SOC",
        "Cyber Security": "Bilgi Güvenliği / SOC",
        "Information Security": "Bilgi Güvenliği / SOC",
        "General": "Genel",
        "Unassigned": "Atanmamış",
        "Sistem Yönetimi": "Sistem Yönetimi",
        "Yazılım Geliştirme": "Yazılım Geliştirme",
        "Network/Ağ Güvenliği": "Network / Ağ Güvenliği",
        "Network / Ağ Güvenliği": "Network / Ağ Güvenliği",
        "Veritabanı Yönetimi": "Veritabanı Yönetimi",
        "DevOps & Bulut": "DevOps & Bulut",
        "Bilgi Güvenliği": "Bilgi Güvenliği / SOC",
        "Bilgi Güvenliği / SOC": "Bilgi Güvenliği / SOC",
        "Genel": "Genel",
        "Atanmamış": "Atanmamış",
        "Atanmadı": "Atanmamış",
    }
}


PAGE_TITLE_MAP = {
    "en": {
        "VMS Yönetici & Operasyon Dashboard": "Security Operations Dashboard",
        "VMS YÖNETİCİ & OPERASYON DASHBOARD": "Security Operations Dashboard",
        "VMS Yönetici & Operasyon Paneli": "Security Operations Dashboard",
        "Güvenlik Operasyonları Paneli": "Security Operations Dashboard",
        "Security Operations Dashboard": "Security Operations Dashboard",
        "Zaafiyet Yönetim Tablosu": "Vulnerability Management Matrix",
        "Vulnerability Management Matrix": "Vulnerability Management Matrix",
        "OpenVAS / Greenbone Tarama Senkronizasyonu": "OpenVAS Scanner Sync",
        "OpenVAS Scanner Sync": "OpenVAS Scanner Sync",
        "Yönetici Özeti & Zaafiyet Değerlendirme Raporu": "Executive Summary & Risk Report",
        "Executive Summary & Risk Report": "Executive Summary & Risk Report",
        "Sistem ve SMTP E-Posta Ayarları": "System & SMTP Settings",
        "System & SMTP Settings": "System & SMTP Settings",
        "Kullanıcı ve Ekip Yönetimi": "User & Team Management",
        "User & Team Management": "User & Team Management",
        "Sisteme Giriş Yap": "Sign In",
        "Giriş Yap": "Sign In",
        "Sign In": "Sign In",
        "Yeni Zaafiyet Kaydı Ekle": "New Vulnerability Record",
        "New Vulnerability Record": "New Vulnerability Record",
    },
    "tr": {
        "Security Operations Dashboard": "Güvenlik Operasyonları Paneli",
        "VMS Yönetici & Operasyon Dashboard": "Güvenlik Operasyonları Paneli",
        "VMS YÖNETİCİ & OPERASYON DASHBOARD": "Güvenlik Operasyonları Paneli",
        "VMS Yönetici & Operasyon Paneli": "Güvenlik Operasyonları Paneli",
        "Güvenlik Operasyonları Paneli": "Güvenlik Operasyonları Paneli",
        "Vulnerability Management Matrix": "Zaafiyet Yönetim Tablosu",
        "Zaafiyet Yönetim Tablosu": "Zaafiyet Yönetim Tablosu",
        "OpenVAS Scanner Sync": "OpenVAS Senkronizasyonu",
        "OpenVAS / Greenbone Tarama Senkronizasyonu": "OpenVAS Senkronizasyonu",
        "Executive Summary & Risk Report": "Yönetici Özeti & Zaafiyet Raporu",
        "Yönetici Özeti & Zaafiyet Değerlendirme Raporu": "Yönetici Özeti & Zaafiyet Raporu",
        "System & SMTP Settings": "Sistem ve SMTP Ayarları",
        "Sistem ve SMTP E-Posta Ayarları": "Sistem ve SMTP Ayarları",
        "User & Team Management": "Kullanıcı ve Ekip Yönetimi",
        "Kullanıcı ve Ekip Yönetimi": "Kullanıcı ve Ekip Yönetimi",
        "Sign In": "Sisteme Giriş Yap",
        "Sisteme Giriş Yap": "Sisteme Giriş Yap",
        "New Vulnerability Record": "Yeni Zaafiyet Kaydı Ekle",
        "Yeni Zaafiyet Kaydı Ekle": "Yeni Zaafiyet Kaydı Ekle",
    }
}

USER_NAME_MAP = {
    "en": {
        "Sistem Yöneticisi (Admin)": "System Administrator (Admin)",
        "Sistem Yöneticisi": "System Administrator",
        "System Administrator (Admin)": "System Administrator (Admin)",
        "System Administrator": "System Administrator",
    },
    "tr": {
        "System Administrator (Admin)": "Sistem Yöneticisi (Admin)",
        "System Administrator": "Sistem Yöneticisi",
        "Sistem Yöneticisi (Admin)": "Sistem Yöneticisi (Admin)",
        "Sistem Yöneticisi": "Sistem Yöneticisi",
    }
}


def get_current_lang(request) -> str:
    """Reads language from cookie 'vulnix_lang', defaults to 'en'."""
    lang = request.cookies.get("vulnix_lang", "en").lower()
    return "tr" if lang == "tr" else "en"


def get_translations(lang: str) -> Dict[str, str]:
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"])


def localize_severity(val: str, lang: str = "en") -> str:
    return SEVERITY_MAP.get(lang, {}).get(val, val)


def localize_status(val: str, lang: str = "en") -> str:
    return STATUS_MAP.get(lang, {}).get(val, val)


def localize_department(val: str, lang: str = "en") -> str:
    if not val:
        return ""
    if lang == "en":
        val_upper = val.upper()
        if "BİLGİ GÜVENLİĞİ" in val_upper or "BILGI GUVENLIGI" in val_upper or "BİLGİ GÜVENLIGI" in val_upper:
            return "Cyber Security / SOC"
        if "SİSTEM" in val_upper or "SISTEM" in val_upper:
            return "System Administration"
        if "YAZILIM" in val_upper:
            return "Software Development"
        if "VERİTABANI" in val_upper or "VERITABANI" in val_upper:
            return "Database Administration"
        if "AĞ" in val_upper or "AG" in val_upper:
            return "Network / Infrastructure"
    elif lang == "tr":
        val_upper = val.upper()
        if "CYBER" in val_upper or "SECURITY" in val_upper:
            return "Bilgi Güvenliği / SOC"
        if "SYSTEM ADMIN" in val_upper:
            return "Sistem Yönetimi"
    return DEPARTMENT_MAP.get(lang, {}).get(val, val)


def localize_page_title(val: str, lang: str = "en") -> str:
    if not val:
        return ""
    if lang == "en":
        if val.startswith("Düzenle:"):
            return val.replace("Düzenle:", "Edit:")
        val_upper = val.upper()
        if "YÖNETİCİ" in val_upper or "OPERASYON" in val_upper or "YONETICI" in val_upper:
            if "DASHBOARD" in val_upper or "PANEL" in val_upper or "VMS" in val_upper:
                return "Security Operations Dashboard"
    elif lang == "tr":
        if val.startswith("Edit:"):
            return val.replace("Edit:", "Düzenle:")
    return PAGE_TITLE_MAP.get(lang, {}).get(val, val)


def localize_user_name(val: str, lang: str = "en") -> str:
    if not val:
        return ""
    if lang == "en":
        val = val.replace("Sistem Yöneticisi", "System Administrator")
        val = val.replace("Yönetici", "Administrator")
    elif lang == "tr":
        val = val.replace("System Administrator", "Sistem Yöneticisi")
        val = val.replace("Administrator", "Yönetici")
    return USER_NAME_MAP.get(lang, {}).get(val, val)


import re

def localize_author(author: str, lang: str = "en") -> str:
    if not author:
        return ""
    if lang == "en":
        author = author.replace("OpenVAS Otomasyonu", "OpenVAS Automation")
        author = author.replace("Hızlı Senkron", "Instant Sync")
        author = author.replace("Periyodik Zamanlayıcı", "Periodic Scheduler")
        author = author.replace("Zamanlayıcı", "Scheduler")
        author = author.replace("OpenVAS Raporu", "OpenVAS Report")
        author = author.replace("Sistem Yöneticisi", "System Administrator")
    elif lang == "tr":
        author = author.replace("OpenVAS Automation", "OpenVAS Otomasyonu")
        author = author.replace("Instant Sync", "Hızlı Senkron")
        author = author.replace("Periodic Scheduler", "Periyodik Zamanlayıcı")
        author = author.replace("Scheduler", "Zamanlayıcı")
        author = author.replace("OpenVAS Report", "OpenVAS Raporu")
        author = author.replace("System Administrator", "Sistem Yöneticisi")
    return author


def localize_message(msg: str, lang: str = "en") -> str:
    if not msg:
        return ""
    if lang == "en":
        msg = re.sub(
            r'Zaafiyet (.*?) taramasından içe aktarıldı\.\s*Atanan birim:\s*(.*?)\.\s*Termin:\s*([^.]+)\.?',
            r'Vulnerability imported from \1 scan. Assigned department: \2. SLA Deadline: \3.',
            msg
        )
        msg = msg.replace("OpenSSL paketi güncellendi ve servis yeniden başlatıldı.", "OpenSSL package updated and service restarted.")
    elif lang == "tr":
        msg = re.sub(
            r'Vulnerability imported from (.*?) scan\.\s*Assigned department:\s*(.*?)\.\s*SLA Deadline:\s*([^.]+)\.?',
            r'Zaafiyet \1 taramasından içe aktarıldı. Atanan birim: \2. Termin: \3.',
            msg
        )
        msg = msg.replace("OpenSSL package updated and service restarted.", "OpenSSL paketi güncellendi ve servis yeniden başlatıldı.")
    return msg


def i18n_context_processor(request) -> Dict[str, Any]:
    """Injected automatically into all Jinja2 templates."""
    lang = get_current_lang(request)
    t_dict = get_translations(lang)
    return {
        "lang": lang,
        "T": t_dict,
        "loc_sev": lambda s: localize_severity(s, lang),
        "loc_status": lambda s: localize_status(s, lang),
        "loc_dept": lambda s: localize_department(s, lang),
        "loc_title": lambda s: localize_page_title(s, lang),
        "loc_user": lambda s: localize_user_name(s, lang),
        "loc_author": lambda s: localize_author(s, lang),
        "loc_msg": lambda s: localize_message(s, lang),
    }
