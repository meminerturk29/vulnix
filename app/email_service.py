import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
from app.database import get_db_connection


def get_setting(key: str, default: str = "") -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row and row[0] is not None else default


def send_email(
    to_email: str,
    to_name: str,
    subject: str,
    html_content: str,
    vuln_id: Optional[int] = None,
    sender_user_id: Optional[int] = None
) -> Tuple[bool, str]:
    """
    Sends a real email using configured SMTP settings (or records to outbox if SMTP not configured).
    Returns (success: bool, message: str)
    """
    smtp_host = get_setting("smtp_host", "").strip()
    smtp_port_str = get_setting("smtp_port", "587").strip()
    smtp_port = int(smtp_port_str) if smtp_port_str.isdigit() else 587
    smtp_user = get_setting("smtp_user", "").strip()
    smtp_pass = get_setting("smtp_pass", "").strip()
    smtp_from = get_setting("smtp_from", "").strip() or f"VMS Zaafiyet Bildirim <{smtp_user or 'noreply@sirket.com'}>"
    smtp_tls = get_setting("smtp_tls", "1") == "1"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # If no SMTP host is configured yet, safely store in database outbox and inform user
    if not smtp_host:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO email_logs (vuln_id, sent_by_user_id, recipient_email, recipient_name, subject, body, status, error_message, sent_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln_id,
            sender_user_id,
            to_email,
            to_name,
            subject,
            html_content,
            "Outbox (SMTP Yapılandırılmadı)",
            "Ayarlar menüsünden gerçek SMTP sunucu adresi ve kimlik bilgileri girildiğinde e-postalar doğrudan alıcıya iletilecektir.",
            now_str
        ))
        conn.commit()
        conn.close()
        return True, "E-posta Outbox'a kaydedildi (SMTP sunucusu henüz ayarlanmadı)."

    # Live Real SMTP Sending
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = f"{to_name} <{to_email}>"

        part = MIMEText(html_content, "html", "utf-8")
        msg.attach(part)

        if smtp_port == 465:
            # SSL
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=12)
        else:
            # Standard / STARTTLS
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=12)
            if smtp_tls:
                server.starttls()

        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)

        server.sendmail(smtp_from, [to_email], msg.as_string())
        server.quit()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO email_logs (vuln_id, sent_by_user_id, recipient_email, recipient_name, subject, body, status, error_message, sent_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln_id,
            sender_user_id,
            to_email,
            to_name,
            subject,
            html_content,
            "SENT (SMTP Başarılı)",
            "",
            now_str
        ))
        conn.commit()
        conn.close()
        return True, f"E-posta {to_email} adresine SMTP sunucusu üzerinden başarıyla gönderildi."

    except Exception as e:
        err_msg = str(e)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO email_logs (vuln_id, sent_by_user_id, recipient_email, recipient_name, subject, body, status, error_message, sent_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln_id,
            sender_user_id,
            to_email,
            to_name,
            subject,
            html_content,
            "FAILED",
            err_msg,
            now_str
        ))
        conn.commit()
        conn.close()
        return False, f"SMTP İletim Hatası: {err_msg}"


def render_vulnerability_email_template(vuln: Dict[str, Any], action_title: str, base_url: str) -> str:
    severity_colors = {
        "Kritik": "#dc2626",
        "Yüksek": "#ea580c",
        "Orta": "#ca8a04",
        "Düşük": "#2563eb",
        "Bilgi": "#4b5563"
    }
    sev_color = severity_colors.get(vuln.get("severity", "Orta"), "#ea580c")
    vuln_url = f"{base_url}/vulnerabilities/{vuln.get('id')}"

    return f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
      <meta charset="UTF-8">
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0f172a; margin: 0; padding: 20px; }}
        .card {{ max-width: 650px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }}
        .header {{ background-color: #020617; color: #ffffff; padding: 24px; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 9999px; font-weight: 700; font-size: 13px; color: #ffffff; background-color: {sev_color}; }}
        .content {{ padding: 24px; color: #1e293b; font-size: 14px; line-height: 1.6; }}
        .table-info {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
        .table-info td {{ padding: 8px 12px; border-bottom: 1px solid #f1f5f9; }}
        .table-info td.label {{ font-weight: 600; color: #64748b; width: 35%; }}
        .section-box {{ background: #f8fafc; border-left: 4px solid #0284c7; padding: 12px 16px; margin: 16px 0; border-radius: 0 8px 8px 0; }}
        .section-box.threat {{ border-left-color: #dc2626; background: #fef2f2; }}
        .btn {{ display: inline-block; padding: 12px 24px; background-color: #0284c7; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; margin-top: 15px; }}
        .footer {{ padding: 16px 24px; background: #f8fafc; font-size: 12px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <div style="font-size: 12px; color: #38bdf8; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;">Kurumsal Zaafiyet Yönetim Sistemi</div>
          <h2 style="margin: 8px 0 0 0; font-size: 20px;">{action_title}</h2>
        </div>
        <div class="content">
          <p>Merhaba <strong>{vuln.get('assignee_name')}</strong>,</p>
          <p>Aşağıda belirtilen güvenlik zaafiyeti sorumlu olduğunuz <strong>{vuln.get('department')}</strong> birimine atanmıştır:</p>

          <table class="table-info">
            <tr>
              <td class="label">Kayıt No:</td>
              <td><strong>{vuln.get('record_no')}</strong></td>
            </tr>
            <tr>
              <td class="label">Zaafiyet Başlığı:</td>
              <td><strong>{vuln.get('title')}</strong></td>
            </tr>
            <tr>
              <td class="label">Seviye / Risk:</td>
              <td><span class="badge">{vuln.get('severity')} (CVSS: {vuln.get('cvss_score')})</span></td>
            </tr>
            <tr>
              <td class="label">Hedef Cihaz:</td>
              <td><code>{vuln.get('target_host')}</code> : <code>{vuln.get('target_port')}</code></td>
            </tr>
            <tr>
              <td class="label">Tarama Aracı:</td>
              <td>{vuln.get('tool_source')}</td>
            </tr>
            <tr>
              <td class="label">Termin (SLA):</td>
              <td><strong style="color: #dc2626;">{vuln.get('due_date')}</strong></td>
            </tr>
            <tr>
              <td class="label">Durum:</td>
              <td><strong>{vuln.get('status')}</strong></td>
            </tr>
          </table>

          <div class="section-box threat">
            <h4 style="margin: 0 0 6px 0; color: #991b1b;">⚠️ Tehdit Değerlendirmesi (Eğer Hacklenirse):</h4>
            <p style="margin: 0;">{vuln.get('threat_assessment')}</p>
          </div>

          <div class="section-box">
            <h4 style="margin: 0 0 6px 0; color: #0369a1;">🛠️ Remediation / Açığı Kapatma Önerisi:</h4>
            <p style="margin: 0;">{vuln.get('remediation')}</p>
          </div>

          <p style="margin-top: 20px; text-align: center;">
            <a href="{vuln_url}" class="btn">Zaafiyeti İncele ve Müdahale Et &rarr;</a>
          </p>
        </div>
        <div class="footer">
          Bu bildirim Kurumsal Zaafiyet Yönetim Sistemi (VMS) tarafından otomatik olarak üretilmiştir.<br>
          Lütfen belirlenen <strong>Termin: {vuln.get('due_date')}</strong> tarihine kadar gerekli aksiyonları alınız.
        </div>
      </div>
    </body>
    </html>
    """


def notify_assignee_about_vulnerability(vuln: Dict[str, Any], base_url: str = "http://localhost:8000", sender_user_id: Optional[int] = None) -> Tuple[bool, str]:
    subject = f"[{vuln.get('severity').upper()}] Zaafiyet Ataması: {vuln.get('record_no')} - {vuln.get('title')}"
    html = render_vulnerability_email_template(vuln, "Yeni Güvenlik Zaafiyeti Bildirimi", base_url)
    return send_email(
        to_email=vuln.get("assignee_email"),
        to_name=vuln.get("assignee_name"),
        subject=subject,
        html_content=html,
        vuln_id=vuln.get("id"),
        sender_user_id=sender_user_id
    )


def notify_sla_reminder(vuln: Dict[str, Any], base_url: str = "http://localhost:8000", sender_user_id: Optional[int] = None) -> Tuple[bool, str]:
    subject = f"[TERMİN HATIRLATMASI] {vuln.get('record_no')} - Hedef Termin: {vuln.get('due_date')}"
    html = render_vulnerability_email_template(vuln, "Termin (SLA) Randevu Hatırlatması", base_url)
    return send_email(
        to_email=vuln.get("assignee_email"),
        to_name=vuln.get("assignee_name"),
        subject=subject,
        html_content=html,
        vuln_id=vuln.get("id"),
        sender_user_id=sender_user_id
    )
