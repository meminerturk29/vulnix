import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from datetime import datetime, timedelta
from app.database import calculate_severity_from_cvss

def infer_department_and_assignee(title: str, port: str, host: str) -> tuple:
    title_lower = title.lower()
    port_clean = port.split("/")[0].strip()

    if any(db in title_lower for db in ["sql", "postgres", "mysql", "oracle", "mongodb", "redis"]) or port_clean in ["1433", "3306", "5432", "1521", "27017", "6379"]:
        return "Veritabanı Yönetimi", "Canan Kaya", "canan.kaya@sirket.com"
    elif any(net in title_lower for net in ["cisco", "vpn", "firewall", "router", "switch", "bgp", "dns", "snmp"]) or port_clean in ["53", "161", "162", "500", "4500"]:
        return "Network/Ağ Güvenliği", "Deniz Arslan", "deniz.arslan@sirket.com"
    elif any(web in title_lower for web in ["xss", "csrf", "sqli", "injection", "cors", "header", "cookie", "jwt", "spring", "struts", "laravel", "django"]):
        return "Yazılım Geliştirme", "Ahmet Yılmaz", "ahmet.yilmaz@sirket.com"
    elif any(dev in title_lower for dev in ["docker", "kubernetes", "k8s", "jenkins", "gitlab", "ci/cd", "nginx"]):
        return "DevOps", "Eren Yıldız", "eren.yildiz@sirket.com"
    else:
        return "Sistem Yönetimi", "Burak Demir", "burak.demir@sirket.com"

def generate_threat_assessment(title: str, severity: str, desc: str) -> str:
    combined = (title + " " + desc).lower()
    if "remote code execution" in combined or "rce" in combined or "kod yürütme" in combined:
        return "Saldırgan hedef sistem üzerinde uzaktan yetkisiz kod çalıştırabilir. Sunucu kontrolünü ele geçirerek iç ağa sıçrayabilir (lateral movement), veri tabanlarına sızabilir veya ransomware yayabilir."
    elif "sql injection" in combined or "sqli" in combined:
        return "Saldırgan veritabanındaki tüm hassas tabloları (müşteri verileri, kimlik bilgileri, finansal kayıtlar) yetkisiz okuyabilir, değiştirebilir veya silebilir. Veri sızıntısı ve KVKK cezalarına yol açar."
    elif "traversal" in combined or "file inclusion" in combined:
        return "Saldırgan sistem dosyalarını (/etc/passwd, web.config, veritabanı parolaları) doğrudan okuyarak sunucu sırlarını ele geçirebilir ve yetki yükseltme saldırılarına zemin hazırlar."
    elif "denial of service" in combined or "dos" in combined:
        return "Saldırgan sistemin kaynaklarını tüketerek veya servisi çökerterek iş sürekliliğini durdurabilir ve şirket operasyonlarında kesintiye neden olabilir."
    elif "bypass" in combined or "authentication" in combined:
        return "Yetkisiz kişiler güvenlik kontrollerini ve kimlik doğrulamayı atlayarak yetkili kullanıcı veya yönetici panellerine izinsiz giriş yapabilir."
    elif "ssl" in combined or "tls" in combined or "cipher" in combined:
        return "Şifrelenmiş ağ trafiği ortadaki adam (MitM) saldırıları veya kriptografik açıklar yoluyla dinlenebilir ve oturum verileri sızdırılabilir."
    elif severity == "Kritik":
        return "Sistemin bütünlüğü, gizliliği ve erişilebilirliği kritik düzeyde risk altındadır. Acil siber saldırı ve veri kaybı tehdidi bulunmaktadır."
    elif severity == "Yüksek":
        return "Saldırganlar bu açıklığı kullanarak şirket ağına yetkisiz erişim sağlayabilir ve hassas iş süreçlerini manipüle edebilir."
    else:
        return "Zafiyet bilgi sızmasına ve sonraki daha büyük hedefli saldırıların keşif aşamasında saldırganın işini kolaylaştırmasına neden olabilir."

def parse_nessus_xml(xml_content: str) -> List[Dict[str, Any]]:
    """
    Parses Nessus XML file content and returns list of vulnerability dictionaries.
    """
    root = ET.fromstring(xml_content)
    parsed_vulns = []

    for host in root.findall(".//ReportHost"):
        host_name = host.get("name", "Unknown Host")
        host_ip = host_name
        host_os = ""

        # Extract host properties
        for tag in host.findall(".//HostProperties/tag"):
            tag_name = tag.get("name")
            if tag_name == "host-ip":
                host_ip = tag.text or host_ip
            elif tag_name == "operating-system":
                host_os = tag.text or ""

        target_host_display = f"{host_ip} ({host_name})" if host_name != host_ip else host_ip

        for item in host.findall(".//ReportItem"):
            plugin_name = item.get("pluginName", "Unnamed Vulnerability")
            port = item.get("port", "0")
            protocol = item.get("protocol", "tcp").upper()
            port_display = f"{port}/{protocol}"

            # Scores and vectors
            cvss3_score_el = item.find("cvss3_base_score")
            cvss2_score_el = item.find("cvss_base_score")
            cvss_score = 0.0

            if cvss3_score_el is not None and cvss3_score_el.text:
                try:
                    cvss_score = float(cvss3_score_el.text)
                except ValueError:
                    pass
            elif cvss2_score_el is not None and cvss2_score_el.text:
                try:
                    cvss_score = float(cvss2_score_el.text)
                except ValueError:
                    pass

            # Severity calculation
            sev_num = item.get("severity", "0")
            if cvss_score > 0.0:
                severity = calculate_severity_from_cvss(cvss_score)
            else:
                sev_map = {"4": "Kritik", "3": "Yüksek", "2": "Orta", "1": "Düşük", "0": "Bilgi"}
                severity = sev_map.get(sev_num, "Bilgi")
                cvss_score = {"Kritik": 9.5, "Yüksek": 7.5, "Orta": 5.0, "Düşük": 2.5, "Bilgi": 0.0}.get(severity, 0.0)

            # Skip pure Informational if gewünscht, but let's keep Low/Medium/High/Critical
            if severity == "Bilgi" and cvss_score == 0:
                continue

            cvss_vector_el = item.find("cvss3_vector")
            cvss_vector = cvss_vector_el.text if cvss_vector_el is not None and cvss_vector_el.text else ""

            cve_el = item.find("cve")
            cve_id = cve_el.text if cve_el is not None and cve_el.text else ""

            desc_el = item.find("description")
            description = desc_el.text if desc_el is not None and desc_el.text else "Açıklama belirtilmedi."

            sol_el = item.find("solution")
            remediation = sol_el.text if sol_el is not None and sol_el.text else "Resmi üretici güvenlik yamalarını uygulayınız."

            synopsis_el = item.find("synopsis")
            if synopsis_el is not None and synopsis_el.text:
                description = f"{synopsis_el.text}\n\n{description}"

            dept, assignee_name, assignee_email = infer_department_and_assignee(plugin_name, port_display, target_host_display)
            threat = generate_threat_assessment(plugin_name, severity, description)

            # SLA Termin calculation
            days_sla = {"Kritik": 3, "Yüksek": 7, "Orta": 15, "Düşük": 30}.get(severity, 15)
            due_date = (datetime.now() + timedelta(days=days_sla)).strftime("%Y-%m-%d")

            parsed_vulns.append({
                "title": plugin_name,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "department": dept,
                "assignee_name": assignee_name,
                "assignee_email": assignee_email,
                "status": "Açık",
                "due_date": due_date,
                "tool_source": "Nessus",
                "target_host": target_host_display,
                "target_port": port_display,
                "target_os": host_os or "Linux/Windows",
                "description": description.strip(),
                "threat_assessment": threat,
                "remediation": remediation.strip(),
                "cve_id": cve_id,
                "notes": f"Nessus otomatik taramasından aktarıldı (Plugin ID: {item.get('pluginID', '')})"
            })

    return parsed_vulns
