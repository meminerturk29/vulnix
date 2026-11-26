import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from datetime import datetime, timedelta
from app.database import calculate_severity_from_cvss

def infer_department_and_assignee(title: str, port: str, host: str) -> tuple:
    title_lower = title.lower()
    port_clean = port.split("/")[0].strip()

    if any(db in title_lower for db in ["sql", "postgres", "mysql", "oracle", "mongodb", "redis"]) or port_clean in ["1433", "3306", "5432", "1521", "27017", "6379"]:
        return "Database Administration", "Unassigned", ""
    elif any(net in title_lower for net in ["cisco", "vpn", "firewall", "router", "switch", "bgp", "dns", "snmp"]) or port_clean in ["53", "161", "162", "500", "4500"]:
        return "Network / Infrastructure", "Unassigned", ""
    elif any(web in title_lower for web in ["xss", "csrf", "sqli", "injection", "cors", "header", "cookie", "jwt", "spring", "struts", "laravel", "django"]):
        return "Software Development", "Unassigned", ""
    elif any(dev in title_lower for dev in ["docker", "kubernetes", "k8s", "jenkins", "gitlab", "ci/cd", "nginx"]):
        return "DevOps & Cloud", "Unassigned", ""
    else:
        return "System Administration", "Unassigned", ""

def generate_threat_assessment(title: str, severity: str, desc: str, lang: str = "en") -> str:
    combined = (title + " " + desc).lower()
    
    if lang == "tr":
        if "remote code execution" in combined or "rce" in combined or "kod yürütme" in combined:
            return "Saldırgan hedef sistem üzerinde uzaktan yetkisiz kod çalıştırabilir. Sunucu kontrolünü ele geçirerek iç ağa sıçrayabilir (lateral movement), veritabanlarına sızabilir veya fidye yazılımı (ransomware) yayabilir."
        elif "sql injection" in combined or "sqli" in combined:
            return "Saldırgan veritabanındaki tüm hassas tabloları (müşteri verileri, kimlik bilgileri, finansal kayıtlar) yetkisiz okuyabilir, değiştirebilir veya silebilir."
        elif "traversal" in combined or "file inclusion" in combined:
            return "Saldırgan sistem yapılandırma dosyalarını ve parolaları doğrudan okuyarak sunucu sırlarını ele geçirebilir ve yetki yükseltme saldırılarına zemin hazırlar."
        elif "denial of service" in combined or "dos" in combined:
            return "Saldırgan sistemin kaynaklarını tüketerek veya servisi çökerterek iş sürekliliğini durdurabilir ve şirket operasyonlarında kesintiye neden olabilir."
        elif "bypass" in combined or "authentication" in combined:
            return "Yetkisiz kişiler güvenlik kontrollerini ve kimlik doğrulamayı atlayarak yetkili kullanıcı veya yönetici panellerine izinsiz giriş yapabilir."
        elif "ssl" in combined or "tls" in combined or "cipher" in combined:
            return "Şifrelenmiş ağ trafiği ortadaki adam (MitM) saldırıları yoluyla dinlenebilir ve oturum verileri sızdırılabilir."
        elif severity in ["Kritik", "Critical"]:
            return "Sistemin bütünlüğü, gizliliği ve erişilebilirliği kritik düzeyde risk altındadır. Acil siber saldırı ve veri kaybı tehdidi bulunmaktadır."
        elif severity in ["Yüksek", "High"]:
            return "Saldırganlar bu açıklığı kullanarak şirket ağına yetkisiz erişim sağlayabilir ve kritik iş süreçlerini manipüle edebilir."
        else:
            return "Zafiyet bilgi sızmasına ve sonraki daha büyük hedefli saldırıların keşif aşamasında saldırganın işini kolaylaştırmasına neden olabilir."

    # Default to English
    if "remote code execution" in combined or "rce" in combined or "kod yürütme" in combined:
        return "An attacker could remotely execute arbitrary code on the target system without authentication. By gaining control over the host, attackers could move laterally across the internal network, compromise databases, or deploy ransomware."
    elif "sql injection" in combined or "sqli" in combined:
        return "An attacker could extract, modify, or delete sensitive database tables (credentials, customer PII, financial records). This could lead to massive data exfiltration and severe compliance violations."
    elif "traversal" in combined or "file inclusion" in combined:
        return "An attacker could directly read restricted configuration and system files (/etc/passwd, web.config, database credentials), exposing system secrets and enabling privilege escalation."
    elif "denial of service" in combined or "dos" in combined:
        return "An attacker could exhaust host resources or crash critical services, resulting in service outage and severe disruption to business continuity."
    elif "bypass" in combined or "authentication" in combined:
        return "Unauthorized parties could bypass security controls and authentication mechanisms to gain unauthorized access to administrative portals and sensitive endpoints."
    elif "ssl" in combined or "tls" in combined or "cipher" in combined:
        return "Encrypted network communication could be intercepted or decrypted via Man-in-the-Middle (MitM) attacks, leaking authentication tokens and session payloads."
    elif severity in ["Kritik", "Critical"]:
        return "System integrity, confidentiality, and availability are at critical risk. Immediate cyber attack and full compromise threat detected."
    elif severity in ["Yüksek", "High"]:
        return "Attackers could exploit this weakness to gain unauthorized access to corporate networks and manipulate sensitive business processes."
    else:
        return "The vulnerability could leak technical information, aiding attackers during the reconnaissance phase of multi-staged attacks."

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
                sev_map = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Info"}
                severity = sev_map.get(sev_num, "Info")
                cvss_score = {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Info": 0.0}.get(severity, 0.0)

            if severity in ["Info", "Bilgi"] and cvss_score == 0:
                continue

            cvss_vector_el = item.find("cvss3_vector")
            cvss_vector = cvss_vector_el.text if cvss_vector_el is not None and cvss_vector_el.text else ""

            cve_el = item.find("cve")
            cve_id = cve_el.text if cve_el is not None and cve_el.text else ""

            desc_el = item.find("description")
            description = desc_el.text if desc_el is not None and desc_el.text else "No description provided."

            sol_el = item.find("solution")
            remediation = sol_el.text if sol_el is not None and sol_el.text else "Apply official vendor security updates and review configuration."

            synopsis_el = item.find("synopsis")
            if synopsis_el is not None and synopsis_el.text:
                description = f"{synopsis_el.text}\n\n{description}"

            dept, assignee_name, assignee_email = infer_department_and_assignee(plugin_name, port_display, target_host_display)
            threat = generate_threat_assessment(plugin_name, severity, description, lang="en")

            # SLA Deadline calculation
            days_sla = {"Critical": 3, "High": 7, "Medium": 15, "Low": 30, "Kritik": 3, "Yüksek": 7, "Orta": 15, "Düşük": 30}.get(severity, 15)
            due_date = (datetime.now() + timedelta(days=days_sla)).strftime("%Y-%m-%d")

            parsed_vulns.append({
                "title": plugin_name,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "department": dept,
                "assignee_name": assignee_name,
                "assignee_email": assignee_email,
                "status": "Open",
                "due_date": due_date,
                "tool_source": "Nessus",
                "target_host": target_host_display,
                "target_port": port_display,
                "target_os": host_os or "General Server",
                "description": description.strip(),
                "threat_assessment": threat,
                "remediation": remediation.strip(),
                "cve_id": cve_id,
                "notes": f"Imported from Nessus XML (Plugin ID: {item.get('pluginID', '')})"
            })

    return parsed_vulns
