import xml.etree.ElementTree as ET
import json
import re
from typing import List, Dict, Any
from datetime import datetime, timedelta
from app.database import calculate_severity_from_cvss
from app.parsers.nessus_parser import infer_department_and_assignee, generate_threat_assessment

def parse_openvas_xml(xml_content: str, include_logs: bool = False) -> List[Dict[str, Any]]:
    """
    Parses OpenVAS / Greenbone Vulnerability Management (GVM) XML export.
    """
    parsed_vulns = []
    if not xml_content or not xml_content.strip():
        return parsed_vulns

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return parsed_vulns

    # Can be either root.findall('.//result') or root.findall('.//results/result')
    results = root.findall(".//result")

    for res in results:
        name_el = res.find("name")
        title = name_el.text if name_el is not None and name_el.text else "OpenVAS Tespit Edilen Zaafiyet"

        host_el = res.find("host")
        host = host_el.text.strip() if host_el is not None and host_el.text else "127.0.0.1"

        port_el = res.find("port")
        port = port_el.text.strip() if port_el is not None and port_el.text else "0/tcp"

        cvss_score = 0.0
        # Check direct severity, severities/severity/score, or nvt/cvss_base
        for path in ["severity", ".//severities/severity/score", ".//cvss_base", ".//severities/severity/value"]:
            node = res.find(path)
            if node is not None and node.text:
                try:
                    val = float(node.text)
                    if val > cvss_score:
                        cvss_score = val
                except ValueError:
                    pass

        threat_el = res.find("threat")
        threat_text = threat_el.text if threat_el is not None and threat_el.text else ""

        if cvss_score > 0.0:
            severity = calculate_severity_from_cvss(cvss_score)
        else:
            threat_map = {
                "High": "Yüksek", "Medium": "Orta", "Low": "Düşük",
                "Log": "Bilgi", "Alarm": "Kritik"
            }
            severity = threat_map.get(threat_text, "Bilgi" if "log" in title.lower() else "Orta")
            if severity != "Bilgi":
                cvss_score = {"Kritik": 9.5, "Yüksek": 7.5, "Orta": 5.0, "Düşük": 2.5}.get(severity, 5.0)

        # Skip log/informational if 0 score unless explicitly requested
        if not include_logs and severity == "Bilgi" and cvss_score == 0:
            continue

        desc_el = res.find("description")
        description = desc_el.text if desc_el is not None and desc_el.text else ""

        cvss_vector = ""
        remediation = "Resmi güvenlik güncellemelerini uygulayınız ve yapılandırmayı kontrol ediniz."
        tags_el = res.find(".//tags")
        if tags_el is not None and tags_el.text:
            tags_txt = tags_el.text
            m_vec = re.search(r'cvss_base_vector=([^|]+)', tags_txt)
            if m_vec:
                cvss_vector = m_vec.group(1).strip()
            if not description or len(description) < 20:
                m_sum = re.search(r'summary=([^|]+)', tags_txt)
                if m_sum:
                    description = m_sum.group(1).strip()
                m_ins = re.search(r'insight=([^|]+)', tags_txt)
                if m_ins:
                    description = (description + "\n\nDetay: " + m_ins.group(1).strip()).strip()
            m_sol = re.search(r'solution=([^|]+)', tags_txt)
            if m_sol:
                remediation = m_sol.group(1).strip()

        cve_id = ""
        cve_el = res.find(".//cve")
        if cve_el is not None and cve_el.text and cve_el.text != "NOCVE":
            cve_id = cve_el.text
        if not cve_id:
            m_cve = re.search(r'(CVE-\d{4}-\d{4,7})', title + " " + description, re.IGNORECASE)
            if m_cve:
                cve_id = m_cve.group(1).upper()

        solution_el = res.find(".//solution")
        if solution_el is not None and solution_el.text:
            remediation = solution_el.text.strip()

        dept, assignee_name, assignee_email = infer_department_and_assignee(title, port, host)
        threat_analysis = generate_threat_assessment(title, severity, description)

        days_sla = {"Kritik": 3, "Yüksek": 7, "Orta": 15, "Düşük": 30, "Bilgi": 60}.get(severity, 15)
        due_date = (datetime.now() + timedelta(days=days_sla)).strftime("%Y-%m-%d")

        parsed_vulns.append({
            "title": title,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "department": dept,
            "assignee_name": assignee_name,
            "assignee_email": assignee_email,
            "status": "Açık",
            "due_date": due_date,
            "tool_source": "OpenVAS",
            "target_host": host,
            "target_port": port,
            "target_os": "Linux/Network",
            "description": description.strip() or f"{title} zaafiyeti tespit edilmiştir.",
            "threat_assessment": threat_analysis,
            "remediation": remediation,
            "cve_id": cve_id,
            "notes": f"OpenVAS raporundan aktarıldı (ID: {res.get('id', '')})"
        })

    return parsed_vulns

def parse_generic_json(json_content: str) -> List[Dict[str, Any]]:
    """
    Parses OpenVAS/Custom JSON vulnerability exports.
    """
    data = json.loads(json_content)
    parsed_vulns = []
    items = data if isinstance(data, list) else data.get("vulnerabilities", data.get("results", []))

    for item in items:
        title = item.get("title", item.get("name", "Bilinmeyen Zaafiyet"))
        score = float(item.get("cvss_score", item.get("severity_score", 5.0)))
        severity = item.get("severity") or calculate_severity_from_cvss(score)
        port = str(item.get("target_port", item.get("port", "443/tcp")))
        host = str(item.get("target_host", item.get("host", "127.0.0.1")))

        dept, assignee_name, assignee_email = infer_department_and_assignee(title, port, host)
        threat = item.get("threat_assessment") or generate_threat_assessment(title, severity, item.get("description", ""))

        days_sla = {"Kritik": 3, "Yüksek": 7, "Orta": 15, "Düşük": 30}.get(severity, 15)
        due_date = item.get("due_date") or (datetime.now() + timedelta(days=days_sla)).strftime("%Y-%m-%d")

        parsed_vulns.append({
            "title": title,
            "severity": severity,
            "cvss_score": score,
            "cvss_vector": item.get("cvss_vector", ""),
            "department": item.get("department", dept),
            "assignee_name": item.get("assignee_name", assignee_name),
            "assignee_email": item.get("assignee_email", assignee_email),
            "status": item.get("status", "Açık"),
            "due_date": due_date,
            "tool_source": item.get("tool_source", "OpenVAS / API"),
            "target_host": host,
            "target_port": port,
            "target_os": item.get("target_os", "Bilinmeyen İşletim Sistemi"),
            "description": item.get("description", "Açıklama belirtilmedi."),
            "threat_assessment": threat,
            "remediation": item.get("remediation", "Sistem güncellemelerini uygulayınız."),
            "cve_id": item.get("cve_id", ""),
            "notes": item.get("notes", "JSON aktarımı ile eklendi.")
        })

    return parsed_vulns
