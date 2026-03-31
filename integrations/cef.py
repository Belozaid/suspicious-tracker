# integrations/cef.py
import json
from typing import Dict, Any

def to_cef(event: Dict[str, Any]) -> str:
    """
    تحويل حادثة (Incident) إلى صيغة CEF (Common Event Format).
    CEF:0|Vendor|Product|Version|Signature|Name|Severity| extension
    """
    vendor = "PRO"
    product = "SuspiciousTracker"
    version = event.get("app_version", "1.0.0")

    # Signature ID (يفضل أن يكون MITRE Technique ID)
    sig = event.get("mitre_technique_id", event.get("scenario_name", "GENERIC"))
    name = event.get("title", "Security Incident").replace('|', '/')  # CEF لا يقبل الرمز |
    threat_score = int(event.get("threat_score", 50))
    # تحويل درجة التهديد 0-100 إلى مستوى خطورة CEF 0-10
    severity_cef = max(0, min(10, round(threat_score / 10)))

    # بناء حقل الامتداد (Extension)
    ext_parts = []
    ext_parts.append(f"incidentId={event.get('incident_id')}")
    ext_parts.append(f"severityLabel={event.get('severity', 'UNKNOWN')}")
    ext_parts.append(f"mitreTactic={event.get('mitre_tactic', '')}")
    ext_parts.append(f"scenario={event.get('scenario_name', '')}")
    ext_parts.append(f"confidence={event.get('confidence', '')}")
    ext_parts.append(f"start={event.get('start_ts_utc', '')}")
    ext_parts.append(f"lastUpdate={event.get('last_update_ts_utc', '')}")
    # إزالة أي قيم None
    ext = " ".join([p for p in ext_parts if p and not p.endswith('=')])

    return f"CEF:0|{vendor}|{product}|{version}|{sig}|{name}|{severity_cef}|{ext}\n"