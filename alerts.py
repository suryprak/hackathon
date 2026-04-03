"""
Alert generation and scenario data for the SOC Alert Triage Environment.

Generates realistic SIEM-style security alerts with ground truth labels
for grading agent performance.
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4


# ---------------------------------------------------------------------------
# Alert templates — each template includes ground truth for grading
# ---------------------------------------------------------------------------

ALERT_TEMPLATES: List[Dict[str, Any]] = [
    # --- TRUE POSITIVES ---
    {
        "alert_type": "Malware Detected",
        "source": "Endpoint Detection (EDR)",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001 - PowerShell",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "critical",
            "category": "malware",
            "assigned_team": "malware_ops",
            "recommended_action": "isolate_host",
        },
        "description": "EDR detected execution of obfuscated PowerShell script downloading payload from external C2 server {c2_ip}. Process tree: explorer.exe → cmd.exe → powershell.exe. Hash {hash} matches known malware family.",
        "raw_log": 'process_name="powershell.exe" cmdline="-enc {encoded_cmd}" parent="cmd.exe" user="{user}" host="{host}" dest_ip="{c2_ip}"',
    },
    {
        "alert_type": "Brute Force Login Attempt",
        "source": "SIEM Correlation Rule",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001 - Password Guessing",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "high",
            "category": "brute_force",
            "assigned_team": "identity_security",
            "recommended_action": "reset_credentials",
        },
        "description": "Detected {count} failed login attempts to account '{user}' from IP {src_ip} within 5 minutes, followed by a successful login. Source IP geolocated to {country}.",
        "raw_log": 'EventID=4625 count={count} user="{user}" src_ip="{src_ip}" success_after_failures=true geo="{country}"',
    },
    {
        "alert_type": "Data Exfiltration via DNS",
        "source": "Network Traffic Analysis",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048.003 - Exfiltration Over DNS",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "critical",
            "category": "data_exfiltration",
            "assigned_team": "data_protection",
            "recommended_action": "isolate_host",
        },
        "description": "Anomalous DNS query volume detected from host {host}. {dns_count} unique subdomain queries to domain '{malicious_domain}' in 10 minutes. Average query length {avg_len} chars — consistent with DNS tunneling.",
        "raw_log": 'dns_queries={dns_count} domain="{malicious_domain}" src_host="{host}" avg_query_len={avg_len} bytes_estimated={bytes_est}',
    },
    {
        "alert_type": "Suspicious Lateral Movement",
        "source": "Active Directory Monitoring",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021.002 - SMB/Windows Admin Shares",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "high",
            "category": "lateral_movement",
            "assigned_team": "network_security",
            "recommended_action": "isolate_host",
        },
        "description": "Service account '{user}' authenticated to {target_count} hosts via SMB within 3 minutes. Source host {host} has no prior history of lateral connections. Admin share \\\\{target}\\C$ accessed.",
        "raw_log": 'EventID=4624 LogonType=3 user="{user}" src="{host}" targets={target_count} protocol=SMB share="\\\\{target}\\C$"',
    },
    {
        "alert_type": "Phishing Email Delivered",
        "source": "Email Security Gateway",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1566.001 - Spearphishing Attachment",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "high",
            "category": "phishing",
            "assigned_team": "threat_intel",
            "recommended_action": "escalate",
        },
        "description": "Email from '{sender}' to '{recipient}' delivered with suspicious attachment '{attachment}'. Sender domain registered {days_ago} days ago. URL in body resolves to IP {dest_ip} flagged by threat intel.",
        "raw_log": 'from="{sender}" to="{recipient}" subject="{subject}" attachment="{attachment}" sender_domain_age={days_ago}d url_ip="{dest_ip}" verdict=suspicious',
    },
    {
        "alert_type": "Reconnaissance - Port Scan",
        "source": "Network IDS",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Scanning",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "medium",
            "category": "reconnaissance",
            "assigned_team": "network_security",
            "recommended_action": "block_ip",
        },
        "description": "Host {src_ip} scanned {port_count} ports on subnet {subnet} in 60 seconds. SYN scan pattern detected targeting common service ports (22, 80, 443, 3389, 8080).",
        "raw_log": 'src_ip="{src_ip}" dest_subnet="{subnet}" ports_scanned={port_count} scan_type=SYN duration=60s top_ports="22,80,443,3389,8080"',
    },
    {
        "alert_type": "Insider Threat - Bulk File Download",
        "source": "DLP / CASB",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1530 - Data from Cloud Storage",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "high",
            "category": "insider_threat",
            "assigned_team": "data_protection",
            "recommended_action": "escalate",
        },
        "description": "User '{user}' downloaded {file_count} files ({total_size} MB) from SharePoint '{site}' in 15 minutes. This is {multiplier}x their normal daily download volume. User submitted resignation last week.",
        "raw_log": 'user="{user}" action=FileDownloaded count={file_count} total_mb={total_size} site="{site}" baseline_ratio={multiplier}x hr_flag=resignation_pending',
    },
    {
        "alert_type": "Denial of Service - SYN Flood",
        "source": "Network Monitoring",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499.001 - OS Exhaustion Flood",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "critical",
            "category": "denial_of_service",
            "assigned_team": "network_security",
            "recommended_action": "block_ip",
        },
        "description": "SYN flood detected targeting web server {target_ip}:{target_port}. {pps} packets/sec from {src_count} source IPs. Server response time degraded from {normal_ms}ms to {degraded_ms}ms.",
        "raw_log": 'type=SYN_FLOOD target="{target_ip}:{target_port}" pps={pps} src_ips={src_count} resp_time_ms={degraded_ms} baseline_ms={normal_ms}',
    },
    # --- FALSE POSITIVES ---
    {
        "alert_type": "Suspicious Login from New Location",
        "source": "Identity Protection",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "ground_truth": {
            "classification": "false_positive",
            "severity": "low",
            "category": "brute_force",
            "assigned_team": "identity_security",
            "recommended_action": "close",
        },
        "description": "User '{user}' logged in from {city}, {country} — a location not seen in the last 90 days. Login was via corporate VPN endpoint. User's calendar shows business travel to {city} this week.",
        "raw_log": 'EventID=4624 user="{user}" src_ip="{src_ip}" geo="{city}, {country}" vpn=true travel_calendar=confirmed',
    },
    {
        "alert_type": "High Volume Outbound Transfer",
        "source": "Network DLP",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "ground_truth": {
            "classification": "false_positive",
            "severity": "low",
            "category": "data_exfiltration",
            "assigned_team": "data_protection",
            "recommended_action": "close",
        },
        "description": "Host {host} transferred {size_gb} GB to cloud storage endpoint {dest}. Transfer matches scheduled nightly backup job 'backup_{service}' running under service account '{user}'.",
        "raw_log": 'src="{host}" dest="{dest}" bytes={size_gb}GB protocol=HTTPS scheduled_task="backup_{service}" user="{user}" type=service_account',
    },
    {
        "alert_type": "Abnormal Process Execution",
        "source": "Endpoint Detection (EDR)",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059 - Command and Scripting Interpreter",
        "ground_truth": {
            "classification": "false_positive",
            "severity": "low",
            "category": "malware",
            "assigned_team": "malware_ops",
            "recommended_action": "close",
        },
        "description": "Unusual process 'custom_tool.exe' executed by '{user}' on {host}. Binary is unsigned. Investigation: tool is an approved internal DevOps utility deployed via SCCM last Tuesday.",
        "raw_log": 'process="custom_tool.exe" user="{user}" host="{host}" signed=false sccm_deployed=true approval_ticket=INC{ticket_id}',
    },
    {
        "alert_type": "Vulnerability Scanner Traffic",
        "source": "Network IDS",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Scanning",
        "ground_truth": {
            "classification": "false_positive",
            "severity": "low",
            "category": "reconnaissance",
            "assigned_team": "network_security",
            "recommended_action": "close",
        },
        "description": "Large number of connection attempts from {src_ip} to multiple hosts on {subnet}. Source IP belongs to scheduled Qualys vulnerability scanner. Scan window: {start_time}–{end_time}.",
        "raw_log": 'src_ip="{src_ip}" type=vuln_scan scanner=Qualys schedule=weekly subnet="{subnet}" window="{start_time}-{end_time}"',
    },
    # --- BENIGN / SUSPICIOUS ---
    {
        "alert_type": "Failed Login - Locked Account",
        "source": "Active Directory",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
        "ground_truth": {
            "classification": "benign",
            "severity": "low",
            "category": "brute_force",
            "assigned_team": "identity_security",
            "recommended_action": "close",
        },
        "description": "Account '{user}' locked after {count} failed attempts. Source is the user's assigned workstation {host}. User called helpdesk reporting forgotten password after vacation.",
        "raw_log": 'EventID=4740 user="{user}" src="{host}" failures={count} helpdesk_ticket=true reason=forgotten_password',
    },
    {
        "alert_type": "Suspicious Outbound Connection",
        "source": "Firewall",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071.001 - Web Protocols",
        "ground_truth": {
            "classification": "suspicious",
            "severity": "medium",
            "category": "malware",
            "assigned_team": "threat_intel",
            "recommended_action": "monitor",
        },
        "description": "Host {host} made HTTPS connections to IP {dest_ip} on port 8443. IP has low reputation score ({rep_score}/100) but no confirmed malicious activity. Connections occur every 30 minutes — possible beaconing.",
        "raw_log": 'src="{host}" dest="{dest_ip}:8443" proto=HTTPS interval=30m rep_score={rep_score} category=uncategorized beacon_pattern=possible',
    },
]

# ---------------------------------------------------------------------------
# Kill-chain campaign template for Task 3
# ---------------------------------------------------------------------------

CAMPAIGN_CHAIN: List[Dict[str, Any]] = [
    {
        "alert_type": "Phishing Email Delivered",
        "source": "Email Security Gateway",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1566.001 - Spearphishing Attachment",
        "chain_position": 1,
        "chain_label": "initial_access",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "high",
            "category": "phishing",
            "assigned_team": "threat_intel",
            "recommended_action": "escalate",
        },
        "description": "Spearphishing email from '{sender}' delivered to '{recipient}' with weaponized document '{attachment}'. Sender domain mimics legitimate vendor '{legit_vendor}'.",
        "raw_log": 'from="{sender}" to="{recipient}" attachment="{attachment}" domain_squatting="{legit_vendor}" delivery=success',
    },
    {
        "alert_type": "Malicious Macro Execution",
        "source": "Endpoint Detection (EDR)",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.005 - Visual Basic",
        "chain_position": 2,
        "chain_label": "execution",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "critical",
            "category": "malware",
            "assigned_team": "malware_ops",
            "recommended_action": "isolate_host",
        },
        "description": "VBA macro executed from '{attachment}' on host {host}. Macro spawned cmd.exe which launched certutil.exe to download secondary payload from {c2_ip}.",
        "raw_log": 'process_tree="WINWORD.EXE→cmd.exe→certutil.exe" host="{host}" user="{recipient}" download_url="http://{c2_ip}/update.exe"',
    },
    {
        "alert_type": "Credential Dumping Detected",
        "source": "Endpoint Detection (EDR)",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003.001 - LSASS Memory",
        "chain_position": 3,
        "chain_label": "credential_access",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "critical",
            "category": "lateral_movement",
            "assigned_team": "identity_security",
            "recommended_action": "reset_credentials",
        },
        "description": "Process 'rundll32.exe' accessed lsass.exe memory on host {host}. Credential dumping tool signatures match Mimikatz variant. {cred_count} credential sets potentially harvested.",
        "raw_log": 'process="rundll32.exe" target="lsass.exe" host="{host}" tool_sig=mimikatz_variant creds_accessed={cred_count}',
    },
    {
        "alert_type": "Lateral Movement via PsExec",
        "source": "Active Directory / EDR",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021.002 - SMB/Windows Admin Shares",
        "chain_position": 4,
        "chain_label": "lateral_movement",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "high",
            "category": "lateral_movement",
            "assigned_team": "network_security",
            "recommended_action": "isolate_host",
        },
        "description": "Compromised account '{stolen_user}' used PsExec to execute commands on {target_count} hosts from {host}. Targets include domain controller {dc_host}.",
        "raw_log": 'tool=PsExec user="{stolen_user}" src="{host}" targets={target_count} dc_access=true dc_host="{dc_host}"',
    },
    {
        "alert_type": "Data Staged for Exfiltration",
        "source": "DLP / File Integrity Monitoring",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1074.001 - Local Data Staging",
        "chain_position": 5,
        "chain_label": "exfiltration",
        "ground_truth": {
            "classification": "true_positive",
            "severity": "critical",
            "category": "data_exfiltration",
            "assigned_team": "data_protection",
            "recommended_action": "isolate_host",
        },
        "description": "Large archive file '{archive}' ({archive_size} MB) created in temp directory on {dc_host}. File contains {doc_count} sensitive documents. Outbound transfer initiated to {exfil_ip} via HTTPS.",
        "raw_log": 'file="{archive}" size_mb={archive_size} path="C:\\Temp" host="{dc_host}" docs={doc_count} exfil_dest="{exfil_ip}" proto=HTTPS',
    },
]


# ---------------------------------------------------------------------------
# Helper: random data values for template filling
# ---------------------------------------------------------------------------

_INTERNAL_IPS = ["10.1.5.23", "10.1.8.104", "10.2.3.55", "10.1.12.77", "10.3.1.200"]
_EXTERNAL_IPS = ["185.234.72.19", "91.203.145.33", "45.77.65.211", "103.25.41.8", "198.51.100.44"]
_HOSTNAMES = ["WS-FIN-042", "WS-HR-015", "SRV-DB-01", "WS-DEV-088", "WS-EXEC-003", "SRV-WEB-02", "WS-MKT-019"]
_USERS = ["jsmith", "agarcia", "bwilson", "clee", "dkumar", "emartinez", "fchen"]
_SERVICE_ACCOUNTS = ["svc_backup", "svc_deploy", "svc_monitor", "svc_scanner"]
_COUNTRIES = ["Russia", "China", "Iran", "North Korea", "Nigeria", "Brazil"]
_CITIES = ["London", "Tokyo", "Sydney", "São Paulo", "Berlin"]
_DOMAINS = ["evil-update.com", "cdn-service-x.net", "api-analytics-corp.io", "secure-docs.xyz"]
_SUBNETS = ["10.1.5.0/24", "10.2.0.0/16", "172.16.10.0/24", "10.3.1.0/24"]
_VENDORS = ["Contoso", "Fabrikam", "Northwind", "AdventureWorks"]
_ATTACHMENTS = ["Invoice_Q4_2025.xlsm", "Project_Update.docm", "HR_Benefits_2026.xlsm", "BoardReport_Draft.docm"]
_SUBJECTS = ["Urgent: Invoice Payment Required", "FW: Updated Project Docs", "Action Needed: Benefits Enrollment", "RE: Board Meeting Prep"]


def _fill_template(template: Dict[str, Any], rng: random.Random) -> Dict[str, Any]:
    """Fill a template's description and raw_log with random realistic values."""
    vals = {
        "c2_ip": rng.choice(_EXTERNAL_IPS),
        "hash": rng.randbytes(8).hex(),
        "encoded_cmd": "SQBFAFgAIAAoA" + rng.randbytes(6).hex(),
        "user": rng.choice(_USERS),
        "host": rng.choice(_HOSTNAMES),
        "src_ip": rng.choice(_EXTERNAL_IPS),
        "dest_ip": rng.choice(_EXTERNAL_IPS),
        "count": rng.randint(15, 200),
        "country": rng.choice(_COUNTRIES),
        "city": rng.choice(_CITIES),
        "subnet": rng.choice(_SUBNETS),
        "port_count": rng.randint(100, 2000),
        "dns_count": rng.randint(500, 5000),
        "malicious_domain": rng.choice(_DOMAINS),
        "avg_len": rng.randint(40, 180),
        "bytes_est": rng.randint(50000, 500000),
        "target_count": rng.randint(3, 15),
        "target": rng.choice(_HOSTNAMES),
        "sender": f"{rng.choice(_USERS)}@{rng.choice(_DOMAINS)}",
        "recipient": f"{rng.choice(_USERS)}@company.com",
        "attachment": rng.choice(_ATTACHMENTS),
        "subject": rng.choice(_SUBJECTS),
        "days_ago": rng.randint(1, 7),
        "file_count": rng.randint(50, 500),
        "total_size": rng.randint(100, 5000),
        "multiplier": rng.randint(5, 50),
        "site": f"Finance-{rng.choice(['Q1', 'Q2', 'Q3', 'Q4'])}-Reports",
        "service": rng.choice(["db", "sharepoint", "exchange", "archive"]),
        "dest": rng.choice(["backup-azure.blob.core.windows.net", "s3-backup-prod.amazonaws.com"]),
        "size_gb": rng.randint(5, 100),
        "ticket_id": rng.randint(100000, 999999),
        "start_time": "02:00",
        "end_time": "04:00",
        "rep_score": rng.randint(15, 45),
        "pps": rng.randint(10000, 100000),
        "src_count": rng.randint(50, 500),
        "target_ip": rng.choice(_INTERNAL_IPS),
        "target_port": rng.choice([80, 443, 8080]),
        "normal_ms": rng.randint(5, 20),
        "degraded_ms": rng.randint(2000, 10000),
        "legit_vendor": rng.choice(_VENDORS),
        "stolen_user": rng.choice(_SERVICE_ACCOUNTS),
        "dc_host": "DC-PROD-01",
        "cred_count": rng.randint(5, 30),
        "archive": f"backup_{rng.randbytes(3).hex()}.7z",
        "archive_size": rng.randint(200, 2000),
        "doc_count": rng.randint(50, 500),
        "exfil_ip": rng.choice(_EXTERNAL_IPS),
    }

    description = template["description"].format_map(vals)
    raw_log = template["raw_log"].format_map(vals)

    return {**template, "description": description, "raw_log": raw_log, "_vals": vals}


def _make_alert(template: Dict[str, Any], rng: random.Random, timestamp: datetime) -> Dict[str, Any]:
    """Create a full alert dict from a filled template."""
    filled = _fill_template(template, rng)
    # Use rng for deterministic alert IDs (not uuid4 which is non-deterministic)
    alert_id = f"ALERT-{rng.randbytes(4).hex().upper()}"

    return {
        "alert_id": alert_id,
        "timestamp": timestamp.isoformat(),
        "alert_type": filled["alert_type"],
        "source": filled["source"],
        "mitre_tactic": filled["mitre_tactic"],
        "mitre_technique": filled["mitre_technique"],
        "description": filled["description"],
        "raw_log": filled["raw_log"],
        "ground_truth": filled["ground_truth"],
        # campaign fields for task 3
        "chain_position": filled.get("chain_position"),
        "chain_label": filled.get("chain_label"),
        "is_campaign": filled.get("chain_position") is not None,
    }


# ---------------------------------------------------------------------------
# Public API: generate scenarios for each task
# ---------------------------------------------------------------------------


def generate_easy_scenario(seed: int = 42) -> List[Dict[str, Any]]:
    """Generate a single alert for the easy task."""
    rng = random.Random(seed)
    # Pick a random true positive or false positive template (not benign/suspicious for clarity)
    tp_fp_templates = [t for t in ALERT_TEMPLATES if t["ground_truth"]["classification"] in ("true_positive", "false_positive")]
    template = rng.choice(tp_fp_templates)
    base_time = datetime(2026, 4, 1, 9, 0, 0, tzinfo=timezone.utc)
    return [_make_alert(template, rng, base_time)]


def generate_medium_scenario(seed: int = 42) -> List[Dict[str, Any]]:
    """Generate a queue of 10 alerts with mixed classifications for the medium task."""
    rng = random.Random(seed)
    base_time = datetime(2026, 4, 1, 8, 0, 0, tzinfo=timezone.utc)

    alerts = []
    # Ensure a good mix: 5 true positives, 3 false positives, 1 benign, 1 suspicious
    tp_templates = [t for t in ALERT_TEMPLATES if t["ground_truth"]["classification"] == "true_positive"]
    fp_templates = [t for t in ALERT_TEMPLATES if t["ground_truth"]["classification"] == "false_positive"]
    benign_templates = [t for t in ALERT_TEMPLATES if t["ground_truth"]["classification"] == "benign"]
    suspicious_templates = [t for t in ALERT_TEMPLATES if t["ground_truth"]["classification"] == "suspicious"]

    selected = (
        rng.sample(tp_templates, min(5, len(tp_templates)))
        + rng.sample(fp_templates, min(3, len(fp_templates)))
        + rng.sample(benign_templates, min(1, len(benign_templates)))
        + rng.sample(suspicious_templates, min(1, len(suspicious_templates)))
    )
    rng.shuffle(selected)

    for i, template in enumerate(selected):
        ts = base_time + timedelta(minutes=rng.randint(1, 120))
        alerts.append(_make_alert(template, rng, ts))

    return alerts


def generate_hard_scenario(seed: int = 42) -> List[Dict[str, Any]]:
    """
    Generate 15 alerts for the hard task.

    5 alerts form a coordinated attack campaign (kill chain).
    10 are noise alerts (mix of true/false positives).
    """
    rng = random.Random(seed)
    base_time = datetime(2026, 4, 1, 6, 0, 0, tzinfo=timezone.utc)

    campaign_id = f"CAMPAIGN-{rng.randbytes(3).hex().upper()}"

    # Generate the 5 campaign alerts in chronological order
    campaign_alerts = []
    for i, template in enumerate(CAMPAIGN_CHAIN):
        ts = base_time + timedelta(minutes=15 * (i + 1))
        alert = _make_alert(template, rng, ts)
        alert["campaign_id"] = campaign_id
        campaign_alerts.append(alert)

    # Generate 10 noise alerts
    noise_templates = rng.choices(ALERT_TEMPLATES, k=10)
    noise_alerts = []
    for template in noise_templates:
        ts = base_time + timedelta(minutes=rng.randint(1, 180))
        alert = _make_alert(template, rng, ts)
        alert["campaign_id"] = None
        noise_alerts.append(alert)

    # Interleave and shuffle all 15 alerts
    all_alerts = campaign_alerts + noise_alerts
    rng.shuffle(all_alerts)

    return all_alerts
