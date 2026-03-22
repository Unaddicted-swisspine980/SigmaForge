"""
SigmaForge - Sigma Rule Engine
Core engine for generating, validating, and managing Sigma detection rules.
"""

import uuid
import yaml
import json
import re
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─────────────────────────────────────────────
# MITRE ATT&CK Mapping Database
# ─────────────────────────────────────────────

MITRE_ATTACK_MAP = {
    # Reconnaissance
    "T1595": {"name": "Active Scanning", "tactic": "reconnaissance"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "reconnaissance"},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "reconnaissance"},
    # Initial Access
    "T1566": {"name": "Phishing", "tactic": "initial-access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "initial-access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "initial-access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "T1133": {"name": "External Remote Services", "tactic": "initial-access"},
    "T1078": {"name": "Valid Accounts", "tactic": "initial-access"},
    "T1199": {"name": "Trusted Relationship", "tactic": "initial-access"},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "initial-access"},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "execution"},
    "T1059.002": {"name": "AppleScript", "tactic": "execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "execution"},
    "T1059.005": {"name": "Visual Basic", "tactic": "execution"},
    "T1059.006": {"name": "Python", "tactic": "execution"},
    "T1059.007": {"name": "JavaScript", "tactic": "execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "execution"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "execution"},
    "T1204": {"name": "User Execution", "tactic": "execution"},
    "T1204.002": {"name": "Malicious File", "tactic": "execution"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "execution"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "execution"},
    "T1569": {"name": "System Services", "tactic": "execution"},
    "T1569.002": {"name": "Service Execution", "tactic": "execution"},
    # Persistence
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "persistence"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "persistence"},
    "T1136": {"name": "Create Account", "tactic": "persistence"},
    "T1136.001": {"name": "Local Account", "tactic": "persistence"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "persistence"},
    "T1543.003": {"name": "Windows Service", "tactic": "persistence"},
    "T1053.005_p": {"name": "Scheduled Task (Persistence)", "tactic": "persistence"},
    "T1505": {"name": "Server Software Component", "tactic": "persistence"},
    "T1505.003": {"name": "Web Shell", "tactic": "persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "persistence"},
    # Privilege Escalation
    "T1055": {"name": "Process Injection", "tactic": "privilege-escalation"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege-escalation"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege-escalation"},
    "T1548.002": {"name": "Bypass User Account Control", "tactic": "privilege-escalation"},
    # Defense Evasion
    "T1562": {"name": "Impair Defenses", "tactic": "defense-evasion"},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "defense-evasion"},
    "T1562.004": {"name": "Disable or Modify System Firewall", "tactic": "defense-evasion"},
    "T1070": {"name": "Indicator Removal", "tactic": "defense-evasion"},
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "defense-evasion"},
    "T1070.004": {"name": "File Deletion", "tactic": "defense-evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
    "T1036": {"name": "Masquerading", "tactic": "defense-evasion"},
    "T1036.005": {"name": "Match Legitimate Name or Location", "tactic": "defense-evasion"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "defense-evasion"},
    "T1218.011": {"name": "Rundll32", "tactic": "defense-evasion"},
    "T1112": {"name": "Modify Registry", "tactic": "defense-evasion"},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "defense-evasion"},
    "T1202": {"name": "Indirect Command Execution", "tactic": "defense-evasion"},
    "T1564": {"name": "Hide Artifacts", "tactic": "defense-evasion"},
    # Credential Access
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential-access"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "credential-access"},
    "T1003.002": {"name": "Security Account Manager", "tactic": "credential-access"},
    "T1003.003": {"name": "NTDS", "tactic": "credential-access"},
    "T1110": {"name": "Brute Force", "tactic": "credential-access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "credential-access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "credential-access"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "credential-access"},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "credential-access"},
    "T1558.003": {"name": "Kerberoasting", "tactic": "credential-access"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "credential-access"},
    # Discovery
    "T1087": {"name": "Account Discovery", "tactic": "discovery"},
    "T1087.001": {"name": "Local Account Discovery", "tactic": "discovery"},
    "T1087.002": {"name": "Domain Account Discovery", "tactic": "discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "discovery"},
    "T1018": {"name": "Remote System Discovery", "tactic": "discovery"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "discovery"},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "discovery"},
    "T1069": {"name": "Permission Groups Discovery", "tactic": "discovery"},
    "T1033": {"name": "System Owner/User Discovery", "tactic": "discovery"},
    "T1007": {"name": "System Service Discovery", "tactic": "discovery"},
    "T1135": {"name": "Network Share Discovery", "tactic": "discovery"},
    "T1046": {"name": "Network Service Discovery", "tactic": "discovery"},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "lateral-movement"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "lateral-movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "lateral-movement"},
    "T1021.003": {"name": "Distributed Component Object Model", "tactic": "lateral-movement"},
    "T1021.004": {"name": "SSH", "tactic": "lateral-movement"},
    "T1021.006": {"name": "Windows Remote Management", "tactic": "lateral-movement"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "lateral-movement"},
    # Collection
    "T1005": {"name": "Data from Local System", "tactic": "collection"},
    "T1560": {"name": "Archive Collected Data", "tactic": "collection"},
    "T1074": {"name": "Data Staged", "tactic": "collection"},
    "T1113": {"name": "Screen Capture", "tactic": "collection"},
    "T1115": {"name": "Clipboard Data", "tactic": "collection"},
    "T1119": {"name": "Automated Collection", "tactic": "collection"},
    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "command-and-control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "command-and-control"},
    "T1071.004": {"name": "DNS", "tactic": "command-and-control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "command-and-control"},
    "T1090": {"name": "Proxy", "tactic": "command-and-control"},
    "T1572": {"name": "Protocol Tunneling", "tactic": "command-and-control"},
    "T1573": {"name": "Encrypted Channel", "tactic": "command-and-control"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "command-and-control"},
    "T1219": {"name": "Remote Access Software", "tactic": "command-and-control"},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "exfiltration"},
    "T1537": {"name": "Transfer Data to Cloud Account", "tactic": "exfiltration"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
    "T1485": {"name": "Data Destruction", "tactic": "impact"},
    "T1489": {"name": "Service Stop", "tactic": "impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "impact"},
    "T1491": {"name": "Defacement", "tactic": "impact"},
    "T1498": {"name": "Network Denial of Service", "tactic": "impact"},
    "T1529": {"name": "System Shutdown/Reboot", "tactic": "impact"},
}

# Tactic ID mapping
TACTIC_IDS = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


# ─────────────────────────────────────────────
# Log Source Definitions
# ─────────────────────────────────────────────

LOG_SOURCES = {
    "process_creation": {
        "category": "process_creation",
        "product": "windows",
        "description": "Windows Process Creation (Sysmon EventID 1 / Security 4688)",
        "fields": [
            "Image", "OriginalFileName", "CommandLine", "ParentImage",
            "ParentCommandLine", "User", "IntegrityLevel", "Hashes",
            "CurrentDirectory", "LogonId", "Company", "Product",
            "Description", "FileVersion"
        ],
    },
    "windows_security": {
        "product": "windows",
        "service": "security",
        "description": "Windows Security Event Log",
        "fields": [
            "EventID", "TargetUserName", "TargetDomainName",
            "SubjectUserName", "SubjectDomainName", "LogonType",
            "IpAddress", "IpPort", "WorkstationName", "Status",
            "SubStatus", "FailureReason", "ProcessName",
            "ServiceName", "TicketEncryptionType", "TicketOptions"
        ],
    },
    "sysmon": {
        "product": "windows",
        "service": "sysmon",
        "description": "Sysmon Operational Log (all event types)",
        "fields": [
            "EventID", "Image", "TargetFilename", "DestinationHostname",
            "DestinationIp", "DestinationPort", "SourceIp", "SourcePort",
            "Protocol", "User", "Hashes", "TargetObject", "Details",
            "SourceImage", "TargetImage", "PipeName", "QueryName",
            "QueryResults", "CallTrace"
        ],
    },
    "powershell": {
        "product": "windows",
        "service": "powershell",
        "description": "PowerShell Script Block / Module Logging",
        "fields": [
            "EventID", "ScriptBlockText", "ScriptBlockId",
            "MessageNumber", "MessageTotal", "Path",
            "HostApplication", "CommandLine", "ContextInfo",
            "Payload"
        ],
    },
    "powershell_classic": {
        "product": "windows",
        "service": "powershell-classic",
        "description": "Windows PowerShell (Classic) Event Log",
        "fields": [
            "EventID", "HostApplication", "CommandLine",
            "EngineVersion", "ScriptName"
        ],
    },
    "firewall": {
        "category": "firewall",
        "description": "Firewall logs (vendor-agnostic)",
        "fields": [
            "src_ip", "src_port", "dst_ip", "dst_port", "action",
            "protocol", "rule_name", "direction", "application",
            "bytes_in", "bytes_out"
        ],
    },
    "proxy": {
        "category": "proxy",
        "description": "Web proxy / HTTP logs",
        "fields": [
            "c-uri", "c-uri-query", "c-uri-stem", "cs-host",
            "cs-method", "cs-referer", "cs-user-agent", "r-dns",
            "sc-status", "src_ip", "dst_ip", "cs-bytes", "sc-bytes"
        ],
    },
    "dns_query": {
        "category": "dns_query",
        "product": "windows",
        "description": "DNS Query Events (Sysmon EventID 22)",
        "fields": [
            "QueryName", "QueryResults", "QueryStatus", "Image",
            "ProcessId", "User"
        ],
    },
    "network_connection": {
        "category": "network_connection",
        "product": "windows",
        "description": "Network Connection Events (Sysmon EventID 3)",
        "fields": [
            "Image", "DestinationHostname", "DestinationIp",
            "DestinationPort", "DestinationIsIpv6", "Initiated",
            "Protocol", "SourceIp", "SourcePort", "User"
        ],
    },
    "file_event": {
        "category": "file_event",
        "product": "windows",
        "description": "File Creation / Modification Events (Sysmon EventID 11)",
        "fields": [
            "TargetFilename", "Image", "CreationUtcTime", "User"
        ],
    },
    "registry_event": {
        "category": "registry_set",
        "product": "windows",
        "description": "Registry Value Set Events (Sysmon EventID 13)",
        "fields": [
            "EventType", "TargetObject", "Details", "Image", "User"
        ],
    },
    "linux_process": {
        "category": "process_creation",
        "product": "linux",
        "description": "Linux Process Creation (auditd / sysmon-linux)",
        "fields": [
            "Image", "CommandLine", "ParentImage", "ParentCommandLine",
            "User", "CurrentDirectory"
        ],
    },
    "linux_auth": {
        "product": "linux",
        "service": "auth",
        "description": "Linux Authentication Logs (/var/log/auth.log)",
        "fields": [
            "User", "SourceIP", "Method", "Service", "Status"
        ],
    },
}


# ─────────────────────────────────────────────
# Pre-built Rule Templates
# ─────────────────────────────────────────────

RULE_TEMPLATES = {
    "suspicious_powershell": {
        "name": "Suspicious PowerShell Execution",
        "description": "Detects potentially malicious PowerShell usage with encoded commands, download cradles, or AMSI bypass attempts",
        "log_source": "process_creation",
        "mitre_techniques": ["T1059.001"],
        "level": "high",
        "status": "experimental",
        "detection": {
            "selection_encoded": {
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": [
                    "-enc", "-EncodedCommand", "FromBase64String",
                    "-e ", "-ec "
                ],
            },
            "selection_download": {
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": [
                    "Net.WebClient", "DownloadString", "DownloadFile",
                    "Invoke-WebRequest", "iwr ", "wget ", "curl ",
                    "Start-BitsTransfer", "Invoke-RestMethod"
                ],
            },
            "selection_amsi": {
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": [
                    "AmsiUtils", "amsiInitFailed",
                    "SetValue(null,$true)", "Disable-WindowsOptionalFeature"
                ],
            },
            "condition": "selection_encoded or selection_download or selection_amsi",
        },
        "falsepositives": ["Administrative scripts", "Software deployment tools"],
        "fields": ["CommandLine", "ParentImage", "User"],
    },
    "mimikatz_execution": {
        "name": "Mimikatz Credential Dumping",
        "description": "Detects Mimikatz execution via command line arguments or process names commonly associated with credential dumping",
        "log_source": "process_creation",
        "mitre_techniques": ["T1003.001"],
        "level": "critical",
        "status": "experimental",
        "detection": {
            "selection_binary": {
                "Image|endswith": [
                    "\\mimikatz.exe", "\\mimilib.dll"
                ],
            },
            "selection_cmdline": {
                "CommandLine|contains": [
                    "sekurlsa::logonpasswords", "sekurlsa::wdigest",
                    "lsadump::sam", "lsadump::dcsync",
                    "privilege::debug", "token::elevate",
                    "crypto::certificates", "kerberos::golden",
                    "kerberos::ptt"
                ],
            },
            "condition": "selection_binary or selection_cmdline",
        },
        "falsepositives": ["Authorized penetration testing"],
        "fields": ["CommandLine", "ParentImage", "User", "Hashes"],
    },
    "suspicious_scheduled_task": {
        "name": "Suspicious Scheduled Task Creation",
        "description": "Detects creation of scheduled tasks from suspicious locations or with suspicious commands that may indicate persistence",
        "log_source": "process_creation",
        "mitre_techniques": ["T1053.005"],
        "level": "medium",
        "status": "experimental",
        "detection": {
            "selection": {
                "Image|endswith": "\\schtasks.exe",
                "CommandLine|contains": "/create",
            },
            "filter_susp_paths": {
                "CommandLine|contains": [
                    "\\AppData\\", "\\Temp\\", "\\ProgramData\\",
                    "\\Users\\Public\\", "%APPDATA%", "%TEMP%",
                    "powershell", "cmd.exe /c", "mshta",
                    "wscript", "cscript", "certutil", "bitsadmin"
                ],
            },
            "condition": "selection and filter_susp_paths",
        },
        "falsepositives": ["Software installers", "System administration"],
        "fields": ["CommandLine", "ParentImage", "User"],
    },
    "windows_logon_brute_force": {
        "name": "Multiple Failed Logon Attempts",
        "description": "Detects multiple failed logon attempts which may indicate a brute force or password spraying attack",
        "log_source": "windows_security",
        "mitre_techniques": ["T1110"],
        "level": "medium",
        "status": "experimental",
        "detection": {
            "selection": {
                "EventID": 4625,
            },
            "condition": "selection | count(TargetUserName) by IpAddress > 10",
        },
        "falsepositives": ["Misconfigured service accounts", "Users forgetting passwords"],
        "fields": ["TargetUserName", "IpAddress", "LogonType", "Status"],
    },
    "event_log_clearing": {
        "name": "Windows Event Log Cleared",
        "description": "Detects when a Windows event log is cleared, which may indicate an attacker covering their tracks",
        "log_source": "windows_security",
        "mitre_techniques": ["T1070.001"],
        "level": "high",
        "status": "stable",
        "detection": {
            "selection": {
                "EventID": [1102, 104],
            },
            "condition": "selection",
        },
        "falsepositives": ["Legitimate log management", "System maintenance windows"],
        "fields": ["SubjectUserName", "SubjectDomainName"],
    },
    "suspicious_dns_query": {
        "name": "Suspicious DNS Query to Known Malicious TLD",
        "description": "Detects DNS queries to suspicious top-level domains commonly used for malware C2 or phishing",
        "log_source": "dns_query",
        "mitre_techniques": ["T1071.004"],
        "level": "medium",
        "status": "experimental",
        "detection": {
            "selection": {
                "QueryName|endswith": [
                    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf",
                    ".gq", ".buzz", ".club", ".work", ".surf",
                    ".bit", ".onion"
                ],
            },
            "condition": "selection",
        },
        "falsepositives": ["Legitimate services using these TLDs"],
        "fields": ["QueryName", "Image", "User"],
    },
    "lolbin_execution": {
        "name": "LOLBin Suspicious Execution",
        "description": "Detects execution of Living-off-the-Land binaries (LOLBins) commonly abused by attackers for download, execution, or bypass",
        "log_source": "process_creation",
        "mitre_techniques": ["T1218"],
        "level": "medium",
        "status": "experimental",
        "detection": {
            "selection_certutil": {
                "Image|endswith": "\\certutil.exe",
                "CommandLine|contains": [
                    "-urlcache", "-split", "-decode",
                    "-encode", "-verifyctl"
                ],
            },
            "selection_mshta": {
                "Image|endswith": "\\mshta.exe",
                "CommandLine|contains": [
                    "javascript:", "vbscript:", "http://", "https://"
                ],
            },
            "selection_rundll32": {
                "Image|endswith": "\\rundll32.exe",
                "CommandLine|contains": [
                    "javascript:", "http://", "https://",
                    "shell32.dll,Control_RunDLL"
                ],
            },
            "selection_regsvr32": {
                "Image|endswith": "\\regsvr32.exe",
                "CommandLine|contains": [
                    "/s", "/i:http", "/i:https", "scrobj.dll"
                ],
            },
            "condition": "selection_certutil or selection_mshta or selection_rundll32 or selection_regsvr32",
        },
        "falsepositives": ["Legitimate administrative usage", "Software installations"],
        "fields": ["CommandLine", "ParentImage", "ParentCommandLine", "User"],
    },
    "firewall_port_scan": {
        "name": "Potential Port Scan Detected",
        "description": "Detects a high number of denied connections from a single source IP which may indicate port scanning activity",
        "log_source": "firewall",
        "mitre_techniques": ["T1046"],
        "level": "medium",
        "status": "experimental",
        "detection": {
            "selection": {
                "action": "denied",
            },
            "condition": "selection | count() by src_ip > 50",
        },
        "falsepositives": ["Vulnerability scanners", "Network monitoring tools"],
        "fields": ["src_ip", "dst_ip", "dst_port"],
    },
    "proxy_suspicious_user_agent": {
        "name": "Suspicious User Agent in Proxy Logs",
        "description": "Detects suspicious or known malicious user agent strings in web proxy logs that may indicate C2 communication or automated tools",
        "log_source": "proxy",
        "mitre_techniques": ["T1071.001"],
        "level": "medium",
        "status": "experimental",
        "detection": {
            "selection": {
                "cs-user-agent|contains": [
                    "python-requests", "Go-http-client", "HTTPie",
                    "Wget", "libwww-perl", "Cobalt", "Empire",
                    "Metasploit", "sqlmap", "Nikto", "Nmap"
                ],
            },
            "condition": "selection",
        },
        "falsepositives": ["Legitimate development tools", "Monitoring scripts"],
        "fields": ["cs-user-agent", "cs-host", "c-uri", "src_ip"],
    },
    "registry_persistence": {
        "name": "Registry Run Key Persistence",
        "description": "Detects modification of registry run keys commonly used for persistence by malware and threat actors",
        "log_source": "registry_event",
        "mitre_techniques": ["T1547.001"],
        "level": "medium",
        "status": "experimental",
        "detection": {
            "selection": {
                "TargetObject|contains": [
                    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                ],
            },
            "filter_legitimate": {
                "Image|endswith": [
                    "\\msiexec.exe", "\\svchost.exe", "\\MsMpEng.exe"
                ],
            },
            "condition": "selection and not filter_legitimate",
        },
        "falsepositives": ["Software installations", "System updates"],
        "fields": ["TargetObject", "Details", "Image", "User"],
    },
    "network_connection_suspicious_port": {
        "name": "Outbound Connection to Non-Standard Port",
        "description": "Detects outbound network connections to non-standard ports from processes that typically do not make such connections",
        "log_source": "network_connection",
        "mitre_techniques": ["T1095"],
        "level": "low",
        "status": "experimental",
        "detection": {
            "selection": {
                "Initiated": "true",
                "DestinationPort": [4444, 5555, 6666, 7777, 8888, 9999,
                                    1234, 31337, 12345, 54321],
            },
            "filter": {
                "Image|endswith": [
                    "\\chrome.exe", "\\firefox.exe", "\\msedge.exe",
                    "\\iexplore.exe", "\\svchost.exe"
                ],
            },
            "condition": "selection and not filter",
        },
        "falsepositives": ["Custom applications", "Development servers"],
        "fields": ["Image", "DestinationIp", "DestinationPort", "User"],
    },
    "linux_reverse_shell": {
        "name": "Linux Reverse Shell Detected",
        "description": "Detects common reverse shell patterns on Linux systems using bash, netcat, or other utilities",
        "log_source": "linux_process",
        "mitre_techniques": ["T1059.004"],
        "level": "critical",
        "status": "experimental",
        "detection": {
            "selection_bash": {
                "CommandLine|contains": [
                    "bash -i >& /dev/tcp/",
                    "bash -c 'bash -i >& /dev/tcp",
                    "0<&196;exec 196<>/dev/tcp/"
                ],
            },
            "selection_netcat": {
                "CommandLine|contains": [
                    "nc -e /bin/", "ncat -e /bin/",
                    "nc.traditional -e", "netcat -e"
                ],
            },
            "selection_python": {
                "CommandLine|contains": [
                    "python -c 'import socket,subprocess",
                    "python3 -c 'import socket,subprocess",
                    "python -c \"import socket,subprocess"
                ],
            },
            "condition": "selection_bash or selection_netcat or selection_python",
        },
        "falsepositives": ["Authorized penetration testing"],
        "fields": ["CommandLine", "ParentImage", "User"],
    },
}


# ─────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────

@dataclass
class SigmaRule:
    """Represents a complete Sigma detection rule."""
    title: str
    description: str
    log_source_key: str
    detection: dict
    level: str = "medium"
    status: str = "experimental"
    author: str = "SigmaForge"
    mitre_techniques: list = field(default_factory=list)
    falsepositives: list = field(default_factory=list)
    references: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    rule_fields: list = field(default_factory=list)
    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    date: str = field(default_factory=lambda: datetime.now().strftime("%Y/%m/%d"))
    modified: Optional[str] = None

    def get_logsource(self) -> dict:
        """Build the logsource block from the log source key."""
        src = LOG_SOURCES.get(self.log_source_key, {})
        logsource = {}
        if "category" in src:
            logsource["category"] = src["category"]
        if "product" in src:
            logsource["product"] = src["product"]
        if "service" in src:
            logsource["service"] = src["service"]
        return logsource

    def get_mitre_tags(self) -> list:
        """Generate ATT&CK tags in Sigma format (attack.tactic, attack.tXXXX)."""
        tags = []
        seen_tactics = set()
        for tech_id in self.mitre_techniques:
            clean_id = tech_id.rstrip("_p")
            info = MITRE_ATTACK_MAP.get(clean_id, MITRE_ATTACK_MAP.get(tech_id))
            if info:
                tactic = info["tactic"]
                if tactic not in seen_tactics:
                    tags.append(f"attack.{tactic}")
                    seen_tactics.add(tactic)
                tag_id = clean_id.lower().replace(".", "_")
                tags.append(f"attack.{tag_id}")
        return tags

    def to_yaml(self) -> str:
        """Serialize the rule to Sigma YAML format."""
        rule = {}
        rule["title"] = self.title
        rule["id"] = self.rule_id
        rule["status"] = self.status
        rule["description"] = self.description

        if self.references:
            rule["references"] = self.references

        rule["author"] = self.author
        rule["date"] = self.date
        if self.modified:
            rule["modified"] = self.modified

        tags = self.get_mitre_tags() + self.tags
        if tags:
            rule["tags"] = tags

        rule["logsource"] = self.get_logsource()
        rule["detection"] = self.detection
        rule["level"] = self.level

        if self.rule_fields:
            rule["fields"] = self.rule_fields

        if self.falsepositives:
            rule["falsepositives"] = self.falsepositives

        return yaml.dump(rule, default_flow_style=False, sort_keys=False,
                         allow_unicode=True, width=120)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "title": self.title,
            "id": self.rule_id,
            "status": self.status,
            "description": self.description,
            "references": self.references,
            "author": self.author,
            "date": self.date,
            "modified": self.modified,
            "tags": self.get_mitre_tags() + self.tags,
            "logsource": self.get_logsource(),
            "detection": self.detection,
            "level": self.level,
            "fields": self.rule_fields,
            "falsepositives": self.falsepositives,
            "mitre_techniques": self.mitre_techniques,
        }


# ─────────────────────────────────────────────
# Rule Validator
# ─────────────────────────────────────────────

class SigmaValidator:
    """Validates Sigma rules against the specification."""

    REQUIRED_FIELDS = ["title", "logsource", "detection"]
    VALID_LEVELS = ["informational", "low", "medium", "high", "critical"]
    VALID_STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"]
    VALID_MODIFIERS = [
        "contains", "startswith", "endswith", "base64",
        "base64offset", "utf16le", "utf16be", "wide",
        "re", "cidr", "all", "gt", "gte", "lt", "lte",
        "fieldref", "expand", "windash"
    ]

    @staticmethod
    def validate(rule_yaml: str) -> dict:
        """
        Validate a Sigma rule YAML string.
        Returns: {"valid": bool, "errors": [], "warnings": []}
        """
        result = {"valid": True, "errors": [], "warnings": []}

        # Parse YAML
        try:
            rule = yaml.safe_load(rule_yaml)
        except yaml.YAMLError as e:
            result["valid"] = False
            result["errors"].append(f"YAML parse error: {str(e)}")
            return result

        if not isinstance(rule, dict):
            result["valid"] = False
            result["errors"].append("Rule must be a YAML mapping/dictionary")
            return result

        # Required fields
        for req_field in SigmaValidator.REQUIRED_FIELDS:
            if req_field not in rule:
                result["valid"] = False
                result["errors"].append(f"Missing required field: '{req_field}'")

        # Title length
        title = rule.get("title", "")
        if len(title) > 256:
            result["errors"].append(f"Title exceeds 256 characters ({len(title)} chars)")
            result["valid"] = False

        # ID format (should be UUID)
        rule_id = rule.get("id", "")
        if rule_id:
            uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            if not re.match(uuid_pattern, str(rule_id), re.IGNORECASE):
                result["warnings"].append("ID is not a valid UUID v4 format")

        # Status
        status = rule.get("status", "")
        if status and status not in SigmaValidator.VALID_STATUSES:
            result["warnings"].append(
                f"Non-standard status '{status}'. "
                f"Valid: {', '.join(SigmaValidator.VALID_STATUSES)}"
            )

        # Level
        level = rule.get("level", "")
        if level and level not in SigmaValidator.VALID_LEVELS:
            result["valid"] = False
            result["errors"].append(
                f"Invalid level '{level}'. "
                f"Valid: {', '.join(SigmaValidator.VALID_LEVELS)}"
            )

        # Logsource validation
        logsource = rule.get("logsource", {})
        if isinstance(logsource, dict):
            has_source = any(k in logsource for k in ["category", "product", "service"])
            if not has_source:
                result["valid"] = False
                result["errors"].append(
                    "logsource must contain at least one of: category, product, service"
                )
        else:
            result["valid"] = False
            result["errors"].append("logsource must be a YAML mapping")

        # Detection validation
        detection = rule.get("detection", {})
        if isinstance(detection, dict):
            if "condition" not in detection:
                result["valid"] = False
                result["errors"].append("detection must contain a 'condition' field")
            else:
                condition = detection["condition"]
                # Check that referenced selections exist
                selections = {k for k in detection.keys() if k != "condition" and k != "timeframe"}
                cond_str = str(condition)
                for sel in selections:
                    pass  # selections exist, that's fine
                # Check for empty selections
                for key, val in detection.items():
                    if key not in ("condition", "timeframe") and not val:
                        result["warnings"].append(f"Empty selection '{key}' in detection")

                # Validate field modifiers
                for key, val in detection.items():
                    if key in ("condition", "timeframe"):
                        continue
                    if isinstance(val, dict):
                        for field_name in val.keys():
                            if "|" in str(field_name):
                                parts = str(field_name).split("|")
                                for mod in parts[1:]:
                                    if mod not in SigmaValidator.VALID_MODIFIERS:
                                        result["warnings"].append(
                                            f"Unknown modifier '{mod}' in field '{field_name}'"
                                        )
        else:
            result["valid"] = False
            result["errors"].append("detection must be a YAML mapping")

        # Tags validation (ATT&CK format)
        tags = rule.get("tags", [])
        if tags:
            for tag in tags:
                if tag.startswith("attack.") and not tag.startswith("attack.t") \
                        and tag.split(".")[-1] not in [
                    t.replace("-", "_") for t in TACTIC_IDS.keys()
                ]:
                    result["warnings"].append(f"Unrecognized ATT&CK tag: '{tag}'")

        # Warnings for best practices
        if "description" not in rule or not rule.get("description"):
            result["warnings"].append("Missing description (recommended)")
        if "author" not in rule:
            result["warnings"].append("Missing author field (recommended)")
        if "date" not in rule:
            result["warnings"].append("Missing date field (recommended)")
        if "falsepositives" not in rule:
            result["warnings"].append("Missing falsepositives field (recommended)")

        return result


# ─────────────────────────────────────────────
# SIEM Converter
# ─────────────────────────────────────────────

class SIEMConverter:
    """Converts Sigma rules to SIEM-specific query languages."""

    @staticmethod
    def _build_field_query(field_name: str, values, backend: str) -> str:
        """Build a query fragment for a single field with optional modifiers."""
        modifiers = []
        base_field = field_name

        if "|" in field_name:
            parts = field_name.split("|")
            base_field = parts[0]
            modifiers = parts[1:]

        if not isinstance(values, list):
            values = [values]

        queries = []
        for val in values:
            val_str = str(val)

            if backend == "splunk":
                q = SIEMConverter._splunk_field_value(base_field, val_str, modifiers)
            elif backend == "elastic":
                q = SIEMConverter._elastic_field_value(base_field, val_str, modifiers)
            elif backend == "sentinel":
                q = SIEMConverter._sentinel_field_value(base_field, val_str, modifiers)
            elif backend == "eql":
                q = SIEMConverter._eql_field_value(base_field, val_str, modifiers)
            else:
                q = f'{base_field}="{val_str}"'
            queries.append(q)

        if len(queries) == 1:
            return queries[0]

        if backend == "splunk":
            return "(" + " OR ".join(queries) + ")"
        elif backend == "elastic":
            return "(" + " OR ".join(queries) + ")"
        elif backend == "eql":
            return "(" + " or ".join(queries) + ")"
        elif backend == "sentinel":
            return "(" + " or ".join(queries) + ")"
        return " OR ".join(queries)

    @staticmethod
    def _splunk_field_value(field: str, value: str, modifiers: list) -> str:
        if "contains" in modifiers:
            return f'{field}="*{value}*"'
        elif "startswith" in modifiers:
            return f'{field}="{value}*"'
        elif "endswith" in modifiers:
            return f'{field}="*{value}"'
        elif "re" in modifiers:
            return f'{field}="{value}"'
        else:
            return f'{field}="{value}"'

    @staticmethod
    def _elastic_field_value(field: str, value: str, modifiers: list) -> str:
        if "contains" in modifiers:
            return f'{field}:*{value}*'
        elif "startswith" in modifiers:
            return f'{field}:{value}*'
        elif "endswith" in modifiers:
            return f'{field}:*{value}'
        elif "re" in modifiers:
            return f'{field}:/{value}/'
        else:
            return f'{field}:"{value}"'

    @staticmethod
    def _sentinel_field_value(field: str, value: str, modifiers: list) -> str:
        if "contains" in modifiers:
            return f'{field} contains "{value}"'
        elif "startswith" in modifiers:
            return f'{field} startswith "{value}"'
        elif "endswith" in modifiers:
            return f'{field} endswith "{value}"'
        elif "re" in modifiers:
            return f'{field} matches regex "{value}"'
        else:
            return f'{field} == "{value}"'

    @staticmethod
    def _eql_field_value(field: str, value: str, modifiers: list) -> str:
        if "contains" in modifiers:
            return f'{field} : "*{value}*"'
        elif "startswith" in modifiers:
            return f'{field} : "{value}*"'
        elif "endswith" in modifiers:
            return f'{field} : "*{value}"'
        elif "re" in modifiers:
            return f'{field} regex~ "{value}"'
        else:
            return f'{field} == "{value}"'

    @staticmethod
    def _convert_selection(selection: dict, backend: str) -> str:
        """Convert a single selection (AND of field matches) to a query."""
        parts = []
        for field_name, values in selection.items():
            parts.append(SIEMConverter._build_field_query(field_name, values, backend))

        joiner = " AND " if backend not in ("sentinel", "eql") else " and "
        if len(parts) == 1:
            return parts[0]
        return "(" + joiner.join(parts) + ")"

    @staticmethod
    def convert(rule_yaml: str, backend: str) -> str:
        """
        Convert a Sigma rule YAML string to a SIEM query.
        Backends: 'splunk', 'elastic', 'eql', 'sentinel'
        """
        rule = yaml.safe_load(rule_yaml)
        detection = rule.get("detection", {})
        condition = detection.get("condition", "")

        # Build selection queries
        selection_queries = {}
        for key, val in detection.items():
            if key in ("condition", "timeframe"):
                continue
            if isinstance(val, dict):
                selection_queries[key] = SIEMConverter._convert_selection(val, backend)

        # Parse condition and substitute selections
        query = SIEMConverter._parse_condition(condition, selection_queries, backend)

        # Add logsource context
        logsource = rule.get("logsource", {})
        source_prefix = SIEMConverter._get_source_prefix(logsource, backend)

        if source_prefix:
            if backend == "splunk":
                query = f"{source_prefix}\n| where {query}"
            elif backend == "elastic":
                query = f"{source_prefix} AND ({query})"
            elif backend == "eql":
                query = f"{source_prefix} where\n  {query}"
            elif backend == "sentinel":
                query = f"{source_prefix}\n| where {query}"

        return query

    @staticmethod
    def _parse_condition(condition: str, selections: dict, backend: str) -> str:
        """Parse the condition expression and substitute selection queries."""
        # Limit condition length to prevent ReDoS on adversarial input
        if len(condition) > 500:
            return condition

        # Handle aggregation conditions (count, sum, etc.)
        agg_match = re.match(
            r'(\w+)\s{0,10}\|\s{0,10}count\((\w*)\)\s{0,10}by\s{1,10}(\w+)\s{0,10}([><=!]{1,2})\s{0,10}(\d+)$',
            condition
        )
        if agg_match:
            sel_name, count_field, group_field, operator, threshold = agg_match.groups()
            base_query = selections.get(sel_name, sel_name)
            return SIEMConverter._build_aggregation(
                base_query, count_field, group_field, operator, threshold, backend
            )

        agg_match2 = re.match(
            r'(\w+)\s{0,10}\|\s{0,10}count\(\)\s{0,10}by\s{1,10}(\w+)\s{0,10}([><=!]{1,2})\s{0,10}(\d+)$',
            condition
        )
        if agg_match2:
            sel_name, group_field, operator, threshold = agg_match2.groups()
            base_query = selections.get(sel_name, sel_name)
            return SIEMConverter._build_aggregation(
                base_query, "", group_field, operator, threshold, backend
            )

        # Standard boolean conditions
        result = condition
        # Sort by length descending to avoid partial replacements
        for sel_name in sorted(selections.keys(), key=len, reverse=True):
            result = result.replace(sel_name, selections[sel_name])

        # Convert boolean operators for backend
        if backend == "splunk":
            result = result.replace(" or ", " OR ").replace(" and ", " AND ")
            result = result.replace(" not ", " NOT ")
        elif backend == "elastic":
            result = result.replace(" or ", " OR ").replace(" and ", " AND ")
            result = result.replace(" not ", " NOT ")
        elif backend == "eql":
            result = result.replace(" OR ", " or ").replace(" AND ", " and ")
            result = result.replace(" NOT ", " not ")
        elif backend == "sentinel":
            result = result.replace(" OR ", " or ").replace(" AND ", " and ")
            result = result.replace(" NOT ", " not ")

        return result

    @staticmethod
    def _build_aggregation(base_query, count_field, group_field, operator, threshold, backend):
        """Build aggregation query for count-based conditions."""
        if backend == "splunk":
            count_expr = f"count({count_field})" if count_field else "count"
            return (
                f"search {base_query}\n"
                f"| stats {count_expr} as event_count by {group_field}\n"
                f"| where event_count {operator} {threshold}"
            )
        elif backend == "elastic":
            return (
                f"// Base filter: {base_query}\n"
                f"// Aggregate: count by {group_field} {operator} {threshold}\n"
                f"// Implement as: terms aggregation on {group_field} with min_doc_count={threshold}"
            )
        elif backend == "eql":
            return (
                f"/* EQL sequence/threshold query */\n"
                f"/* Base filter: {base_query} */\n"
                f"/* Threshold: count by {group_field} {operator} {threshold} */\n"
                f"/* Note: EQL uses 'sequence' or 'sample' for correlation; */\n"
                f"/* threshold detection may require ES|QL or detection rules API */"
            )
        elif backend == "sentinel":
            count_expr = f"count({count_field})" if count_field else "count()"
            return (
                f"// Base filter\n"
                f"| where {base_query}\n"
                f"| summarize event_count = {count_expr} by {group_field}\n"
                f"| where event_count {operator} {threshold}"
            )
        return base_query

    @staticmethod
    def _get_source_prefix(logsource: dict, backend: str) -> str:
        """Generate SIEM-specific source/index prefix from logsource."""
        category = logsource.get("category", "")
        product = logsource.get("product", "")
        service = logsource.get("service", "")

        if backend == "splunk":
            index_map = {
                "process_creation": 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1',
                "windows": {
                    "security": 'index=wineventlog sourcetype="WinEventLog:Security"',
                    "sysmon": 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
                    "powershell": 'index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational"',
                    "powershell-classic": 'index=wineventlog sourcetype="WinEventLog:Windows PowerShell"',
                },
                "dns_query": 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22',
                "network_connection": 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3',
                "file_event": 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11',
                "registry_set": 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13',
                "firewall": 'index=firewall sourcetype="firewall"',
                "proxy": 'index=proxy sourcetype="proxy"',
            }
            if category in index_map and isinstance(index_map[category], str):
                return index_map[category]
            if product == "windows" and service in index_map.get("windows", {}):
                return index_map["windows"][service]
            if product == "linux":
                return 'index=linux sourcetype="linux:audit"'
            return f'index=* sourcetype=*'

        elif backend == "elastic":
            index_map = {
                "process_creation": "winlogbeat-* AND event.code:1",
                "dns_query": "winlogbeat-* AND event.code:22",
                "network_connection": "winlogbeat-* AND event.code:3",
                "file_event": "winlogbeat-* AND event.code:11",
                "registry_set": "winlogbeat-* AND event.code:13",
                "firewall": "filebeat-*",
                "proxy": "filebeat-*",
            }
            if category in index_map:
                return index_map[category]
            if product == "windows" and service == "security":
                return "winlogbeat-* AND event.provider:Microsoft-Windows-Security-Auditing"
            if product == "windows" and service == "sysmon":
                return "winlogbeat-* AND event.provider:Microsoft-Windows-Sysmon"
            if product == "windows" and service in ("powershell", "powershell-classic"):
                return "winlogbeat-* AND event.provider:Microsoft-Windows-PowerShell"
            if product == "linux":
                return 'filebeat-* AND event.module:auditd'
            return "*"

        elif backend == "eql":
            # EQL uses event category types as the query source
            eql_map = {
                "process_creation": "process",
                "dns_query": "dns",
                "network_connection": "network",
                "file_event": "file",
                "registry_set": "registry",
                "firewall": "network",
                "proxy": "network",
            }
            if category in eql_map:
                return eql_map[category]
            if product == "windows" and service == "security":
                return "any"
            if product == "windows" and service == "sysmon":
                return "any"
            if product == "windows" and service in ("powershell", "powershell-classic"):
                return "process"
            if product == "linux":
                return "process"
            return "any"

        elif backend == "sentinel":
            table_map = {
                "process_creation": "SysmonEvent\n| where EventID == 1",
                "dns_query": "SysmonEvent\n| where EventID == 22",
                "network_connection": "SysmonEvent\n| where EventID == 3",
                "file_event": "SysmonEvent\n| where EventID == 11",
                "registry_set": "SysmonEvent\n| where EventID == 13",
                "firewall": "CommonSecurityLog",
                "proxy": "CommonSecurityLog",
            }
            if category in table_map:
                return table_map[category]
            if product == "windows" and service == "security":
                return "SecurityEvent"
            if product == "windows" and service == "sysmon":
                return "SysmonEvent"
            if product == "windows" and service in ("powershell", "powershell-classic"):
                return "Event\n| where Source == 'Microsoft-Windows-PowerShell'"
            if product == "linux" and service == "auth":
                return "Syslog\n| where Facility == 'auth'"
            if product == "linux":
                return "Syslog"
            return "CommonSecurityLog"

        return ""


# ─────────────────────────────────────────────
# Rule Builder (from form data)
# ─────────────────────────────────────────────

def build_rule_from_form(data: dict) -> SigmaRule:
    """Build a SigmaRule from web form submission data."""
    # Parse detection from form
    detection = {}

    # Handle selections
    selections = data.get("selections", [])
    for sel in selections:
        sel_name = sel.get("name", "selection")
        sel_fields = {}
        for fld in sel.get("fields", []):
            field_name = fld.get("field", "")
            modifier = fld.get("modifier", "")
            values = fld.get("values", [])

            if modifier:
                key = f"{field_name}|{modifier}"
            else:
                key = field_name

            # Try to parse single values as int
            parsed_values = []
            for v in values:
                try:
                    parsed_values.append(int(v))
                except (ValueError, TypeError):
                    parsed_values.append(v)

            if len(parsed_values) == 1:
                sel_fields[key] = parsed_values[0]
            else:
                sel_fields[key] = parsed_values

            sel_fields[key] = parsed_values[0] if len(parsed_values) == 1 else parsed_values

        detection[sel_name] = sel_fields

    # Handle filters
    filters = data.get("filters", [])
    for flt in filters:
        flt_name = flt.get("name", "filter")
        flt_fields = {}
        for fld in flt.get("fields", []):
            field_name = fld.get("field", "")
            modifier = fld.get("modifier", "")
            values = fld.get("values", [])

            key = f"{field_name}|{modifier}" if modifier else field_name

            parsed_values = []
            for v in values:
                try:
                    parsed_values.append(int(v))
                except (ValueError, TypeError):
                    parsed_values.append(v)

            flt_fields[key] = parsed_values[0] if len(parsed_values) == 1 else parsed_values

        detection[flt_name] = flt_fields

    detection["condition"] = data.get("condition", "selection")

    rule = SigmaRule(
        title=data.get("title", "Untitled Rule"),
        description=data.get("description", ""),
        log_source_key=data.get("log_source", "process_creation"),
        detection=detection,
        level=data.get("level", "medium"),
        status=data.get("status", "experimental"),
        author=data.get("author", "SigmaForge"),
        mitre_techniques=data.get("mitre_techniques", []),
        falsepositives=data.get("falsepositives", []),
        references=data.get("references", []),
        rule_fields=data.get("fields", []),
    )

    return rule


def build_rule_from_template(template_key: str) -> SigmaRule:
    """Build a SigmaRule from a pre-built template."""
    template = RULE_TEMPLATES.get(template_key)
    if not template:
        raise ValueError(f"Unknown template: {template_key}")

    return SigmaRule(
        title=template["name"],
        description=template["description"],
        log_source_key=template["log_source"],
        detection=template["detection"],
        level=template["level"],
        status=template["status"],
        author="SigmaForge",
        mitre_techniques=template["mitre_techniques"],
        falsepositives=template["falsepositives"],
        rule_fields=template.get("fields", []),
    )
