# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
MITRE ATT&CK mapping module with D3FEND mitigations
"""
from typing import Dict, List, Any
import re

from threat_analysis.custom_threats import get_custom_threats


class MitreMapping:
    """Class for managing MITRE ATT&CK mapping with D3FEND mitigations"""
    
    def __init__(self, threat_model=None):
        self.mapping = self._initialize_mapping()
        self.threat_patterns = self._initialize_threat_patterns()
        self.custom_threats = self._load_custom_threats(threat_model)

    def _load_custom_threats(self, threat_model) -> Dict[str, List[Dict[str, Any]]]:
        """Loads custom threats from the custom_threats module."""
        if threat_model:
            return get_custom_threats(threat_model)
        return {}

    def get_custom_threats(self) -> Dict[str, List[Dict[str, Any]]]:
        """Returns the loaded custom threats."""
        return self.custom_threats
        
    def _initialize_mapping(self) -> Dict[str, Dict[str, Any]]:
        """Initializes comprehensive STRIDE to MITRE ATT&CK mapping with D3FEND mitigations"""
        return {
            "Spoofing": {
                "tactics": ["Initial Access", "Defense Evasion", "Credential Access"],
                "techniques": [
                    {
                        "id": "T1566",
                        "name": "Phishing",
                        "description": "Identity spoofing via phishing",
                        "defend_mitigations": [
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Implement multi-factor authentication to reduce phishing effectiveness"},
                            {"id": "D3-UATR", "name": "User Account Control", "description": "User awareness training and security education"},
                            {"id": "D3-EMAL", "name": "Email Filtering", "description": "Deploy email security solutions with phishing detection"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Block malicious domains and URLs"},
                            {"id": "D3-CERT", "name": "Certificate Analysis", "description": "Validate SSL certificates to detect phishing sites"}
                        ]
                    },
                    {
                        "id": "T1036",
                        "name": "Masquerading",
                        "description": "Disguising malicious processes",
                        "defend_mitigations": [
                            {"id": "D3-FAPA", "name": "File Analysis", "description": "Analyze file attributes and signatures"},
                            {"id": "D3-HEUR", "name": "Heuristic Analysis", "description": "Use behavioral analysis to detect masquerading"},
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Implement application allowlisting"},
                            {"id": "D3-PMON", "name": "Process Monitoring", "description": "Monitor process execution and parent-child relationships"}
                        ]
                    },
                    {
                        "id": "T1134",
                        "name": "Access Token Manipulation",
                        "description": "Manipulation of access tokens",
                        "defend_mitigations": [
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement least privilege access controls"},
                            {"id": "D3-TOKM", "name": "Token Analysis", "description": "Monitor token usage and detect anomalies"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to token manipulation"},
                            {"id": "D3-PMON", "name": "Process Monitoring", "description": "Monitor process creation with suspicious tokens"}
                        ]
                    },
                    {
                        "id": "T1078",
                        "name": "Valid Accounts",
                        "description": "Use of valid accounts for access",
                        "defend_mitigations": [
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Enforce MFA for all account access"},
                            {"id": "D3-PWDP", "name": "Strong Password Policy", "description": "Implement and enforce strong password policies"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor account usage patterns and detect anomalies"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement principle of least privilege"}
                        ]
                    },
                    {
                        "id": "T1078.003",
                        "name": "Local Accounts",
                        "description": "Abuse of local accounts",
                        "defend_mitigations": [
                            {"id": "D3-LACM", "name": "Local Account Monitoring", "description": "Monitor local account activity and access patterns"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Restrict local account privileges"},
                            {"id": "D3-ACCL", "name": "Account Lockout", "description": "Implement account lockout policies"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls from local accounts"}
                        ]
                    },
                    {
                        "id": "T1110",
                        "name": "Brute Force",
                        "description": "Attempting to guess or crack passwords",
                        "defend_mitigations": [
                            {"id": "D3-ACCL", "name": "Account Lockout", "description": "Implement progressive account lockout policies"},
                            {"id": "D3-CAPT", "name": "CAPTCHA", "description": "Deploy CAPTCHA systems for authentication"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Implement authentication rate limiting"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Block suspicious IP addresses"},
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Require MFA to mitigate credential compromise"}
                        ]
                    },
                    {
                        "id": "T1110.001",
                        "name": "Password Guessing",
                        "description": "Dictionary-based password attacks",
                        "defend_mitigations": [
                            {"id": "D3-PWDP", "name": "Strong Password Policy", "description": "Enforce complex password requirements"},
                            {"id": "D3-ACCL", "name": "Account Lockout", "description": "Lock accounts after failed attempts"},
                            {"id": "D3-AUTHM", "name": "Authentication Event Thresholding", "description": "Monitor and alert on authentication failures"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Limit authentication attempts per time period"}
                        ]
                    },
                    {
                        "id": "T1110.003",
                        "name": "Password Spraying",
                        "description": "Low-and-slow password attack",
                        "defend_mitigations": [
                            {"id": "D3-AUTHM", "name": "Authentication Event Thresholding", "description": "Detect distributed authentication failures"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Block IP addresses showing spray patterns"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor for unusual login patterns across accounts"},
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Require MFA to prevent password-only attacks"}
                        ]
                    },
                    {
                        "id": "T1110.004",
                        "name": "Credential Stuffing",
                        "description": "Using breached credential pairs",
                        "defend_mitigations": [
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Require MFA for all logins"},
                            {"id": "D3-CRED", "name": "Credential Monitoring", "description": "Monitor for reused credentials from breaches"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Block known bot networks and proxies"},
                            {"id": "D3-BIOS", "name": "Biometric Authentication", "description": "Implement biometric authentication where possible"}
                        ]
                    },
                    {
                        "id": "T1185",
                        "name": "Browser Session Hijacking",
                        "description": "Session hijacking attacks",
                        "defend_mitigations": [
                            {"id": "D3-SESM", "name": "Session Management", "description": "Implement secure session management practices"},
                            {"id": "D3-TLSA", "name": "TLS Analysis", "description": "Use HTTPS everywhere with proper TLS configuration"},
                            {"id": "D3-COOK", "name": "Cookie Security", "description": "Implement secure cookie attributes"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for session anomalies"}
                        ]
                    },
                    {
                        "id": "T1539",
                        "name": "Steal Web Session Cookie",
                        "description": "Session credential theft",
                        "defend_mitigations": [
                            {"id": "D3-COOK", "name": "Cookie Security", "description": "Implement HttpOnly and Secure flags for cookies"},
                            {"id": "D3-SESM", "name": "Session Management", "description": "Use short session timeouts and rotation"},
                            {"id": "D3-TLSA", "name": "TLS Analysis", "description": "Enforce HTTPS for all sensitive operations"},
                            {"id": "D3-WEBS", "name": "Web Session Monitoring", "description": "Monitor web session patterns for anomalies"}
                        ]
                    },
                    {
                        "id": "T1212",
                        "name": "Exploitation for Credential Access",
                        "description": "Exploiting vulnerabilities to access credentials",
                        "defend_mitigations": [
                            {"id": "D3-VULM", "name": "Vulnerability Scanning", "description": "Regular vulnerability scanning and assessment"},
                            {"id": "D3-PATM", "name": "Patch Management", "description": "Implement timely patch management processes"},
                            {"id": "D3-ENDP", "name": "Endpoint Detection", "description": "Deploy endpoint detection and response (EDR)"},
                            {"id": "D3-SEGM", "name": "Network Segmentation", "description": "Implement network segmentation to limit exposure"}
                        ]
                    },
                    {
                        "id": "T1557",
                        "name": "Adversary-in-the-Middle",
                        "description": "Man-in-the-middle attacks",
                        "defend_mitigations": [
                            {"id": "D3-TLSA", "name": "TLS Analysis", "description": "Enforce strong encryption for all communications"},
                            {"id": "D3-CERT", "name": "Certificate Analysis", "description": "Implement certificate pinning and validation"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic for MitM indicators"},
                            {"id": "D3-DNSA", "name": "DNS Analysis", "description": "Use secure DNS and monitor for DNS manipulation"}
                        ]
                    },
                    {
                        "id": "T1556",
                        "name": "Modify Authentication Process",
                        "description": "Authentication bypass techniques",
                        "defend_mitigations": [
                            {"id": "D3-AUTHA", "name": "Authentication Hardening", "description": "Implement robust authentication mechanisms"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls affecting authentication"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor authentication system integrity"},
                            {"id": "D3-AUTHM", "name": "Authentication Event Thresholding", "description": "Monitor authentication logs for anomalies"}
                        ]
                    },
                    {
                        "id": "T1598",
                        "name": "Phishing for Information",
                        "description": "Cross Site Request Forgery attacks",
                        "defend_mitigations": [
                            {"id": "D3-CSRF", "name": "CSRF Protection", "description": "Implement anti-CSRF tokens and SameSite cookies"},
                            {"id": "D3-UATR", "name": "User Account Control", "description": "Educate users about phishing and CSRF attacks"},
                            {"id": "D3-WEBS", "name": "Web Session Monitoring", "description": "Monitor web sessions for suspicious activity"},
                            {"id": "D3-INPV", "name": "Input Validation", "description": "Validate all user inputs and requests"}
                        ]
                    },
                    {
                        "id": "T1213",
                        "name": "Data from Information Repositories",
                        "description": "Exploiting Trust in Client",
                        "defend_mitigations": [
                            {"id": "D3-DLP", "name": "Data Loss Prevention", "description": "Implement comprehensive DLP solutions"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor access to sensitive data repositories"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Restrict access to sensitive repositories"},
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt sensitive data at rest and in transit"}
                        ]
                    }
                ]
            },
            "Tampering": {
                "tactics": ["Defense Evasion", "Impact", "Initial Access", "Execution"],
                "techniques": [
                    {
                        "id": "T1565",
                        "name": "Data Manipulation",
                        "description": "Unauthorized data modification",
                        "defend_mitigations": [
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Implement data integrity checks and monitoring"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor data access and modification activities"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Maintain secure backups with integrity verification"},
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt sensitive data to prevent tampering"}
                        ]
                    },
                    {
                        "id": "T1070",
                        "name": "Indicator Removal",
                        "description": "Deletion of activity traces",
                        "defend_mitigations": [
                            {"id": "D3-LOGM", "name": "Centralized Logging", "description": "Implement centralized and tamper-proof logging"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Secure log backup and retention policies"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor system integrity and log modifications"},
                            {"id": "D3-SIEM", "name": "Security Information Management", "description": "Use SIEM for log analysis and correlation"}
                        ]
                    },
                    {
                        "id": "T1027",
                        "name": "Obfuscated Files or Information",
                        "description": "Obfuscation of malicious content",
                        "defend_mitigations": [
                            {"id": "D3-FAPA", "name": "File Analysis", "description": "Implement advanced file analysis and de-obfuscation"},
                            {"id": "D3-SAND", "name": "Dynamic Analysis", "description": "Use sandboxing for suspicious file analysis"},
                            {"id": "D3-HEUR", "name": "Heuristic Analysis", "description": "Deploy behavioral analysis for obfuscated content"},
                            {"id": "D3-STAT", "name": "Static Analysis", "description": "Perform static analysis on files and scripts"}
                        ]
                    },
                    {
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "description": "Web application vulnerabilities exploitation",
                        "defend_mitigations": [
                            {"id": "D3-WAFF", "name": "Web Application Firewall", "description": "Deploy and configure Web Application Firewalls"},
                            {"id": "D3-VULM", "name": "Vulnerability Scanning", "description": "Regular penetration testing and vulnerability assessment"},
                            {"id": "D3-INPV", "name": "Input Validation", "description": "Implement comprehensive input validation"},
                            {"id": "D3-PATM", "name": "Patch Management", "description": "Maintain current security patches for applications"}
                        ]
                    },
                    {
                        "id": "T1059",
                        "name": "Command and Scripting Interpreter",
                        "description": "Command injection and execution",
                        "defend_mitigations": [
                            {"id": "D3-INPV", "name": "Input Validation", "description": "Implement strict input validation and sanitization"},
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Use application allowlisting to prevent malicious execution"},
                            {"id": "D3-PMON", "name": "Process Monitoring", "description": "Monitor process execution and command-line arguments"},
                            {"id": "D3-SAND", "name": "Dynamic Analysis", "description": "Use sandboxing for script analysis"}
                        ]
                    },
                    {
                        "id": "T1059.007",
                        "name": "JavaScript",
                        "description": "JavaScript-based attacks including XSS",
                        "defend_mitigations": [
                            {"id": "D3-CSP", "name": "Content Security Policy", "description": "Implement and enforce Content Security Policy"},
                            {"id": "D3-INPV", "name": "Input Validation", "description": "Validate and sanitize all user inputs"},
                            {"id": "D3-OUTP", "name": "Output Encoding", "description": "Perform proper output encoding to prevent XSS"},
                            {"id": "D3-WEBS", "name": "Web Session Monitoring", "description": "Monitor web sessions for malicious JavaScript"}
                        ]
                    },
                    {
                        "id": "T1505.003",
                        "name": "Web Shell",
                        "description": "Web shell installation and usage",
                        "defend_mitigations": [
                            {"id": "D3-FAPA", "name": "File Analysis", "description": "Monitor file uploads and analyze for web shells"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor web server file integrity"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic for web shell communications"},
                            {"id": "D3-WAFF", "name": "Web Application Firewall", "description": "Configure WAF to detect web shell activities"}
                        ]
                    },
                    {
                        "id": "T1105",
                        "name": "Ingress Tool Transfer",
                        "description": "Remote file inclusion and malicious file upload",
                        "defend_mitigations": [
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Implement network segmentation and egress filtering"},
                            {"id": "D3-FAPA", "name": "File Analysis", "description": "Analyze all file transfers and uploads"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic for suspicious file transfers"},
                            {"id": "D3-SAND", "name": "Dynamic Analysis", "description": "Sandbox suspicious files before execution"}
                        ]
                    },
                    {
                        "id": "T1211",
                        "name": "Exploitation for Defense Evasion",
                        "description": "Exploiting vulnerabilities to evade defenses",
                        "defend_mitigations": [
                            {"id": "D3-VULM", "name": "Vulnerability Scanning", "description": "Regular security audits and penetration testing"},
                            {"id": "D3-PATM", "name": "Patch Management", "description": "Maintain current security patches"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor system integrity and defense mechanisms"},
                            {"id": "D3-ENDP", "name": "Endpoint Detection", "description": "Deploy advanced endpoint detection and response"}
                        ]
                    },
                    {
                        "id": "T1055",
                        "name": "Process Injection",
                        "description": "Injecting code into privileged processes",
                        "defend_mitigations": [
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Implement application allowlisting"},
                            {"id": "D3-PMON", "name": "Process Monitoring", "description": "Monitor process creation and injection activities"},
                            {"id": "D3-MEMF", "name": "Memory Protection", "description": "Enable memory protection mechanisms"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to process injection"}
                        ]
                    },
                    {
                        "id": "T1562",
                        "name": "Impair Defenses",
                        "description": "Disabling security controls",
                        "defend_mitigations": [
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor security control integrity"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Enforce security configuration management"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls affecting security controls"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Backup security configurations"}
                        ]
                    },
                    {
                        "id": "T1562.001",
                        "name": "Disable or Modify System Firewall",
                        "description": "Firewall manipulation",
                        "defend_mitigations": [
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Implement multiple layers of firewall protection"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Monitor and enforce firewall configurations"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic and firewall logs"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls affecting firewall"}
                        ]
                    },
                    {
                        "id": "T1140",
                        "name": "Deobfuscate/Decode Files or Information",
                        "description": "Processing encoded/obfuscated content",
                        "defend_mitigations": [
                            {"id": "D3-GENERIC-DEFENSE-55", "description": "Implement content inspection"},
                            {"id": "D3-GENERIC-DEFENSE-56", "description": "Use sandboxing for suspicious files"}
                        ]
                    },
                    {
                        "id": "T1083",
                        "name": "File and Directory Discovery",
                        "description": "Discovery of sensitive files and directories",
                        "defend_mitigations": [
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement least privilege access controls"},
                            {"id": "D3-FMON", "name": "File Monitoring", "description": "Monitor file and directory access patterns"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy honeypots and decoy files"},
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt sensitive files and directories"}
                        ]
                    },
                    {
                        "id": "T1574",
                        "name": "Hijack Execution Flow",
                        "description": "Execution flow manipulation",
                        "defend_mitigations": [
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Implement application allowlisting"},
                            {"id": "D3-PMON", "name": "Process Monitoring", "description": "Monitor process execution flows"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor system component integrity"},
                            {"id": "D3-MEMF", "name": "Memory Protection", "description": "Enable memory protection mechanisms"}
                        ]
                    },
                    {
                        "id": "T1071",
                        "name": "Application Layer Protocol",
                        "description": "Protocol manipulation and smuggling",
                        "defend_mitigations": [
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic for protocol anomalies"},
                            {"id": "D3-PROTF", "name": "Protocol Filtering", "description": "Implement protocol-specific filtering"},
                            {"id": "D3-DPI", "name": "Deep Packet Inspection", "description": "Use deep packet inspection for protocol analysis"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter suspicious protocol communications"}
                        ]
                    },
                    {
                        "id": "T1071.001",
                        "name": "Web Protocols",
                        "description": "HTTP/HTTPS protocol manipulation",
                        "defend_mitigations": [
                            {"id": "D3-WAFF", "name": "Web Application Firewall", "description": "Deploy WAF with HTTP protocol inspection"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor HTTP/HTTPS traffic for anomalies"},
                            {"id": "D3-TLSA", "name": "TLS Analysis", "description": "Analyze TLS communications for manipulation"},
                            {"id": "D3-INPV", "name": "Input Validation", "description": "Validate HTTP requests and responses"}
                        ]
                    },
                    {
                        "id": "T1112",
                        "name": "Modify Registry",
                        "description": "Registry manipulation and information tampering",
                        "defend_mitigations": [
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor registry modifications"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor registry integrity"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Enforce registry configuration baselines"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Backup critical registry keys"}
                        ]
                    },
                    {
                        "id": "T1565.001",
                        "name": "Stored Data Manipulation",
                        "description": "XML Schema Poisoning and nested payload attacks",
                        "defend_mitigations": [
                            {"id": "D3-INPV", "name": "Input Validation", "description": "Validate XML schemas and data structures"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor stored data integrity"},
                            {"id": "D3-FAPA", "name": "File Analysis", "description": "Analyze XML and structured data files"},
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt sensitive stored data"}
                        ]
                    },
                    {
                        "id": "T1621",
                        "name": "Multi-Factor Authentication Request Generation",
                        "description": "Removing Important Client Functionality",
                        "defend_mitigations": [
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Implement robust MFA with anomaly detection"},
                            {"id": "D3-AUTHM", "name": "Authentication Event Thresholding", "description": "Monitor MFA request patterns"},
                            {"id": "D3-UATR", "name": "User Account Control", "description": "Educate users about MFA fatigue attacks"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Limit MFA request frequency"}
                        ]
                    },
                    {
                        "id": "T1499.004",
                        "name": "Application or System Exploitation",
                        "description": "Buffer manipulation and overflow attacks",
                        "defend_mitigations": [
                            {"id": "D3-MEMF", "name": "Memory Protection", "description": "Enable memory protection mechanisms"},
                            {"id": "D3-INPV", "name": "Input Validation", "description": "Implement strict input validation"},
                            {"id": "D3-STACK", "name": "Stack Protection", "description": "Enable stack protection mechanisms"},
                            {"id": "D3-VULM", "name": "Vulnerability Scanning", "description": "Regular vulnerability assessments"}
                        ]
                    }
                ]
            },

"Repudiation": {
                "tactics": ["Defense Evasion", "Impact"],
                "techniques": [
                    {
                        "id": "T1070.001",
                        "name": "Clear Windows Event Logs",
                        "description": "Clearing Windows event logs",
                        "defend_mitigations": [
                            {"id": "D3-LOGM", "name": "Centralized Logging", "description": "Implement centralized logging with tamper-proof storage"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Secure backup of log files with integrity verification"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor system integrity and log modifications"},
                            {"id": "D3-SIEM", "name": "Security Information Management", "description": "Use SIEM for log analysis and correlation"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor administrative account activities"}
                        ]
                    },
                    {
                        "id": "T1070.002",
                        "name": "Clear Linux or Mac System Logs",
                        "description": "Clearing Unix/Linux system logs",
                        "defend_mitigations": [
                            {"id": "D3-LOGM", "name": "Centralized Logging", "description": "Implement centralized logging with remote syslog"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Automated backup of system logs"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor file system integrity for log files"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls affecting log files"},
                            {"id": "D3-FMON", "name": "File Monitoring", "description": "Monitor file access and modifications"}
                        ]
                    },
                    {
                        "id": "T1070.003",
                        "name": "Clear Command History",
                        "description": "Clearing command history",
                        "defend_mitigations": [
                            {"id": "D3-LOGM", "name": "Centralized Logging", "description": "Centralize command history logging"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls for command execution"},
                            {"id": "D3-PMON", "name": "Process Monitoring", "description": "Monitor process execution and command-line arguments"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Backup command history files"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor history file integrity"}
                        ]
                    },
                    {
                        "id": "T1070.004",
                        "name": "File Deletion",
                        "description": "Removing files to eliminate traces",
                        "defend_mitigations": [
                            {"id": "D3-FMON", "name": "File Monitoring", "description": "Monitor file deletion activities"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Implement comprehensive backup strategies"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor file system integrity"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls for file operations"},
                            {"id": "D3-FORENS", "name": "Forensic Analysis", "description": "Implement forensic logging capabilities"}
                        ]
                    },
                    {
                        "id": "T1070.006",
                        "name": "Timestomp",
                        "description": "Modifying file timestamps",
                        "defend_mitigations": [
                            {"id": "D3-FMON", "name": "File Monitoring", "description": "Monitor file timestamp modifications"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor file system integrity and timestamps"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls affecting file attributes"},
                            {"id": "D3-FORENS", "name": "Forensic Analysis", "description": "Maintain forensic timeline records"},
                            {"id": "D3-HASH", "name": "File Hashing", "description": "Implement file integrity hashing"}
                        ]
                    },
                    {
                        "id": "T1562",
                        "name": "Impair Defenses",
                        "description": "Disabling logging and monitoring",
                        "defend_mitigations": [
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor security control integrity"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Enforce security configuration management"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls affecting security controls"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Backup security configurations"},
                            {"id": "D3-REDUNDANCY", "name": "Defense Redundancy", "description": "Implement multiple layers of defense"}
                        ]
                    },
                    {
                        "id": "T1562.002",
                        "name": "Disable Windows Event Logging",
                        "description": "Disabling event logging",
                        "defend_mitigations": [
                            {"id": "D3-LOGM", "name": "Centralized Logging", "description": "Implement centralized logging infrastructure"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls affecting logging services"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor logging service integrity"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Enforce logging configuration baselines"},
                            {"id": "D3-SERVM", "name": "Service Monitoring", "description": "Monitor critical service states"}
                        ]
                    },
                    {
                        "id": "T1562.006",
                        "name": "Indicator Blocking",
                        "description": "Blocking security indicators",
                        "defend_mitigations": [
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic for blocked indicators"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor security tool integrity"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls affecting security tools"},
                            {"id": "D3-REDUNDANCY", "name": "Defense Redundancy", "description": "Implement multiple detection mechanisms"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Enforce security tool configurations"}
                        ]
                    },
                    {
                        "id": "T1565.001",
                        "name": "Stored Data Manipulation",
                        "description": "Audit log manipulation",
                        "defend_mitigations": [
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor stored data integrity"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Implement secure data backup with integrity checks"},
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt sensitive stored data"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor data access and modification activities"},
                            {"id": "D3-HASH", "name": "File Hashing", "description": "Implement cryptographic integrity verification"}
                        ]
                    }
                ]
            },
            "InformationDisclosure": {
                "tactics": ["Collection", "Exfiltration", "Discovery", "Reconnaissance"],
                "techniques": [
                    {
                        "id": "T1005",
                        "name": "Data from Local System",
                        "description": "Collecting local sensitive data",
                        "defend_mitigations": [
                            {"id": "D3-DLP", "name": "Data Loss Prevention", "description": "Implement comprehensive DLP solutions"},
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt sensitive data at rest"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor local data access patterns"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement least privilege access controls"},
                            {"id": "D3-FMON", "name": "File Monitoring", "description": "Monitor sensitive file access"}
                        ]
                    },
                    {
                        "id": "T1041",
                        "name": "Exfiltration Over C2 Channel",
                        "description": "Data exfiltration via command and control",
                        "defend_mitigations": [
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic for data exfiltration"},
                            {"id": "D3-DLP", "name": "Data Loss Prevention", "description": "Implement network-based DLP"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter suspicious network communications"},
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt data in transit"},
                            {"id": "D3-SEGM", "name": "Network Segmentation", "description": "Implement network segmentation"}
                        ]
                    },
                    {
                        "id": "T1083",
                        "name": "File and Directory Discovery",
                        "description": "Discovery of sensitive files and directories",
                        "defend_mitigations": [
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement least privilege access controls"},
                            {"id": "D3-FMON", "name": "File Monitoring", "description": "Monitor file and directory access patterns"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy honeypots and decoy files"},
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt sensitive files and directories"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor account access to sensitive areas"}
                        ]
                    },
                    {
                        "id": "T1040",
                        "name": "Network Sniffing",
                        "description": "Network traffic interception and sniffing",
                        "defend_mitigations": [
                            {"id": "D3-TLSA", "name": "TLS Analysis", "description": "Enforce encryption for all network communications"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic for sniffing activities"},
                            {"id": "D3-SEGM", "name": "Network Segmentation", "description": "Implement network segmentation"},
                            {"id": "D3-VPN", "name": "VPN Analysis", "description": "Use VPN for sensitive communications"},
                            {"id": "D3-NIDS", "name": "Network Intrusion Detection", "description": "Deploy network intrusion detection systems"}
                        ]
                    },
                    {
                        "id": "T1592",
                        "name": "Gather Victim Host Information",
                        "description": "Host information gathering and fingerprinting",
                        "defend_mitigations": [
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter reconnaissance traffic"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for reconnaissance activities"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy honeypots to detect reconnaissance"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Harden system configurations"},
                            {"id": "D3-BANNER", "name": "Banner Hiding", "description": "Hide service banners and version information"}
                        ]
                    },
                    {
                        "id": "T1592.002",
                        "name": "Software",
                        "description": "Software fingerprinting and enumeration",
                        "defend_mitigations": [
                            {"id": "D3-BANNER", "name": "Banner Hiding", "description": "Hide software version information"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter fingerprinting attempts"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for software enumeration"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy deceptive software information"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Secure software configurations"}
                        ]
                    },
                    {
                        "id": "T1595",
                        "name": "Active Scanning",
                        "description": "Active reconnaissance and scanning",
                        "defend_mitigations": [
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter and block scanning traffic"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for scanning activities"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Implement rate limiting on services"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy honeypots to detect scanning"},
                            {"id": "D3-NIDS", "name": "Network Intrusion Detection", "description": "Deploy network intrusion detection"}
                        ]
                    },
                    {
                        "id": "T1595.001",
                        "name": "Scanning IP Blocks",
                        "description": "Network scanning and enumeration",
                        "defend_mitigations": [
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Block scanning traffic at network perimeter"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for network scanning patterns"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Implement connection rate limiting"},
                            {"id": "D3-GEOIP", "name": "Geolocation Filtering", "description": "Filter traffic based on geographical location"},
                            {"id": "D3-BLACKL", "name": "IP Blacklisting", "description": "Maintain dynamic IP blacklists"}
                        ]
                    },
                    {
                        "id": "T1595.002",
                        "name": "Vulnerability Scanning",
                        "description": "Vulnerability assessment and scanning",
                        "defend_mitigations": [
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter vulnerability scanning traffic"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for vulnerability scanning activities"},
                            {"id": "D3-VULM", "name": "Vulnerability Scanning", "description": "Perform regular internal vulnerability assessments"},
                            {"id": "D3-PATM", "name": "Patch Management", "description": "Maintain current security patches"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy honeypots to detect scanning"}
                        ]
                    },
                    {
                        "id": "T1589",
                        "name": "Gather Victim Identity Information",
                        "description": "Identity information gathering",
                        "defend_mitigations": [
                            {"id": "D3-OSINT", "name": "OSINT Monitoring", "description": "Monitor open source intelligence for exposed information"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement strong privacy controls"},
                            {"id": "D3-UATR", "name": "User Account Control", "description": "Educate users about information disclosure"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for reconnaissance activities"},
                            {"id": "D3-DLP", "name": "Data Loss Prevention", "description": "Prevent identity information leakage"}
                        ]
                    },
                    {
                        "id": "T1590",
                        "name": "Gather Victim Network Information",
                        "description": "Network information reconnaissance",
                        "defend_mitigations": [
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter network reconnaissance traffic"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for network information gathering"},
                            {"id": "D3-BANNER", "name": "Banner Hiding", "description": "Hide network infrastructure information"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy network honeypots"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Secure network device configurations"}
                        ]
                    },
                    {
                        "id": "T1591",
                        "name": "Gather Victim Org Information",
                        "description": "Organizational information gathering",
                        "defend_mitigations": [
                            {"id": "D3-OSINT", "name": "OSINT Monitoring", "description": "Monitor for organizational information exposure"},
                            {"id": "D3-UATR", "name": "User Account Control", "description": "Educate employees about information security"},
                            {"id": "D3-DLP", "name": "Data Loss Prevention", "description": "Prevent organizational information leakage"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for organizational reconnaissance"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement information classification controls"}
                        ]
                    },
                    {
                        "id": "T1613",
                        "name": "Container and Resource Discovery",
                        "description": "Container and cloud resource discovery",
                        "defend_mitigations": [
                            {"id": "D3-CLOUD", "name": "Cloud Monitoring", "description": "Monitor cloud resource access and discovery"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement least privilege for cloud resources"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor container network communications"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor cloud account activities"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Secure cloud and container configurations"}
                        ]
                    },
                    {
                        "id": "T1046",
                        "name": "Network Service Discovery",
                        "description": "Service enumeration and discovery",
                        "defend_mitigations": [
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter service discovery traffic"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for service enumeration"},
                            {"id": "D3-SERV", "name": "Service Hardening", "description": "Harden and secure network services"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy honeypot services"},
                            {"id": "D3-BANNER", "name": "Banner Hiding", "description": "Hide service banners and information"}
                        ]
                    },
                    {
                        "id": "T1087",
                        "name": "Account Discovery",
                        "description": "User and account enumeration",
                        "defend_mitigations": [
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor account enumeration attempts"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement account security controls"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter account enumeration traffic"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Limit account lookup requests"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy decoy accounts"}
                        ]
                    },
                    {
                        "id": "T1518",
                        "name": "Software Discovery",
                        "description": "Installed software discovery",
                        "defend_mitigations": [
                            {"id": "D3-BANNER", "name": "Banner Hiding", "description": "Hide software version information"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor for software enumeration"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Restrict software information access"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Secure software configurations"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy deceptive software information"}
                        ]
                    },
                    {
                        "id": "T1082",
                        "name": "System Information Discovery",
                        "description": "System configuration discovery",
                        "defend_mitigations": [
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system information queries"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Restrict system information access"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Secure system configurations"},
                            {"id": "D3-BANNER", "name": "Banner Hiding", "description": "Hide system information"},
                            {"id": "D3-DECOY", "name": "Decoy Content", "description": "Deploy deceptive system information"}
                        ]
                    },
                    {
                        "id": "T1213",
                        "name": "Data from Information Repositories",
                        "description": "Lifting sensitive data from caches and repositories",
                        "defend_mitigations": [
                            {"id": "D3-DLP", "name": "Data Loss Prevention", "description": "Implement comprehensive DLP solutions"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Restrict access to sensitive repositories"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor repository access patterns"},
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt sensitive data repositories"},
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Secure backup of sensitive repositories"}
                        ]
                    },
                    {
                        "id": "T1555",
                        "name": "Credentials from Password Stores",
                        "description": "Reverse engineering and white box analysis",
                        "defend_mitigations": [
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt password stores and credential storage"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement secure credential storage"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor credential store access"},
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Require MFA for credential store access"},
                            {"id": "D3-FMON", "name": "File Monitoring", "description": "Monitor password store file access"}
                        ]
                    },
                    {
                        "id": "T1552",
                        "name": "Unsecured Credentials",
                        "description": "Exploiting incorrectly configured SSL/TLS",
                        "defend_mitigations": [
                            {"id": "D3-TLSA", "name": "TLS Analysis", "description": "Implement proper TLS configuration and monitoring"},
                            {"id": "D3-CERT", "name": "Certificate Analysis", "description": "Implement certificate validation and pinning"},
                            {"id": "D3-ENCR", "name": "Data Encryption", "description": "Encrypt all sensitive communications"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Secure SSL/TLS configurations"},
                            {"id": "D3-VULM", "name": "Vulnerability Scanning", "description": "Regular SSL/TLS vulnerability assessment"}
                        ]
                    }
                ]
            },
            "DenialOfService": {
                "tactics": ["Impact"],
                "techniques": [
                    {
                        "id": "T1499",
                        "name": "Endpoint Denial of Service",
                        "description": "Endpoint-focused denial of service",
                        "defend_mitigations": [
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Implement connection and request rate limiting"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter malicious traffic patterns"},
                            {"id": "D3-RESM", "name": "Resource Monitoring", "description": "Monitor system resource utilization"},
                            {"id": "D3-LOAD", "name": "Load Balancing", "description": "Distribute traffic across multiple endpoints"},
                            {"id": "D3-DDOS", "name": "DDoS Protection", "description": "Deploy DDoS protection services"}
                        ]
                    },
                    {
                        "id": "T1499.001",
                        "name": "OS Exhaustion Flood",
                        "description": "Operating system resource exhaustion",
                        "defend_mitigations": [
                            {"id": "D3-RESM", "name": "Resource Monitoring", "description": "Monitor OS resource consumption"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Limit resource-intensive operations"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter resource exhaustion attacks"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Configure OS resource limits"},
                            {"id": "D3-SCALE", "name": "Auto-scaling", "description": "Implement automatic resource scaling"}
                        ]
                    },
                    {
                        "id": "T1499.002",
                        "name": "Service Exhaustion Flood",
                        "description": "Service resource exhaustion",
                        "defend_mitigations": [
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Implement service-level rate limiting"},
                            {"id": "D3-SERVM", "name": "Service Monitoring", "description": "Monitor service resource consumption"},
                            {"id": "D3-LOAD", "name": "Load Balancing", "description": "Distribute service load"},
                            {"id": "D3-QUEUE", "name": "Request Queuing", "description": "Implement request queuing mechanisms"},
                            {"id": "D3-CIRCUIT", "name": "Circuit Breaker", "description": "Implement circuit breaker patterns"}
                        ]
                    },
                    {
                        "id": "T1499.003",
                        "name": "Application Exhaustion Flood",
                        "description": "Application-level resource exhaustion",
                        "defend_mitigations": [
                            {"id": "D3-WAFF", "name": "Web Application Firewall", "description": "Deploy WAF with DoS protection"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Implement application-level rate limiting"},
                            {"id": "D3-RESM", "name": "Resource Monitoring", "description": "Monitor application resource usage"},
                            {"id": "D3-CACHE", "name": "Caching", "description": "Implement application caching strategies"},
                            {"id": "D3-VALID", "name": "Input Validation", "description": "Validate all application inputs"}
                        ]
                    },
                    {
                        "id": "T1499.004",
                        "name": "Application or System Exploitation",
                        "description": "Exploiting vulnerabilities for DoS",
                        "defend_mitigations": [
                            {"id": "D3-VULM", "name": "Vulnerability Scanning", "description": "Regular vulnerability assessments"},
                            {"id": "D3-PATM", "name": "Patch Management", "description": "Maintain current security patches"},
                            {"id": "D3-INPV", "name": "Input Validation", "description": "Implement comprehensive input validation"},
                            {"id": "D3-MEMF", "name": "Memory Protection", "description": "Enable memory protection mechanisms"},
                            {"id": "D3-SAND", "name": "Dynamic Analysis", "description": "Use sandboxing for suspicious content"}
                        ]
                    },
                    {
                        "id": "T1498",
                        "name": "Network Denial of Service",
                        "description": "Network-level denial of service",
                        "defend_mitigations": [
                            {"id": "D3-DDOS", "name": "DDoS Protection", "description": "Deploy comprehensive DDoS protection"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter malicious network traffic"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Implement network-level rate limiting"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic patterns"},
                            {"id": "D3-BLACKHOLE", "name": "Blackhole Routing", "description": "Implement blackhole routing for attacks"}
                        ]
                    },
                    {
                        "id": "T1498.001",
                        "name": "Direct Network Flood",
                        "description": "Direct network flooding attacks",
                        "defend_mitigations": [
                            {"id": "D3-DDOS", "name": "DDoS Protection", "description": "Deploy DDoS protection services"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter and block network flood traffic"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Implement network-level rate limiting"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic for flood patterns"}
                        ]
                    },
                    {
                        "id": "T1498.002",
                        "name": "Reflection Amplification",
                        "description": "Amplification-based DDoS attacks",
                        "defend_mitigations": [
                            {"id": "D3-DDOS", "name": "DDoS Protection", "description": "Deploy DDoS protection services with amplification attack mitigation"},
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Filter and block reflection/amplification traffic"},
                            {"id": "D3-DNSA", "name": "DNS Analysis", "description": "Secure DNS resolvers to prevent amplification"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Implement rate limiting on vulnerable services"}
                        ]
                    },
                    {
                        "id": "T1496",
                        "name": "Resource Hijacking",
                        "description": "System resource hijacking",
                        "defend_mitigations": [
                            {"id": "D3-RESM", "name": "Resource Monitoring", "description": "Monitor system resource utilization for anomalies"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Harden system configurations to prevent resource hijacking"},
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Restrict unauthorized process execution"},
                            {"id": "D3-PMON", "name": "Process Monitoring", "description": "Monitor process resource consumption"}
                        ]
                    },
                    {
                        "id": "T1489",
                        "name": "Service Stop",
                        "description": "Stopping critical services",
                        "defend_mitigations": [
                            {"id": "D3-SERVM", "name": "Service Monitoring", "description": "Monitor critical service states and auto-restart"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Secure service configurations and permissions"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor privileged account activity related to service control"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor integrity of service binaries"}
                        ]
                    },
                    {
                        "id": "T1561",
                        "name": "Disk Wipe",
                        "description": "Disk wiping and data destruction",
                        "defend_mitigations": [
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Implement comprehensive and offsite data backups"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor file system integrity for wiping attempts"},
                            {"id": "D3-ENDP", "name": "Endpoint Detection", "description": "Deploy EDR to detect and prevent disk wiping"},
                            {"id": "D3-FMON", "name": "File Monitoring", "description": "Monitor for mass file deletion or modification"}
                        ]
                    },
                    {
                        "id": "T1485",
                        "name": "Data Destruction",
                        "description": "Destructive data manipulation",
                        "defend_mitigations": [
                            {"id": "D3-BACK", "name": "Data Backup", "description": "Implement comprehensive data backup and recovery"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor data integrity and detect unauthorized modification"},
                            {"id": "D3-DLP", "name": "Data Loss Prevention", "description": "Prevent unauthorized data destruction"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor data access and modification activities"}
                        ]
                    },
                    {
                        "id": "T1499.004",
                        "name": "Application or System Exploitation",
                        "description": "XML Entity Expansion and XML Ping of Death attacks",
                        "defend_mitigations": [
                            {"id": "D3-INPV", "name": "Input Validation", "description": "Validate XML inputs and disable external entities"},
                            {"id": "D3-WAFF", "name": "Web Application Firewall", "description": "Configure WAF to detect XML attacks"},
                            {"id": "D3-RATL", "name": "Rate Limiting", "description": "Limit XML request frequency"},
                            {"id": "D3-RESM", "name": "Resource Monitoring", "description": "Monitor application resource usage for XML attacks"}
                        ]
                    }
                ]
            },
            "ElevationOfPrivilege": {
                "tactics": ["Privilege Escalation", "Defense Evasion", "Persistence"],
                "techniques": [
                    {
                        "id": "T1548",
                        "name": "Abuse Elevation Control Mechanism",
                        "description": "Exploiting elevation control mechanisms",
                        "defend_mitigations": [
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement least privilege access controls"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Enforce secure configuration of elevation mechanisms"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to elevation"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor integrity of elevation control binaries"}
                        ]
                    },
                    {
                        "id": "T1548.001",
                        "name": "Setuid and Setgid",
                        "description": "Unix privilege escalation via setuid/setgid",
                        "defend_mitigations": [
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Restrict execution of setuid/setgid binaries"},
                            {"id": "D3-FMON", "name": "File Monitoring", "description": "Monitor for unauthorized setuid/setgid changes"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Audit and minimize setuid/setgid usage"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor integrity of setuid/setgid files"}
                        ]
                    },
                    {
                        "id": "T1548.002",
                        "name": "Bypass User Account Control",
                        "description": "Windows UAC bypass techniques",
                        "defend_mitigations": [
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Configure UAC to highest security level"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to UAC bypass"},
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Restrict execution of known UAC bypass tools"},
                            {"id": "D3-ENDP", "name": "Endpoint Detection", "description": "Deploy EDR to detect UAC bypass attempts"}
                        ]
                    },
                    {
                        "id": "T1548.003",
                        "name": "Sudo and Sudo Caching",
                        "description": "Sudo abuse for privilege escalation",
                        "defend_mitigations": [
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Implement strict sudo policies (least privilege)"},
                            {"id": "D3-LOGM", "name": "Centralized Logging", "description": "Centralize and monitor sudo logs"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor privileged account activity"},
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Require MFA for sudo access"}
                        ]
                    },
                    {
                        "id": "T1548.004",
                        "name": "Elevated Execution with Prompt",
                        "description": "Prompting for elevated execution",
                        "defend_mitigations": [
                            {"id": "D3-UATR", "name": "User Account Control", "description": "Educate users about suspicious elevation prompts"},
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Restrict execution of unsigned or untrusted executables"},
                            {"id": "D3-ENDP", "name": "Endpoint Detection", "description": "Detect and block suspicious elevated execution attempts"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to elevated execution"}
                        ]
                    },
                    {
                        "id": "T1055",
                        "name": "Process Injection",
                        "description": "Injecting code into privileged processes",
                        "defend_mitigations": [
                            {"id": "D3-MEMF", "name": "Memory Protection", "description": "Enable memory protection mechanisms (ASLR, DEP)"},
                            {"id": "D3-PMON", "name": "Process Monitoring", "description": "Monitor process creation and injection activities"},
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Implement application allowlisting"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to process injection"}
                        ]
                    },
                    {
                        "id": "T1055.001",
                        "name": "Dynamic-link Library Injection",
                        "description": "DLL injection for privilege escalation",
                        "defend_mitigations": [
                            {"id": "D3-MEMF", "name": "Memory Protection", "description": "Enable memory protection mechanisms"},
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Restrict loading of unsigned DLLs"},
                            {"id": "D3-FMON", "name": "File Monitoring", "description": "Monitor for suspicious DLL creation/modification"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to DLL injection"}
                        ]
                    },
                    {
                        "id": "T1068",
                        "name": "Exploitation for Privilege Escalation",
                        "description": "Exploiting vulnerabilities for privilege escalation",
                        "defend_mitigations": [
                            {"id": "D3-VULM", "name": "Vulnerability Scanning", "description": "Regular vulnerability assessments and penetration testing"},
                            {"id": "D3-PATM", "name": "Patch Management", "description": "Implement timely patch management processes"},
                            {"id": "D3-ENDP", "name": "Endpoint Detection", "description": "Deploy EDR to detect exploitation attempts"},
                            {"id": "D3-INPV", "name": "Input Validation", "description": "Implement comprehensive input validation"}
                        ]
                    },
                    {
                        "id": "T1078.001",
                        "name": "Default Accounts",
                        "description": "Using default credentials for elevation",
                        "defend_mitigations": [
                            {"id": "D3-PWDP", "name": "Strong Password Policy", "description": "Change all default passwords"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor for activity on default accounts"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Disable or remove unused default accounts"},
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Enforce MFA for all accounts"}
                        ]
                    },
                    {
                        "id": "T1078.002",
                        "name": "Domain Accounts",
                        "description": "Abusing domain accounts for elevation",
                        "defend_mitigations": [
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement least privilege for domain accounts"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor domain account activity and access patterns"},
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Enforce MFA for domain accounts"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic for suspicious domain authentication"}
                        ]
                    },
                    {
                        "id": "T1078.003",
                        "name": "Local Accounts",
                        "description": "Abusing local accounts for elevation",
                        "defend_mitigations": [
                            {"id": "D3-LACM", "name": "Local Account Monitoring", "description": "Monitor local account activity and access patterns"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Restrict local account privileges"},
                            {"id": "D3-ACCL", "name": "Account Lockout", "description": "Implement account lockout policies"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls from local accounts"}
                        ]
                    },
                    {
                        "id": "T1078.004",
                        "name": "Cloud Accounts",
                        "description": "Abusing cloud accounts for elevation",
                        "defend_mitigations": [
                            {"id": "D3-CLOUD", "name": "Cloud Monitoring", "description": "Monitor cloud account activity and access"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement least privilege for cloud accounts"},
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Enforce MFA for cloud accounts"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Secure cloud configurations and policies"}
                        ]
                    },
                    {
                        "id": "T1134.001",
                        "name": "Token Impersonation/Theft",
                        "description": "Access token impersonation",
                        "defend_mitigations": [
                            {"id": "D3-TOKM", "name": "Token Analysis", "description": "Monitor token usage and detect anomalies"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to token manipulation"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement least privilege to reduce token exposure"},
                            {"id": "D3-ENDP", "name": "Endpoint Detection", "description": "Detect and prevent token theft"}
                        ]
                    },
                    {
                        "id": "T1134.002",
                        "name": "Create Process with Token",
                        "description": "Process creation with stolen tokens",
                        "defend_mitigations": [
                            {"id": "D3-PMON", "name": "Process Monitoring", "description": "Monitor process creation with suspicious tokens"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to process creation with tokens"},
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Restrict execution of unauthorized processes"},
                            {"id": "D3-ENDP", "name": "Endpoint Detection", "description": "Detect and block processes created with stolen tokens"}
                        ]
                    },
                    {
                        "id": "T1134.003",
                        "name": "Make and Impersonate Token",
                        "description": "Token creation and impersonation",
                        "defend_mitigations": [
                            {"id": "D3-TOKM", "name": "Token Analysis", "description": "Monitor token creation and impersonation attempts"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to token creation"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Restrict privileges for token creation"},
                            {"id": "D3-ENDP", "name": "Endpoint Detection", "description": "Detect and prevent token impersonation"}
                        ]
                    },
                    {
                        "id": "T1134.004",
                        "name": "Parent PID Spoofing",
                        "description": "Process parent spoofing for elevation",
                        "defend_mitigations": [
                            {"id": "D3-PMON", "name": "Process Monitoring", "description": "Monitor process parent-child relationships for anomalies"},
                            {"id": "D3-SYSM", "name": "System Call Monitoring", "description": "Monitor system calls related to process creation"},
                            {"id": "D3-ENDP", "name": "Endpoint Detection", "description": "Detect and block parent PID spoofing attempts"},
                            {"id": "D3-EXEC", "name": "Executable Allowlisting", "description": "Restrict execution of processes with suspicious parent PIDs"}
                        ]
                    },
                    {
                        "id": "T1134.005",
                        "name": "SID-History Injection",
                        "description": "SID history manipulation",
                        "defend_mitigations": [
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor for suspicious SID history modifications"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor integrity of security identifiers"},
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Secure Active Directory configurations"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor network traffic for SID history injection indicators"}
                        ]
                    },
                    {
                        "id": "T1484",
                        "name": "Domain Policy Modification",
                        "description": "Privilege abuse and policy manipulation",
                        "defend_mitigations": [
                            {"id": "D3-CONF", "name": "Configuration Management", "description": "Implement strict change control for domain policies"},
                            {"id": "D3-LOGM", "name": "Centralized Logging", "description": "Centralize and monitor domain policy changes"},
                            {"id": "D3-ACCM", "name": "Account Monitoring", "description": "Monitor privileged account activity related to domain policies"},
                            {"id": "D3-INTEG", "name": "System Integrity Monitoring", "description": "Monitor integrity of domain policy files"}
                        ]
                    },
                    {
                        "id": "T1021",
                        "name": "Remote Services",
                        "description": "Lateral movement using remote services",
                        "defend_mitigations": [
                            {"id": "D3-NETF", "name": "Network Traffic Filtering", "description": "Restrict access to remote services"},
                            {"id": "D3-NETM", "name": "Network Monitoring", "description": "Monitor remote service access for anomalies"},
                            {"id": "D3-PRIV", "name": "Credential Hardening", "description": "Implement least privilege for remote service accounts"},
                            {"id": "D3-MFA", "name": "Multi-factor Authentication", "description": "Enforce MFA for remote service access"}
                        ]
                    }
                ]
            }
        }
    
    def _initialize_threat_patterns(self) -> Dict[str, str]:
        """
        Enhanced threat recognition patterns with comprehensive coverage
        """
        return {
            # === Core MITRE ATT&CK Techniques ===
            "T1566": r"(?i)phishing|identity spoofing|social engineering|spear phishing",
            "T1036": r"(?i)masquerading|impersonation|disguise|process masquerading",
            "T1078": r"(?i)valid accounts|compromised credentials|stolen accounts|authentication abuse|authentication bypass|weak authentication|insecure credentials|exploitation of trusted credentials|principal spoof",
            "T1110": r"(?i)brute force|password attack|credential stuffing|password spraying|dictionary attack|encryption brute forcing",
            "T1110.001": r"(?i)dictionary.based password attack|password guessing|dictionary attack",
            "T1185": r"(?i)session hijacking|browser session hijacking",
            "T1539": r"(?i)session cookie|steal.*session|session sidejacking|reusing session ids|session replay|session credential falsification|session.*prediction|session.*manipulation|session.*forging",
            "T1557": r"(?i)man.in.the.middle|adversary.in.the.middle|mitm attack",
            "T1556": r"(?i)authentication bypass|modify authentication|authentication abuse",
            "T1598": r"(?i)cross site request forgery|csrf|phishing for information",
            
            # Tampering and Injection Attacks
            "T1565": r"(?i)data manipulation|process tampering|alteration of data|input data manipulation|parameter injection|audit log manipulation|schema poisoning|xml schema poisoning",
            "T1190": r"(?i)exploit public.facing application|web application exploit|application vulnerability|injection|sql injection|xml injection|command injection|code injection|ldap injection|format string injection|server side include|ssi injection|remote code inclusion|argument injection|dtd injection|resource injection",
            "T1059": r"(?i)command.*injection|scripting interpreter|command execution|shell injection",
            "T1059.007": r"(?i)javascript|xss|cross.site scripting|dom.based xss|reflected xss|stored xss|script injection",
            "T1505.003": r"(?i)web shell|php.*inclusion|remote.*inclusion|file.*inclusion",
            "T1105": r"(?i)ingress tool transfer|malicious file|file upload|remote file inclusion|php remote file inclusion",
            "T1071": r"(?i)application layer protocol|protocol manipulation|communication channel manipulation",
            "T1071.001": r"(?i)web protocols|http.*manipulation|http.*smuggling|http.*splitting|protocol tampering",
            
            # HTTP-specific attacks
            "T1071.001": r"(?i)http request splitting|http response smuggling|http request smuggling|xml routing detour|client.server protocol manipulation",
            
            # Path and Directory Attacks
            "T1083": r"(?i)path traversal|directory traversal|relative path traversal|file.*directory discovery|try all common switches",
            
            # Encoding and Obfuscation
            "T1027": r"(?i)obfuscated files|double encoding|obfuscation|encoding manipulation",
            "T1140": r"(?i)deobfuscate|decode|alternate encoding|leverage alternate encoding",
            
            # Session and Credential Attacks
            "T1212": r"(?i)exploitation for credential access|credential exploitation",
            "T1134": r"(?i)access token manipulation|token manipulation|token theft|token impersonation",
            
            # Information Disclosure and Reconnaissance
            "T1005": r"(?i)sensitive data disclosure|local data|unprotected sensitive data|data leak|credentials aging",
            "T1040": r"(?i)network sniffing|sniffing attacks|interception|cross site tracing",
            "T1592": r"(?i)footprinting|web application fingerprinting|victim host information|software fingerprinting",
            "T1595": r"(?i)active scanning|vulnerability scanning|fuzzing|scanning",
            "T1083": r"(?i)file.*directory discovery|excavation",
            "T1213": r"(?i)exploiting trust in client|data from information repositories|lifting sensitive data.*cache",
            "T1555": r"(?i)reverse engineering|white box reverse engineering|credentials from password stores",
            "T1552": r"(?i)unsecured credentials|exploiting incorrectly configured ssl|ssl/tls misconfiguration",
            
            # JSON and API Attacks
            "T1041": r"(?i)json hijacking|javascript hijacking|api manipulation|exploit.*apis|exploit test apis|exploit script.based apis",
            
            # Registry and Environment
            "T1112": r"(?i)modify registry|manipulate registry|registry manipulation|manipulate registry information",
            "T1574": r"(?i)hijack execution flow|subverting environment variable|environment variable manipulation|command delimiters",
            
            # Content and Interface Attacks
            "T1036": r"(?i)content spoofing|masquerading|iframe overlay",
            
            # Privilege Escalation
            "T1068": r"(?i)privilege escalation|exploitation for privilege escalation|elevation of privilege|vulnerability in the management interface|unpatched.*vulnerabilities|compromise of the management interface",
            "T1548": r"(?i)abuse elevation control|exploiting incorrectly configured access control|functionality misuse|hijacking.*privileged process|catching exception.*privileged",
            "T1055": r"(?i)process injection|hijacking.*privileged process|embedding scripts",
            "T1484": r"(?i)privilege abuse|domain policy modification",
            "T1021": r"(?i)remote services|lateral movement",
            
            # Denial of Service and Buffer Attacks
            "T1499": r"(?i)denial of service|dos attack|endpoint dos|resource exhaustion|flooding|excessive allocation|xml.*blowup|buffer overflow|removing.*functionality|xml entity expansion|xml ping of death",
            "T1498": r"(?i)network denial of service|ddos|network flood|amplification",
            "T1489": r"(?i)service stop|disable.*service",
            "T1499.004": r"(?i)buffer manipulation|overflow buffers|xml entity expansion|xml ping of death",
            
            # Client Function Removal
            "T1621": r"(?i)removing important client functionality|multi.factor authentication request generation",
            
            # Log and Audit Manipulation
            "T1070": r"(?i)indicator removal|log deletion|clear.*logs|audit log manipulation|repudiation of critical actions",
            "T1070.001": r"(?i)clear windows event logs",
            "T1070.002": r"(?i)clear linux.*logs|clear mac.*logs",
            "T1562": r"(?i)impair defenses|disable.*security|functionality misuse|insecure security configuration|hardening",
            "T1562.001": r"(?i)firewall rule misconfiguration|disable or modify system firewall",
            
            # PyTM STRIDE Categories
            "spoofing": "Spoofing",
            "tampering": "Tampering",
            "repudiation": "Repudiation", 
            "informationdisclosure": "InformationDisclosure",
            "information disclosure": "InformationDisclosure",
            "denialofservice": "DenialOfService",
            "denial of service": "DenialOfService",
            "elevationofprivilege": "ElevationOfPrivilege",
            "elevation of privilege": "ElevationOfPrivilege"
        }
    
    def map_threat_to_mitre(self, threat_description: str) -> List[Dict[str, Any]]:
        """Maps a threat description to MITRE ATT&CK techniques using regex patterns."""
        found_techniques = {} # Use dict to store unique techniques by ID
        
        for pattern_value, pattern_regex in self.threat_patterns.items(): # pattern_value can be a T-ID or STRIDE category
            if re.search(pattern_regex, threat_description, re.IGNORECASE):
                # If the pattern_value is a direct MITRE T-ID
                if re.match(r'T\d{4}(?:\.\d{3})?', pattern_value): # Regex to check if it's a T-ID format
                    technique_id = pattern_value
                    # Find technique details across all categories in self.mapping
                    for category_mapping in self.mapping.values():
                        for technique in category_mapping.get("techniques", []):
                            if technique.get("id") == technique_id:
                                tech_copy = technique.copy()
                                tech_copy['tactics'] = category_mapping.get("tactics", []) # Add tactics from the category
                                found_techniques[technique_id] = tech_copy
                                break # Found this technique, move to next pattern
                else: # The pattern_value is likely a STRIDE category
                    stride_category = pattern_value
                    category_mapping = self.mapping.get(stride_category)
                    if category_mapping:
                        # For a STRIDE category, we return all associated techniques
                        # However, for 'map_threat_to_mitre' we want specific matches if possible.
                        # If a specific T-ID pattern didn't match, we fall back to the general STRIDE techniques.
                        # To avoid over-mapping, we only add if no specific T-ID was already found for this description.
                        # This logic might need refinement based on desired precision.
                        for technique in category_mapping.get("techniques", []):
                            # Avoid adding if a more specific T-ID was already found for this description
                            if technique.get("id") not in found_techniques:
                                tech_copy = technique.copy()
                                tech_copy['tactics'] = category_mapping.get("tactics", [])
                                # Ensure defend_mitigations are copied for STRIDE category matches
                                if 'defend_mitigations' in technique:
                                    tech_copy['defend_mitigations'] = technique['defend_mitigations']
                                found_techniques[technique.get("id")] = tech_copy
        
        return list(found_techniques.values())
    
    def get_all_techniques(self) -> List[Dict[str, str]]:
        """Returns all distinct MITRE techniques defined in the mapping."""
        techniques = []
        for threat_info in self.mapping.values():
            techniques.extend(threat_info.get("techniques", []))
        return techniques
    
    def get_techniques_count(self) -> int:
        """Returns the total number of distinct MITRE techniques defined in the mapping."""
        return len(self.get_all_techniques())
    
    def add_custom_mapping(self, threat_type: str, tactics: List[str], techniques: List[Dict[str, str]]):
        """Adds a custom mapping for a STRIDE category."""
        self.mapping[threat_type] = {
            "tactics": tactics,
            "techniques": techniques
        }

        
    def analyze_pytm_threats_list(self, pytm_threats_list: List[Any]) -> Dict[str, Any]:
        """
        Analyzes a list of PyTM threat objects and applies MITRE mapping.
        """
        results = {
            "total_threats": len(pytm_threats_list),
            "stride_distribution": {},
            "mitre_techniques_count": 0,
            "processed_threats": []
        }
        unique_mitre_techniques = set()
        
        for i, threat_tuple in enumerate(pytm_threats_list):
            threat, target = threat_tuple
            
            threat_description = getattr(threat, 'description', '')
            threat_name = getattr(threat, 'name', str(threat.__class__.__name__))
            
            stride_category = self.classify_pytm_threat(threat)
            mitre_techniques = self.map_threat_to_mitre(threat_description)
            mitre_tactics = self.get_tactics_for_threat(stride_category)
            
            processed_threat = {
                "threat_name": threat_name,
                "description": threat_description,
                "target": target,
                "stride_category": stride_category,
                "mitre_tactics": mitre_tactics,
                "mitre_techniques": mitre_techniques,
                "original_threat": threat
            }
            
            results["processed_threats"].append(processed_threat)
            
            if stride_category:
                if stride_category not in results["stride_distribution"]:
                    results["stride_distribution"][stride_category] = 0
                results["stride_distribution"][stride_category] += 1
            
            for tech in mitre_techniques:
                unique_mitre_techniques.add(tech.get("id"))
        
        results["mitre_techniques_count"] = len(unique_mitre_techniques)
        
        print(f"\n=== Final Results ===")
        print(f"Total threats: {results['total_threats']}")
        
        
        
        return results

    def classify_pytm_threat(self, threat) -> str:
        """
        Classifies a threat into a STRIDE category based on its properties.
        """
        # Priority 1: Use the pre-assigned stride_category if it exists
        if hasattr(threat, 'stride_category') and threat.stride_category:
            return threat.stride_category

        # Priority 2: Use the threat's class name if it maps to a STRIDE category
        threat_class_name = threat.__class__.__name__
        if threat_class_name in ['Spoofing', 'Tampering', 'Repudiation', 'InformationDisclosure', 'DenialOfService', 'ElevationOfPrivilege']:
            return threat_class_name

        # Priority 3: Use keyword matching on the threat's description
        description = getattr(threat, 'description', '').lower()
        if not description:
            return 'Unknown'

        # Keywords for each STRIDE category
        stride_keywords = {
            'Spoofing': ['spoof', 'impersonat', 'masquerad', 'phish', 'credential theft'],
            'Tampering': ['tamper', 'modif', 'inject', 'xss', 'cross-site scripting', 'idor'],
            'Repudiation': ['repudiat', 'deny action', 'non-repudiation'],
            'Information Disclosure': ['disclos', 'leak', 'unauthoriz', 'exfiltrat', 'intercept'],
            'Denial of Service': ['dos', 'denial of service', 'flood', 'exhaust'],
            'Elevation of Privilege': ['privilege escalation', 'elevat', 'bypass', 'escalat']
        }

        for category, keywords in stride_keywords.items():
            if any(keyword in description for keyword in keywords):
                return category

        return 'Unknown'


    def get_tactics_for_threat(self, stride_category: str) -> List[str]:
        """
        Enhanced MITRE tactics mapping for STRIDE categories.
        """
        stride_to_tactics = {
            'Information Disclosure': [
                'Collection',
                'Exfiltration', 
                'Discovery'
            ],
            'Tampering': [
                'Defense Evasion',
                'Impact',
                'Initial Access',
                'Execution'
            ],
            'Spoofing': [
                'Initial Access',
                'Credential Access',
                'Defense Evasion'
            ],
            'Denial of Service': [
                'Impact'
            ],
            'Elevation of Privilege': [
                'Privilege Escalation',
                'Defense Evasion'
            ],
            'Repudiation': [
                'Defense Evasion',
                'Impact'
            ]
        }
        
        tactics = stride_to_tactics.get(stride_category, [])
        return tactics
    
    def get_stride_categories(self) -> List[str]:
        """Returns the list of available STRIDE categories."""
        return list(self.mapping.keys())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Returns mapping statistics."""
        return {
            "total_stride_categories": len(self.mapping),
            "total_techniques": self.get_techniques_count(),
            "total_threat_patterns": len(self.threat_patterns),
            "stride_categories": list(self.mapping.keys()),
            "techniques_per_category": {
                category: len(info.get("techniques", []))
                for category, info in self.mapping.items()
            }
        }