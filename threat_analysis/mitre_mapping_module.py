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
import os
import requests
import json
import time
from typing import Dict, List, Any
import re

from threat_analysis.custom_threats import get_custom_threats


class MitreMapping:
    """Class for managing MITRE ATT&CK mapping with D3FEND mitigations"""
    
    def __init__(self, threat_model=None, threat_model_path: str = '/mnt/d/dev/github/threatModelBypyTm/threat_model.md'):
        self.mapping = self._initialize_mapping()
        self.threat_patterns = self._initialize_threat_patterns()
        self.custom_threats = self._load_custom_threats(threat_model)
        self.markdown_mitigations = self._load_mitigations_from_markdown(threat_model_path)
        self.severity_multipliers = self._load_severity_multipliers_from_markdown(threat_model_path)
        self.custom_mitre_mappings = self._load_custom_mitre_mappings_from_markdown(threat_model_path)
        

    def _load_custom_threats(self, threat_model) -> Dict[str, List[Dict[str, Any]]]:
        """Loads custom threats from the custom_threats module."""
        if threat_model:
            return get_custom_threats(threat_model)
        return {}

    def get_custom_threats(self) -> Dict[str, List[Dict[str, Any]]]:
        """Returns the loaded custom threats."""
        return self.custom_threats
        
    def _load_mitigations_from_markdown(self, markdown_file_path: str) -> Dict[str, List[str]]:
        """
        Loads mitigations from the '## Mitigations' section of a Markdown file.
        Expected format:
        ## Mitigations
        - **Threat Name 1**:
            - Mitigation 1
            - Mitigation 2
        - **Threat Name 2**:
            - Mitigation A
        """
        mitigations = {}
        try:
            with open(markdown_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            mitigations_section_match = re.search(r'## Mitigations\n(.*?)(\n## |$)', content, re.DOTALL)
            if mitigations_section_match:
                mitigations_content = mitigations_section_match.group(1).strip()
                
                current_threat = None
                for line in mitigations_content.split('\n'):
                    line = line.strip()
                    if line.startswith('- **') and line.endswith('**:'):
                        current_threat_name = line[len('- **'):-len('**:')].strip()
                        mitre_id_match = re.search(r'\(T\d{4}(?:\.\d{3})?\)', current_threat_name)
                        if mitre_id_match:
                            current_threat = mitre_id_match.group(0)[1:-1] # Extract T-ID without parentheses
                        else:
                            current_threat = current_threat_name # Fallback to full name if no T-ID found
                        mitigations[current_threat] = []
                    elif current_threat and line.startswith('- '):
                        mitigation_text = line[len('- '):].strip()
                        mitigations[current_threat].append(mitigation_text)
        except FileNotFoundError:
            print(f"Warning: Mitigation file not found at {markdown_file_path}")
        except Exception as e:
            print(f"Error loading mitigations from markdown: {e}")
        return mitigations

    def _load_severity_multipliers_from_markdown(self, markdown_file_path: str) -> Dict[str, float]:
        """
        Loads severity multipliers from the '## Severity Multipliers' section of a Markdown file.
        Expected format:
        ## Severity Multipliers
        - **Server Name 1**: 1.5
        - **Server Name 2**: 2.0
        """
        multipliers = {}
        try:
            with open(markdown_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            multipliers_section_match = re.search(r'## Severity Multipliers\n(.*?)(\n## |$)', content, re.DOTALL)
            if multipliers_section_match:
                multipliers_content = multipliers_section_match.group(1).strip()
                
                for line in multipliers_content.split('\n'):
                    line = line.strip()
                    match = re.match(r'- \*\*(.*?)\*\*: (\d+\.\d+)', line)
                    if match:
                        name = match.group(1).strip()
                        value = float(match.group(2))
                        multipliers[name] = value
        except FileNotFoundError:
            print(f"Warning: Severity multipliers file not found at {markdown_file_path}")
        except Exception as e:
            print(f"Error loading severity multipliers from markdown: {e}")
        return multipliers

    def _load_custom_mitre_mappings_from_markdown(self, markdown_file_path: str) -> List[Dict[str, Any]]:
        """
        Loads custom MITRE ATT&CK mappings from the '## Custom Mitre Mapping' section of a Markdown file.
        """
        custom_mappings = []
        try:
            with open(markdown_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            mapping_section_match = re.search(r'## Custom Mitre Mapping\n(.*?)(\n## |$)', content, re.DOTALL)
            if mapping_section_match:
                mappings_content = mapping_section_match.group(1).strip()
                
                # Regex to capture the threat name, tactics, and techniques string
                # It looks for lines starting with '- **Threat Name**:'
                # and then captures the rest of the line which should be a JSON-like string
                pattern = re.compile(r'- \*\*(.*?)\*\*:\s*(tactics=\[.*?\](?:,\s*techniques=\[.*?\])?)')
                
                for line in mappings_content.split('\n'):
                    line = line.strip()
                    match = pattern.match(line)
                    if match:
                        threat_name = match.group(1).strip()
                        json_like_string = match.group(2)
                        
                        # Replace single quotes with double quotes for valid JSON
                        json_like_string = json_like_string.replace("'", '"')
                        
                        # Add curly braces to make it a valid JSON object
                        json_like_string = "{" + json_like_string + "}"
                        
                        try:
                            # Parse the JSON-like string
                            data = json.loads(json_like_string)
                            
                            # Extract tactics and techniques
                            tactics = data.get("tactics", [])
                            techniques = data.get("techniques", [])
                            
                            custom_mappings.append({
                                "threat_name": threat_name,
                                "tactics": tactics,
                                "techniques": techniques
                            })
                        except json.JSONDecodeError as e:
                            print(f"Error decoding JSON for custom mapping '{threat_name}': {e}")
                            print(f"Problematic string: {json_like_string}")
        except FileNotFoundError:
            print(f"Warning: Custom MITRE mapping file not found at {markdown_file_path}")
        except Exception as e:
            print(f"Error loading custom MITRE mappings from markdown: {e}")
        return custom_mappings

    def _initialize_mapping(self) -> Dict[str, Dict[str, Any]]:
        """Initializes comprehensive STRIDE to MITRE ATT&CK mapping with D3FEND mitigations"""
        mapping = {
            "Spoofing": {
                "tactics": ["Initial Access", "Defense Evasion", "Credential Access"],
                "techniques": [
                    {
                        "id": "T1566",
                        "name": "Phishing",
                        "description": "Identity spoofing via phishing",
                        "mitre_mitigations": [
                            {"id": "M1056", "name": "User Training"},
                            {"id": "M1049", "name": "Antivirus/Antimalware"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SEC-AWARE", "name": "Security Awareness Training", "description": "Conduct regular security awareness training for all employees, focusing on phishing recognition"},
                            {"id": "D3-EMAIL-FILTER", "name": "Email Filtering", "description": "Implement email filtering and anti-phishing solutions"},
                            {"id": "D3-EMAIL-AUTH", "name": "Email Authentication", "description": "Use DMARC, SPF, and DKIM to prevent email spoofing"},
                            {"id": "D3-REPORT-SUSP", "name": "Report Suspicious Emails", "description": "Encourage reporting of suspicious emails"},
                            {"id": "D3-MFA", "name": "Multi-Factor Authentication", "description": "Implement strong authentication (MFA) to mitigate credential compromise from phishing"}
                        ]
                    },
                    {
                        "id": "T1036",
                        "name": "Masquerading",
                        "description": "Disguising malicious processes",
                        "mitre_mitigations": [
                            {"id": "M1049", "name": "Antivirus/Antimalware"},
                            {"id": "M1045", "name": "Code Signing"},
                            {"id": "M1038", "name": "Execution Prevention"},
                            {"id": "M1026", "name": "Privileged Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-APP-ALLOW", "name": "Application Allowlisting", "description": "Implement application allowlisting to prevent execution of unauthorized binaries"},
                            {"id": "D3-PROC-MON", "name": "Process Monitoring", "description": "Monitor process creation and parent-child relationships for anomalies"},
                            {"id": "D3-CODE-SIGN", "name": "Code Signing", "description": "Use code signing to verify the authenticity of executables"},
                            {"id": "D3-BEHAV-ANALYSIS", "name": "Behavioral Analysis", "description": "Implement behavioral analysis to detect unusual process activity"},
                            {"id": "D3-SYS-CONFIG-AUDIT", "name": "System Configuration Audit", "description": "Regularly audit system configurations for unauthorized changes"}
                        ]
                    },
                    {
                        "id": "T1134",
                        "name": "Access Token Manipulation",
                        "description": "Manipulation of access tokens",
                        "mitre_mitigations": [
                            {"id": "M1049", "name": "Antivirus/Antimalware"},
                            {"id": "M1043", "name": "Audit"},
                            {"id": "M1028", "name": "Operating System Configuration"},
                            {"id": "M1026", "name": "Privileged Account Management"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-LEAST-PRIV", "name": "Least Privilege", "description": "Implement least privilege for all user accounts and processes"},
                            {"id": "D3-TOKEN-MON", "name": "Token Monitoring", "description": "Monitor for suspicious process injection or token manipulation attempts"},
                            {"id": "D3-EDR", "name": "EDR Solutions", "description": "Use Endpoint Detection and Response (EDR) solutions to detect and prevent such attacks"},
                            {"id": "D3-API-RESTRICT", "name": "API Restriction", "description": "Restrict access to sensitive APIs and system calls"},
                            {"id": "D3-TOKEN-AUDIT", "name": "Token Configuration Audit", "description": "Regularly audit security configurations related to token management"}
                        ]
                    },
                    {
                        "id": "T1078",
                        "name": "Valid Accounts",
                        "description": "Use of valid accounts for access",
                        "mitre_mitigations": [
                            {"id": "M1049", "name": "Antivirus/Antimalware"},
                            {"id": "M1043", "name": "Audit"},
                            {"id": "M1036", "name": "Disable or Remove Feature or Program"},
                            {"id": "M1026", "name": "Privileged Account Management"},
                            {"id": "M1018", "name": "User Account Control"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-STRONG-PASS", "name": "Strong Password Policy", "description": "Enforce strong, unique passwords and multi-factor authentication (MFA) for all accounts"},
                            {"id": "D3-ACC-LOCK", "name": "Account Lockout", "description": "Implement account lockout policies after a certain number of failed login attempts"},
                            {"id": "D3-ACC-REVIEW", "name": "Account Review", "description": "Regularly review and revoke unused or unnecessary accounts"},
                            {"id": "D3-IDM", "name": "Identity Management", "description": "Use a centralized identity management system"},
                            {"id": "D3-LOGIN-MON", "name": "Login Monitoring", "description": "Monitor for unusual login patterns or access from suspicious locations"}
                        ]
                    },
                    {
                        "id": "T1078.003",
                        "name": "Local Accounts",
                        "description": "Abuse of local accounts",
                        "mitre_mitigations": [
                            {"id": "M1049", "name": "Antivirus/Antimalware"},
                            {"id": "M1043", "name": "Audit"},
                            {"id": "M1036", "name": "Disable or Remove Feature or Program"},
                            {"id": "M1026", "name": "Privileged Account Management"},
                            {"id": "M1018", "name": "User Account Control"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-LOCAL-PASS", "name": "Local Password Policy", "description": "Implement strong password policies for local accounts"},
                            {"id": "D3-LOCAL-AUDIT", "name": "Local Account Audit", "description": "Regularly audit local account privileges"},
                            {"id": "D3-LOCAL-LOCKOUT", "name": "Local Account Lockout", "description": "Implement account lockout for local accounts"}
                        ]
                    },
                    {
                        "id": "T1110",
                        "name": "Brute Force",
                        "description": "Attempting to guess or crack passwords",
                        "mitre_mitigations": [
                            {"id": "M1043", "name": "Audit"},
                            {"id": "M1029", "name": "Network Intrusion Prevention"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-ACC-LOCK", "name": "Account Lockout", "description": "Implement account lockout policies after a few failed attempts"},
                            {"id": "D3-MFA", "name": "Multi-Factor Authentication", "description": "Use multi-factor authentication (MFA) for all accounts"},
                            {"id": "D3-RATE-LIMIT", "name": "Rate Limiting", "description": "Implement rate limiting on login attempts"},
                            {"id": "D3-CAPTCHA", "name": "CAPTCHA", "description": "Use CAPTCHA or other bot detection mechanisms"},
                            {"id": "D3-AUTH-LOG-MON", "name": "Authentication Log Monitoring", "description": "Monitor authentication logs for unusual patterns of failed logins"}
                        ]
                    },
                    {
                        "id": "T1110.001",
                        "name": "Password Guessing",
                        "description": "Dictionary-based password attacks",
                        "mitre_mitigations": [
                            {"id": "M1043", "name": "Audit"},
                            {"id": "M1029", "name": "Network Intrusion Prevention"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-STRONG-PASS", "name": "Strong Password Policy", "description": "Enforce strong password policies"},
                            {"id": "D3-ACC-LOCK", "name": "Account Lockout", "description": "Implement account lockout after failed attempts"},
                            {"id": "D3-AUTH-MON", "name": "Authentication Monitoring", "description": "Monitor authentication logs for unusual patterns"}
                        ]
                    },
                    {
                        "id": "T1110.003",
                        "name": "Password Spraying",
                        "description": "Low-and-slow password attack",
                        "mitre_mitigations": [
                            {"id": "M1043", "name": "Audit"},
                            {"id": "M1029", "name": "Network Intrusion Prevention"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-MFA", "name": "Multi-Factor Authentication", "description": "Implement multi-factor authentication (MFA)"},
                            {"id": "D3-LOGIN-MON", "name": "Login Pattern Monitoring", "description": "Monitor for unusual login patterns across multiple accounts"},
                            {"id": "D3-RATE-LIMIT", "name": "Rate Limiting", "description": "Implement rate limiting on authentication attempts"}
                        ]
                    },
                    {
                        "id": "T1110.004",
                        "name": "Credential Stuffing",
                        "description": "Using breached credential pairs",
                        "mitre_mitigations": [
                            {"id": "M1043", "name": "Audit"},
                            {"id": "M1029", "name": "Network Intrusion Prevention"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-MFA", "name": "Multi-Factor Authentication", "description": "Implement multi-factor authentication (MFA) for all accounts"},
                            {"id": "D3-CRED-MON", "name": "Credential Monitoring", "description": "Monitor for credential reuse from known breaches"},
                            {"id": "D3-RATE-LIMIT", "name": "Rate Limiting", "description": "Implement rate limiting on login attempts"}
                        ]
                    },
                    {
                        "id": "T1185",
                        "name": "Browser Session Hijacking",
                        "description": "Session hijacking attacks",
                        "mitre_mitigations": [
                            {"id": "M1028", "name": "Operating System Configuration"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SEC-SESSION", "name": "Secure Session Management", "description": "Implement secure session management practices"},
                            {"id": "D3-HTTPS-ENFORCE", "name": "HTTPS Enforcement", "description": "Enforce HTTPS for all web communications"},
                            {"id": "D3-COOKIE-FLAGS", "name": "Cookie Flags", "description": "Use HttpOnly and Secure flags for session cookies"}
                        ]
                    },
                    {
                        "id": "T1539",
                        "name": "Steal Web Session Cookie",
                        "description": "Session credential theft",
                        "mitre_mitigations": [
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-HTTPONLY-SECURE", "name": "HttpOnly and Secure Flags", "description": "Use HttpOnly and Secure flags for all session cookies"},
                            {"id": "D3-SESSION-TIMEOUT", "name": "Session Timeouts", "description": "Implement short session timeouts and session invalidation upon logout"},
                            {"id": "D3-HTTPS-ENFORCE", "name": "HTTPS Enforcement", "description": "Enforce HTTPS for all web communications"},
                            {"id": "D3-SESSION-MON", "name": "Session Monitoring", "description": "Monitor for unusual session activity or multiple logins from different locations"},
                            {"id": "D3-CSP", "name": "Content Security Policy", "description": "Implement Content Security Policy (CSP) to mitigate XSS attacks that could steal cookies"}
                        ]
                    },
                    {
                        "id": "T1212",
                        "name": "Exploitation for Credential Access",
                        "description": "Exploiting vulnerabilities to access credentials",
                        "mitre_mitigations": [
                            {"id": "M1050", "name": "Exploit Protection"},
                            {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                            {"id": "M1026", "name": "Privileged Account Management"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-PATCH-OS", "name": "Patching and Updates", "description": "Keep all software and operating systems patched and up-to-date"},
                            {"id": "D3-VULN-MGMT", "name": "Vulnerability Management", "description": "Implement vulnerability management programs"},
                            {"id": "D3-STRONG-CRED", "name": "Strong Credentials", "description": "Use strong, unique passwords and MFA"},
                            {"id": "D3-RESTRICT-CRED", "name": "Restrict Credential Access", "description": "Restrict access to credential stores"},
                            {"id": "D3-MON-CRED-ACCESS", "name": "Monitor Credential Access", "description": "Monitor for suspicious access to credential files or registry keys"}
                        ]
                    },
                    {
                        "id": "T1557",
                        "name": "Adversary-in-the-Middle",
                        "description": "Man-in-the-middle attacks",
                        "mitre_mitigations": [
                            {"id": "M1049", "name": "Antivirus/Antimalware"},
                            {"id": "M1043", "name": "Audit"},
                            {"id": "M1028", "name": "Operating System Configuration"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-HTTPS-ENFORCE", "name": "HTTPS Enforcement", "description": "Enforce HTTPS for all web traffic and validate SSL/TLS certificates"},
                            {"id": "D3-CERT-PIN", "name": "Certificate Pinning", "description": "Implement certificate pinning for critical applications"},
                            {"id": "D3-SEC-DNS", "name": "Secure DNS", "description": "Use secure DNS (DNSSEC, DNS over HTTPS/TLS) to prevent DNS spoofing"},
                            {"id": "D3-ARP-MON", "name": "ARP Monitoring", "description": "Monitor network for ARP spoofing or other MitM indicators"},
                            {"id": "D3-NET-AUTH", "name": "Network Device Authentication", "description": "Implement strong authentication for network devices"}
                        ]
                    },
                    {
                        "id": "T1556",
                        "name": "Modify Authentication Process",
                        "description": "Authentication bypass techniques",
                        "mitre_mitigations": [
                            {"id": "M1043", "name": "Audit"},
                            {"id": "M1028", "name": "Operating System Configuration"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-ROBUST-AUTH", "name": "Robust Authentication", "description": "Implement robust authentication mechanisms that are resistant to bypass techniques"},
                            {"id": "D3-AUTH-AUDIT", "name": "Authentication Audit", "description": "Regularly audit authentication logic and configurations"},
                            {"id": "D3-AUTH-LOG-MON", "name": "Authentication Log Monitoring", "description": "Monitor authentication logs for anomalies or failed bypass attempts"},
                            {"id": "D3-SDL-AUTH", "name": "SDL for Authentication", "description": "Use secure development lifecycle (SDL) practices for authentication components"},
                            {"id": "D3-MFA", "name": "Multi-Factor Authentication", "description": "Implement multi-factor authentication (MFA) as an additional layer of security"}
                        ]
                    },
                    {
                        "id": "T1598",
                        "name": "Phishing for Information",
                        "description": "Cross Site Request Forgery attacks",
                        "mitre_mitigations": [
                            {"id": "M1056", "name": "User Training"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-ANTI-CSRF", "name": "Anti-CSRF Tokens", "description": "Implement anti-CSRF tokens in all web forms"},
                            {"id": "D3-SAMESITE", "name": "SameSite Cookies", "description": "Use SameSite cookies to prevent cross-site requests"},
                            {"id": "D3-USER-EDU", "name": "User Education", "description": "Educate users about the risks of clicking suspicious links or submitting forms on untrusted sites"},
                            {"id": "D3-ORIGIN-VALID", "name": "Origin Validation", "description": "Validate the origin of all requests"},
                            {"id": "D3-CSP", "name": "Content Security Policy", "description": "Implement strict Content Security Policy (CSP) to restrict resource loading"}
                        ]
                    },
                    {
                        "id": "T1213",
                        "name": "Data from Information Repositories",
                        "description": "Exploiting Trust in Client",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-ACCESS-CONTROL", "name": "Access Control", "description": "Implement strict access controls and least privilege for data repositories"},
                            {"id": "D3-ENCRYPTION", "name": "Data Encryption", "description": "Encrypt sensitive data at rest"},
                            {"id": "D3-MON-ACCESS", "name": "Access Monitoring", "description": "Monitor access to sensitive data repositories for unusual patterns"},
                            {"id": "D3-DLP", "name": "Data Loss Prevention", "description": "Implement Data Loss Prevention (DLP) solutions"},
                            {"id": "D3-AUDIT-PERM", "name": "Permission Audit", "description": "Regularly audit permissions on data repositories"}
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
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-INTEG-CHECKS", "name": "Data Integrity Checks", "description": "Implement data integrity checks (e.g., hashing, digital signatures)"},
                            {"id": "D3-INPUT-VALID", "name": "Input Validation", "description": "Enforce strict input validation and sanitization for all user-supplied data"},
                            {"id": "D3-SEC-CODING", "name": "Secure Coding Practices", "description": "Use secure coding practices to prevent buffer overflows and other memory corruption issues"},
                            {"id": "D3-ACCESS-CTRL", "name": "Access Controls", "description": "Implement access controls to restrict who can modify sensitive data"},
                            {"id": "D3-BACKUP-VERIFY", "name": "Backup Verification", "description": "Regularly backup data and verify backup integrity"}
                        ]
                    },
                    {
                        "id": "T1070",
                        "name": "Indicator Removal",
                        "description": "Deletion of activity traces",
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-CENTRAL-LOG", "name": "Centralized Logging", "description": "Implement centralized, immutable logging to a secure, remote log server"},
                            {"id": "D3-IMMED-LOG", "name": "Immediate Logging", "description": "Configure systems to send logs immediately to the log server"},
                            {"id": "D3-LOG-PROTECT", "name": "Log Protection", "description": "Protect log files with strong access controls and integrity monitoring"},
                            {"id": "D3-LOG-REVIEW", "name": "Log Review", "description": "Regularly review logs for signs of tampering or deletion"},
                            {"id": "D3-AUDIT-TRAIL", "name": "Audit Trails", "description": "Implement audit trails for administrative actions"}
                        ]
                    },
                    {
                        "id": "T1027",
                        "name": "Obfuscated Files or Information",
                        "description": "Obfuscation of malicious content",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1038", "name": "Execution Prevention"},
                           {"id": "M1029", "name": "Network Intrusion Prevention"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-FILE-ANALYSIS", "name": "File Analysis", "description": "Implement advanced file analysis and de-obfuscation techniques"},
                            {"id": "D3-SANDBOX", "name": "Sandboxing", "description": "Use sandboxing for suspicious file analysis"},
                            {"id": "D3-BEHAV-ANALYSIS", "name": "Behavioral Analysis", "description": "Deploy behavioral analysis for obfuscated content"},
                            {"id": "D3-STATIC-ANALYSIS", "name": "Static Analysis", "description": "Perform static analysis on files and scripts"}
                        ]
                    },
                    {
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "description": "Web application vulnerabilities exploitation",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1030", "name": "Network Segmentation"},
                           {"id": "M1029", "name": "Network Intrusion Prevention"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-WAFF", "name": "Web Application Firewall", "description": "Deploy a Web Application Firewall (WAF) to filter malicious requests"},
                            {"id": "D3-AUDIT", "name": "Security Audits", "description": "Conduct regular security audits and penetration testing of public-facing applications"},
                            {"id": "D3-PATCH", "name": "Patch Management", "description": "Keep all application frameworks, libraries, and dependencies updated to their latest secure versions"},
                            {"id": "D3-API-SEC", "name": "API Security", "description": "Implement secure API design principles, including authentication, authorization, and rate limiting"},
                            {"id": "D3-SQL-INJ", "name": "SQL Injection Prevention", "description": "Use parameterized queries or ORMs to prevent SQL injection"}
                        ]
                    },
                    {
                        "id": "T1059",
                        "name": "Command and Scripting Interpreter",
                        "description": "Command injection and execution",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1038", "name": "Execution Prevention"},
                           {"id": "M1026", "name": "Privileged Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-INPUT-VALID", "name": "Input Validation", "description": "Implement strict input validation and sanitization"},
                            {"id": "D3-APP-ALLOW", "name": "Application Allowlisting", "description": "Use application allowlisting to prevent malicious execution"},
                            {"id": "D3-PROC-MON", "name": "Process Monitoring", "description": "Monitor process execution and command-line arguments"},
                            {"id": "D3-SANDBOX", "name": "Sandboxing", "description": "Use sandboxing for script analysis"}
                        ]
                    },
                    {
                        "id": "T1059.007",
                        "name": "JavaScript",
                        "description": "JavaScript-based attacks including XSS",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1038", "name": "Execution Prevention"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-CSP", "name": "Content Security Policy", "description": "Implement and enforce Content Security Policy"},
                            {"id": "D3-INPUT-VALID", "name": "Input Validation", "description": "Validate and sanitize all user inputs"},
                            {"id": "D3-OUTPUT-ENCODE", "name": "Output Encoding", "description": "Perform proper output encoding to prevent XSS"},
                            {"id": "D3-WEB-SESSION-MON", "name": "Web Session Monitoring", "description": "Monitor web sessions for malicious JavaScript"}
                        ]
                    },
                    {
                        "id": "T1505.003",
                        "name": "Web Shell",
                        "description": "Web shell installation and usage",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1029", "name": "Network Intrusion Prevention"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-FILE-UPLOAD-MON", "name": "File Upload Monitoring", "description": "Monitor file uploads and analyze for web shells"},
                            {"id": "D3-WEB-INTEG", "name": "Web Server Integrity", "description": "Monitor web server file integrity"},
                            {"id": "D3-NET-MON", "name": "Network Monitoring", "description": "Monitor network traffic for web shell communications"},
                            {"id": "D3-WAF-CONFIG", "name": "WAF Configuration", "description": "Configure WAF to detect web shell activities"}
                        ]
                    },
                    {
                        "id": "T1105",
                        "name": "Ingress Tool Transfer",
                        "description": "Remote file inclusion and malicious file upload",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1037", "name": "Filter Network Traffic"},
                           {"id": "M1031", "name": "Network Segmentation"},
                           {"id": "M1029", "name": "Network Intrusion Prevention"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-NET-SEG-EGRESS", "name": "Network Segmentation & Egress Filtering", "description": "Implement network segmentation and egress filtering"},
                            {"id": "D3-FILE-TRANSFER-ANALYSIS", "name": "File Transfer Analysis", "description": "Analyze all file transfers and uploads"},
                            {"id": "D3-SUSP-FILE-TRANSFER-MON", "name": "Suspicious File Transfer Monitoring", "description": "Monitor network traffic for suspicious file transfers"},
                            {"id": "D3-SANDBOX", "name": "Sandboxing", "description": "Sandbox suspicious files before execution"}
                        ]
                    },
                    {
                        "id": "T1211",
                        "name": "Exploitation for Defense Evasion",
                        "description": "Exploiting vulnerabilities to evade defenses",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1026", "name": "Privileged Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SEC-AUDIT", "name": "Security Audits", "description": "Regular security audits and penetration testing"},
                            {"id": "D3-PATCH-MGMT", "name": "Patch Management", "description": "Maintain current security patches"},
                            {"id": "D3-SYS-INTEG-MON", "name": "System Integrity Monitoring", "description": "Monitor system integrity and defense mechanisms"},
                            {"id": "D3-ADV-EDR", "name": "Advanced EDR", "description": "Deploy advanced endpoint detection and response"}
                        ]
                    },
                    {
                        "id": "T1055",
                        "name": "Process Injection",
                        "description": "Injecting code into privileged processes",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1038", "name": "Execution Prevention"},
                           {"id": "M1026", "name": "Privileged Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-MEM-PROTECT", "name": "Memory Protection", "description": "Enable memory protection mechanisms (ASLR, DEP)"},
                            {"id": "D3-PROC-MON", "name": "Process Monitoring", "description": "Monitor process creation and injection activities"},
                            {"id": "D3-APP-ALLOW", "name": "Application Allowlisting", "description": "Implement application allowlisting"},
                            {"id": "D3-SYSCALL-MON", "name": "System Call Monitoring", "description": "Monitor system calls related to process injection"}
                        ]
                    },
                    {
                        "id": "T1562",
                        "name": "Impair Defenses",
                        "description": "Disabling security controls",
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1018", "name": "User Account Control"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SYS-INTEG-MON", "name": "System Integrity Monitoring", "description": "Implement system integrity monitoring to detect changes to security configurations or binaries"},
                            {"id": "D3-CONFIG-BASE", "name": "Configuration Baselines", "description": "Enforce configuration management baselines for all systems"},
                            {"id": "D3-GPO-CONFIG", "name": "GPO/Config Management", "description": "Use Group Policy Objects (GPOs) or configuration management tools to prevent unauthorized changes"},
                            {"id": "D3-SEC-SW-MON", "name": "Security Software Monitoring", "description": "Monitor for attempts to disable security software (antivirus, EDR)"},
                            {"id": "D3-MULTI-LAYER", "name": "Multi-Layered Defense", "description": "Implement multi-layered defenses so that disabling one control doesn't compromise the entire system"}
                        ]
                    },
                    {
                        "id": "T1562.001",
                        "name": "Disable or Modify System Firewall",
                        "description": "Firewall manipulation",
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1018", "name": "User Account Control"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-MULTI-FIREWALL", "name": "Multi-Layer Firewall Protection", "description": "Implement multiple layers of firewall protection"},
                            {"id": "D3-FIREWALL-CONFIG", "name": "Firewall Configuration Enforcement", "description": "Monitor and enforce firewall configurations"},
                            {"id": "D3-NET-FIREWALL-LOGS", "name": "Network & Firewall Log Monitoring", "description": "Monitor network traffic and firewall logs"},
                            {"id": "D3-SYSCALL-FIREWALL", "name": "System Call Monitoring for Firewall", "description": "Monitor system calls affecting firewall"}
                        ]
                    },
                    {
                        "id": "T1140",
                        "name": "Deobfuscate/Decode Files or Information",
                        "description": "Processing encoded/obfuscated content",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1021", "name": "Restrict Web-Based Content"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-CONTENT-INSPECT", "name": "Content Inspection", "description": "Implement content inspection"},
                            {"id": "D3-SANDBOX", "name": "Sandboxing", "description": "Use sandboxing for suspicious files"}
                        ]
                    },
                    {
                        "id": "T1083",
                        "name": "File and Directory Discovery",
                        "description": "Discovery of sensitive files and directories",
                        "defend_mitigations": [
                            {"id": "D3-LEAST-PRIV", "name": "Least Privilege", "description": "Implement least privilege for file and directory access"},
                            {"id": "D3-DIR-LIST", "name": "Directory Listing Restriction", "description": "Restrict directory listing on web servers"},
                            {"id": "D3-FILE-MON", "name": "File Access Monitoring", "description": "Monitor file and directory access for unusual patterns"},
                            {"id": "D3-ENCRYPTION", "name": "File Encryption", "description": "Encrypt sensitive files"},
                            {"id": "D3-HONEYPOT", "name": "Honeypots", "description": "Use honeypots to detect reconnaissance activities"}
                        ]
                    },
                    {
                        "id": "T1574",
                        "name": "Hijack Execution Flow",
                        "description": "Execution flow manipulation",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1038", "name": "Execution Prevention"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-APP-ALLOW", "name": "Application Allowlisting", "description": "Implement application allowlisting"},
                            {"id": "D3-PROC-EXEC-MON", "name": "Process Execution Monitoring", "description": "Monitor process execution flows"},
                            {"id": "D3-SYS-COMP-INTEG", "name": "System Component Integrity", "description": "Monitor system component integrity"},
                            {"id": "D3-MEM-PROTECT", "name": "Memory Protection", "description": "Enable memory protection mechanisms"}
                        ]
                    },
                    {
                        "id": "T1071",
                        "name": "Application Layer Protocol",
                        "description": "Protocol manipulation and smuggling",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"},
                           {"id": "M1029", "name": "Network Intrusion Prevention"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-NET-MON", "name": "Network Monitoring", "description": "Monitor network traffic for protocol anomalies"},
                            {"id": "D3-PROTOCOL-FILTER", "name": "Protocol Filtering", "description": "Implement protocol-specific filtering"},
                            {"id": "D3-DPI", "name": "Deep Packet Inspection", "description": "Use deep packet inspection for protocol analysis"},
                            {"id": "D3-SUSP-PROTOCOL-FILTER", "name": "Suspicious Protocol Filtering", "description": "Filter suspicious protocol communications"}
                        ]
                    },
                    {
                        "id": "T1071.001",
                        "name": "Web Protocols",
                        "description": "HTTP/HTTPS protocol manipulation",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"},
                           {"id": "M1029", "name": "Network Intrusion Prevention"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-WAF-HTTP", "name": "WAF HTTP Inspection", "description": "Deploy WAF with HTTP protocol inspection"},
                            {"id": "D3-HTTP-MON", "name": "HTTP/HTTPS Monitoring", "description": "Monitor HTTP/HTTPS traffic for anomalies"},
                            {"id": "D3-TLS-ANALYSIS", "name": "TLS Communication Analysis", "description": "Analyze TLS communications for manipulation"},
                            {"id": "D3-HTTP-VALID", "name": "HTTP Validation", "description": "Validate HTTP requests and responses"}
                        ]
                    },
                    {
                        "id": "T1112",
                        "name": "Modify Registry",
                        "description": "Registry manipulation and information tampering",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1038", "name": "Execution Prevention"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-REG-MON", "name": "Registry Monitoring", "description": "Monitor registry modifications"},
                            {"id": "D3-REG-INTEG", "name": "Registry Integrity", "description": "Monitor registry integrity"},
                            {"id": "D3-REG-CONFIG", "name": "Registry Configuration", "description": "Enforce registry configuration baselines"},
                            {"id": "D3-REG-BACKUP", "name": "Registry Backup", "description": "Backup critical registry keys"}
                        ]
                    },
                    {
                        "id": "T1565.001",
                        "name": "Stored Data Manipulation",
                        "description": "XML Schema Poisoning and nested payload attacks",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-XML-VALID", "name": "XML Validation", "description": "Validate XML schemas and data structures"},
                            {"id": "D3-STORED-DATA-INTEG", "name": "Stored Data Integrity", "description": "Monitor stored data integrity"},
                            {"id": "D3-XML-ANALYSIS", "name": "XML Analysis", "description": "Analyze XML and structured data files"},
                            {"id": "D3-ENCRYPT-STORED", "name": "Encrypt Stored Data", "description": "Encrypt sensitive stored data"}
                        ]
                    },
                    {
                        "id": "T1621",
                        "name": "Multi-Factor Authentication Request Generation",
                        "description": "Removing Important Client Functionality",
                        "mitre_mitigations": [
                            {"id": "M1033", "name": "Limit Access to Resource Over Network"},
                            {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-MFA-ANOMALY", "name": "MFA Anomaly Detection", "description": "Implement robust MFA with anomaly detection"},
                            {"id": "D3-MFA-REQ-MON", "name": "MFA Request Monitoring", "description": "Monitor MFA request patterns"},
                            {"id": "D3-MFA-FATIGUE-EDU", "name": "MFA Fatigue Education", "description": "Educate users about MFA fatigue attacks"},
                            {"id": "D3-MFA-RATE-LIMIT", "name": "MFA Rate Limiting", "description": "Limit MFA request frequency"}
                        ]
                    },
                    {
                        "id": "T1499.004",
                        "name": "Application or System Exploitation",
                        "description": "Buffer manipulation and overflow attacks",
                        "mitre_mitigations": [
                            {"id": "M1050", "name": "Exploit Protection"},
                            {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                            {"id": "M1030", "name": "Network Segmentation"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-MEM-PROTECT", "name": "Memory Protection", "description": "Enable memory protection mechanisms"},
                            {"id": "D3-INPUT-VALID", "name": "Input Validation", "description": "Implement strict input validation"},
                            {"id": "D3-STACK-PROTECT", "name": "Stack Protection", "description": "Enable stack protection mechanisms"},
                            {"id": "D3-VULN-ASSESS", "name": "Vulnerability Assessment", "description": "Regular vulnerability assessments"}
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
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-CENTRAL-LOG", "name": "Centralized Logging", "description": "Implement centralized logging with tamper-proof storage"},
                            {"id": "D3-SECURE-LOG-BACKUP", "name": "Secure Log Backup", "description": "Secure backup of log files with integrity verification"},
                            {"id": "D3-SYS-INTEG-LOG-MON", "name": "System Integrity & Log Monitoring", "description": "Monitor system integrity and log modifications"},
                            {"id": "D3-SIEM", "name": "SIEM for Log Analysis", "description": "Use SIEM for log analysis and correlation"},
                            {"id": "D3-ADMIN-ACC-MON", "name": "Admin Account Monitoring", "description": "Monitor administrative account activities"}
                        ]
                    },
                    {
                        "id": "T1070.002",
                        "name": "Clear Linux or Mac System Logs",
                        "description": "Clearing Unix/Linux system logs",
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-CENTRAL-LOG-SYSLOG", "name": "Centralized Logging with Syslog", "description": "Implement centralized logging with remote syslog"},
                            {"id": "D3-AUTO-LOG-BACKUP", "name": "Automated Log Backup", "description": "Automated backup of system logs"},
                            {"id": "D3-FS-INTEG-LOG", "name": "File System Integrity for Logs", "description": "Monitor file system integrity for log files"},
                            {"id": "D3-SYSCALL-LOG", "name": "System Call Monitoring for Logs", "description": "Monitor system calls affecting log files"},
                            {"id": "D3-FILE-ACCESS-MON", "name": "File Access Monitoring", "description": "Monitor file access and modifications"}
                        ]
                    },
                    {
                        "id": "T1070.003",
                        "name": "Clear Command History",
                        "description": "Clearing command history",
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-CENTRAL-CMD-LOG", "name": "Centralized Command Logging", "description": "Centralize command history logging"},
                            {"id": "D3-SYSCALL-CMD-EXEC", "name": "System Call Monitoring for Command Execution", "description": "Monitor system calls for command execution"},
                            {"id": "D3-PROC-CMD-MON", "name": "Process Command Monitoring", "description": "Monitor process execution and command-line arguments"},
                            {"id": "D3-CMD-HIST-BACKUP", "name": "Command History Backup", "description": "Backup command history files"},
                            {"id": "D3-HIST-FILE-INTEG", "name": "History File Integrity", "description": "Monitor history file integrity"}
                        ]
                    },
                    {
                        "id": "T1070.004",
                        "name": "File Deletion",
                        "description": "Removing files to eliminate traces",
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-FILE-DEL-MON", "name": "File Deletion Monitoring", "description": "Monitor file deletion activities"},
                            {"id": "D3-COMP-BACKUP", "name": "Comprehensive Backup", "description": "Implement comprehensive backup strategies"},
                            {"id": "D3-FS-INTEG", "name": "File System Integrity", "description": "Monitor file system integrity"},
                            {"id": "D3-SYSCALL-FILE-OPS", "name": "System Call Monitoring for File Operations", "description": "Monitor system calls for file operations"},
                            {"id": "D3-FORENSIC-LOG", "name": "Forensic Logging", "description": "Implement forensic logging capabilities"}
                        ]
                    },
                    {
                        "id": "T1070.006",
                        "name": "Timestomp",
                        "description": "Modifying file timestamps",
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-FILE-TIMESTAMP-MON", "name": "File Timestamp Monitoring", "description": "Monitor file timestamp modifications"},
                            {"id": "D3-FS-INTEG-TIMESTAMP", "name": "File System Integrity & Timestamps", "description": "Monitor file system integrity and timestamps"},
                            {"id": "D3-SYSCALL-FILE-ATTR", "name": "System Call Monitoring for File Attributes", "description": "Monitor system calls affecting file attributes"},
                            {"id": "D3-FORENSIC-TIMELINE", "name": "Forensic Timeline", "description": "Maintain forensic timeline records"},
                            {"id": "D3-FILE-HASHING", "name": "File Hashing", "description": "Implement file integrity hashing"}
                        ]
                    },
                    {
                        "id": "T1562",
                        "name": "Impair Defenses",
                        "description": "Disabling logging and monitoring",
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1018", "name": "User Account Control"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SYS-INTEG-MON", "name": "System Integrity Monitoring", "description": "Implement system integrity monitoring to detect changes to security configurations or binaries"},
                            {"id": "D3-CONFIG-BASE", "name": "Configuration Baselines", "description": "Enforce configuration management baselines for all systems"},
                            {"id": "D3-GPO-CONFIG", "name": "GPO/Config Management", "description": "Use Group Policy Objects (GPOs) or configuration management tools to prevent unauthorized changes"},
                            {"id": "D3-SEC-SW-MON", "name": "Security Software Monitoring", "description": "Monitor for attempts to disable security software (antivirus, EDR)"},
                            {"id": "D3-MULTI-LAYER", "name": "Multi-Layered Defense", "description": "Implement multi-layered defenses so that disabling one control doesn't compromise the entire system"}
                        ]
                    },
                    {
                        "id": "T1562.002",
                        "name": "Disable Windows Event Logging",
                        "description": "Disabling event logging",
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1018", "name": "User Account Control"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-CENTRAL-LOG-INFRA", "name": "Centralized Logging Infrastructure", "description": "Implement centralized logging infrastructure"},
                            {"id": "D3-SYSCALL-LOG-SVC", "name": "System Call Monitoring for Logging Services", "description": "Monitor system calls affecting logging services"},
                            {"id": "D3-LOG-SVC-INTEG", "name": "Logging Service Integrity", "description": "Monitor logging service integrity"},
                            {"id": "D3-LOG-CONFIG-BASE", "name": "Logging Configuration Baselines", "description": "Enforce logging configuration baselines"},
                            {"id": "D3-CRIT-SVC-MON", "name": "Critical Service Monitoring", "description": "Monitor critical service states"}
                        ]
                    },
                    {
                        "id": "T1562.006",
                        "name": "Indicator Blocking",
                        "description": "Blocking security indicators",
                        "mitre_mitigations": [
                           {"id": "M1054", "name": "Software Deployment Tools"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1018", "name": "User Account Control"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-NET-TRAFFIC-MON", "name": "Network Traffic Monitoring", "description": "Monitor network traffic for blocked indicators"},
                            {"id": "D3-SEC-TOOL-INTEG", "name": "Security Tool Integrity", "description": "Monitor security tool integrity"},
                            {"id": "D3-SYSCALL-SEC-TOOL", "name": "System Call Monitoring for Security Tools", "description": "Monitor system calls affecting security tools"},
                            {"id": "D3-MULTI-DETECT", "name": "Multiple Detection Mechanisms", "description": "Implement multiple detection mechanisms"},
                            {"id": "D3-SEC-TOOL-CONFIG", "name": "Security Tool Configuration", "description": "Enforce security tool configurations"}
                        ]
                    },
                    {
                        "id": "T1565.001",
                        "name": "Stored Data Manipulation",
                        "description": "Audit log manipulation",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-STORED-DATA-INTEG", "name": "Stored Data Integrity Monitoring", "description": "Monitor stored data integrity"},
                            {"id": "D3-SECURE-DATA-BACKUP", "name": "Secure Data Backup", "description": "Implement secure data backup with integrity checks"},
                            {"id": "D3-ENCRYPT-SENSITIVE", "name": "Encrypt Sensitive Data", "description": "Encrypt sensitive stored data"},
                            {"id": "D3-DATA-ACCESS-MON", "name": "Data Access Monitoring", "description": "Monitor data access and modification activities"},
                            {"id": "D3-CRYPTO-INTEG", "name": "Cryptographic Integrity Verification", "description": "Implement cryptographic integrity verification"}
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
                            {"id": "D3-ACCESS-CONTROL", "name": "Access Control", "description": "Implement strict access controls and least privilege for local sensitive data"},
                            {"id": "D3-ENCRYPTION", "name": "Data Encryption", "description": "Encrypt sensitive data on local systems"},
                            {"id": "D3-FILE-MON", "name": "File System Monitoring", "description": "Monitor file system access for unusual patterns"},
                            {"id": "D3-EDR", "name": "EDR Solutions", "description": "Use Endpoint Detection and Response (EDR) to detect unauthorized data access"},
                            {"id": "D3-DATA-CLASS", "name": "Data Classification", "description": "Implement data classification and handling policies"}
                        ]
                    },
                    {
                        "id": "T1041",
                        "name": "Exfiltration Over C2 Channel",
                        "description": "Data exfiltration via command and control",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-DLP", "name": "Data Loss Prevention", "description": "Implement Data Loss Prevention (DLP) solutions to monitor and block sensitive data exfiltration"},
                            {"id": "D3-NET-SEG", "name": "Network Segmentation", "description": "Segment networks to limit the scope of potential data breaches"},
                            {"id": "D3-NET-MON", "name": "Network Monitoring", "description": "Monitor network traffic for unusual patterns, large data transfers, or communication with known malicious IPs"},
                            {"id": "D3-ENCRYPTION", "name": "Data Encryption", "description": "Encrypt sensitive data both at rest and in transit"},
                            {"id": "D3-EGRESS-FILTER", "name": "Egress Filtering", "description": "Implement egress filtering to control outbound network connections"}
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
                            {"id": "D3-ENCRYPT-COMM", "name": "Encrypt Communications", "description": "Encrypt all sensitive network communications using strong protocols like TLS 1.2/1.3"},
                            {"id": "D3-NET-SEG", "name": "Network Segmentation", "description": "Implement network segmentation and VLANs to isolate sensitive traffic"},
                            {"id": "D3-SEC-NET-DEV", "name": "Secure Network Devices", "description": "Use secure network devices and configurations"},
                            {"id": "D3-NIDS-NIPS", "name": "NIDS/NIPS Deployment", "description": "Deploy Network Intrusion Detection/Prevention Systems (NIDS/NIPS) to detect sniffing activities"},
                            {"id": "D3-DISABLE-PORTS", "name": "Disable Unused Ports", "description": "Disable unused network ports and services"}
                        ]
                    },
                    {
                        "id": "T1592",
                        "name": "Gather Victim Host Information",
                        "description": "Host information gathering and fingerprinting",
                        "defend_mitigations": [
                            {"id": "D3-MIN-ATTACK-SURF", "name": "Minimize Attack Surface", "description": "Minimize exposed attack surface by disabling unnecessary services and ports"},
                            {"id": "D3-HOST-FIREWALL", "name": "Host-Based Firewalls", "description": "Implement host-based firewalls"},
                            {"id": "D3-NET-SEG", "name": "Network Segmentation", "description": "Use network segmentation"},
                            {"id": "D3-NET-MON", "name": "Network Monitoring", "description": "Monitor network traffic for reconnaissance activities"},
                            {"id": "D3-HIDE-INFO", "name": "Hide System Info", "description": "Hide or obfuscate system and software version information"}
                        ]
                    },
                    {
                        "id": "T1592.002",
                        "name": "Software",
                        "description": "Software fingerprinting and enumeration",
                        "mitre_mitigations": [
                           {"id": "M1036", "name": "Disable or Remove Feature or Program"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-HIDE-VERSION", "name": "Hide Version Information", "description": "Hide software version information"},
                            {"id": "D3-FILTER-FINGERPRINT", "name": "Filter Fingerprinting", "description": "Filter fingerprinting attempts"},
                            {"id": "D3-SOFTWARE-ENUM-MON", "name": "Software Enumeration Monitoring", "description": "Monitor for software enumeration"},
                            {"id": "D3-DECEPTIVE-SOFTWARE", "name": "Deceptive Software Information", "description": "Deploy deceptive software information"},
                            {"id": "D3-SECURE-SOFTWARE-CONFIG", "name": "Secure Software Configuration", "description": "Secure software configurations"}
                        ]
                    },
                    {
                        "id": "T1595",
                        "name": "Active Scanning",
                        "description": "Active reconnaissance and scanning",
                        "defend_mitigations": [
                            {"id": "D3-FIREWALL-IPS", "name": "Firewall/IPS", "description": "Implement firewalls and intrusion prevention systems to block scanning attempts"},
                            {"id": "D3-RATE-LIMIT", "name": "Rate Limiting", "description": "Use rate limiting on public-facing services"},
                            {"id": "D3-NET-LOG-MON", "name": "Network Log Monitoring", "description": "Monitor network logs for signs of active scanning"},
                            {"id": "D3-HONEYPOT", "name": "Honeypots", "description": "Deploy honeypots to detect and analyze scanning activities"},
                            {"id": "D3-PATCH-NET-DEV", "name": "Patch Network Devices", "description": "Keep network devices and software patched"}
                        ]
                    },
                    {
                        "id": "T1595.001",
                        "name": "Scanning IP Blocks",
                        "description": "Network scanning and enumeration",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-BLOCK-SCAN", "name": "Block Scanning Traffic", "description": "Block scanning traffic at network perimeter"},
                            {"id": "D3-NET-SCAN-MON", "name": "Network Scanning Monitoring", "description": "Monitor for network scanning patterns"},
                            {"id": "D3-CONN-RATE-LIMIT", "name": "Connection Rate Limiting", "description": "Implement connection rate limiting"},
                            {"id": "D3-GEO-FILTER", "name": "Geolocation Filtering", "description": "Filter traffic based on geographical location"},
                            {"id": "D3-IP-BLACKLIST", "name": "IP Blacklisting", "description": "Maintain dynamic IP blacklists"}
                        ]
                    },
                    {
                        "id": "T1595.002",
                        "name": "Vulnerability Scanning",
                        "description": "Vulnerability assessment and scanning",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-FILTER-VULN-SCAN", "name": "Filter Vulnerability Scanning", "description": "Filter vulnerability scanning traffic"},
                            {"id": "D3-MON-VULN-SCAN", "name": "Monitor Vulnerability Scanning", "description": "Monitor for vulnerability scanning activities"},
                            {"id": "D3-INTERNAL-VULN-ASSESS", "name": "Internal Vulnerability Assessment", "description": "Perform regular internal vulnerability assessments"},
                            {"id": "D3-PATCH-MGMT", "name": "Patch Management", "description": "Maintain current security patches"},
                            {"id": "D3-HONEYPOT", "name": "Honeypots", "description": "Deploy honeypots to detect scanning"}
                        ]
                    },
                    {
                        "id": "T1589",
                        "name": "Gather Victim Identity Information",
                        "description": "Identity information gathering",
                        "mitre_mitigations": [
                           {"id": "M1056", "name": "User Training"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-OSINT-MON", "name": "OSINT Monitoring", "description": "Monitor open source intelligence for exposed information"},
                            {"id": "D3-PRIVACY-CTRL", "name": "Privacy Controls", "description": "Implement strong privacy controls"},
                            {"id": "D3-USER-EDU", "name": "User Education", "description": "Educate users about information disclosure"},
                            {"id": "D3-RECON-MON", "name": "Reconnaissance Monitoring", "description": "Monitor for reconnaissance activities"},
                            {"id": "D3-ID-LEAK-PREV", "name": "Identity Leakage Prevention", "description": "Prevent identity information leakage"}
                        ]
                    },
                    {
                        "id": "T1590",
                        "name": "Gather Victim Network Information",
                        "description": "Network information reconnaissance",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"},
                           {"id": "M1030", "name": "Network Segmentation"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-NET-RECON-FILTER", "name": "Network Reconnaissance Filtering", "description": "Filter network reconnaissance traffic"},
                            {"id": "D3-NET-INFO-GATHER-MON", "name": "Network Information Gathering Monitoring", "description": "Monitor for network information gathering"},
                            {"id": "D3-HIDE-NET-INFO", "name": "Hide Network Information", "description": "Hide network infrastructure information"},
                            {"id": "D3-NET-HONEYPOT", "name": "Network Honeypots", "description": "Deploy network honeypots"},
                            {"id": "D3-SECURE-NET-CONFIG", "name": "Secure Network Configuration", "description": "Secure network device configurations"}
                        ]
                    },
                    {
                        "id": "T1591",
                        "name": "Gather Victim Org Information",
                        "description": "Organizational information gathering",
                        "mitre_mitigations": [
                           {"id": "M1056", "name": "User Training"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-ORG-INFO-MON", "name": "Organizational Information Monitoring", "description": "Monitor for organizational information exposure"},
                            {"id": "D3-EMP-EDU", "name": "Employee Education", "description": "Educate employees about information security"},
                            {"id": "D3-ORG-INFO-PREV", "name": "Organizational Information Prevention", "description": "Prevent organizational information leakage"},
                            {"id": "D3-ORG-RECON-MON", "name": "Organizational Reconnaissance Monitoring", "description": "Monitor for organizational reconnaissance"},
                            {"id": "D3-INFO-CLASS", "name": "Information Classification", "description": "Implement information classification controls"}
                        ]
                    },
                    {
                        "id": "T1613",
                        "name": "Container and Resource Discovery",
                        "description": "Container and cloud resource discovery",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1030", "name": "Network Segmentation"},
                           {"id": "M1026", "name": "Privileged Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-CLOUD-RES-MON", "name": "Cloud Resource Monitoring", "description": "Monitor cloud resource access and discovery"},
                            {"id": "D3-CLOUD-LEAST-PRIV", "name": "Cloud Least Privilege", "description": "Implement least privilege for cloud resources"},
                            {"id": "D3-CONTAINER-NET-MON", "name": "Container Network Monitoring", "description": "Monitor container network communications"},
                            {"id": "D3-CLOUD-ACC-MON", "name": "Cloud Account Monitoring", "description": "Monitor cloud account activities"},
                            {"id": "D3-SECURE-CLOUD-CONFIG", "name": "Secure Cloud Configuration", "description": "Secure cloud and container configurations"}
                        ]
                    },
                    {
                        "id": "T1046",
                        "name": "Network Service Discovery",
                        "description": "Service enumeration and discovery",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1037", "name": "Filter Network Traffic"},
                           {"id": "M1030", "name": "Network Segmentation"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SVC-DISC-FILTER", "name": "Service Discovery Filtering", "description": "Filter service discovery traffic"},
                            {"id": "D3-SVC-ENUM-MON", "name": "Service Enumeration Monitoring", "description": "Monitor for service enumeration"},
                            {"id": "D3-SVC-HARDEN", "name": "Service Hardening", "description": "Harden and secure network services"},
                            {"id": "D3-HONEYPOT-SVC", "name": "Honeypot Services", "description": "Deploy honeypot services"},
                            {"id": "D3-HIDE-SVC-INFO", "name": "Hide Service Information", "description": "Hide service banners and information"}
                        ]
                    },
                    {
                        "id": "T1087",
                        "name": "Account Discovery",
                        "description": "User and account enumeration",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1033", "name": "Limit Access to Resource Over Network"},
                           {"id": "M1030", "name": "Network Segmentation"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-ACC-ENUM-MON", "name": "Account Enumeration Monitoring", "description": "Monitor account enumeration attempts"},
                            {"id": "D3-ACC-SEC-CTRL", "name": "Account Security Controls", "description": "Implement account security controls"},
                            {"id": "D3-ACC-ENUM-FILTER", "name": "Account Enumeration Filtering", "description": "Filter account enumeration traffic"},
                            {"id": "D3-ACC-LOOKUP-LIMIT", "name": "Account Lookup Limiting", "description": "Limit account lookup requests"},
                            {"id": "D3-DECOY-ACC", "name": "Decoy Accounts", "description": "Deploy decoy accounts"}
                        ]
                    },
                    {
                        "id": "T1518",
                        "name": "Software Discovery",
                        "description": "Installed software discovery",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1038", "name": "Execution Prevention"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-HIDE-SW-VERSION", "name": "Hide Software Version", "description": "Hide software version information"},
                            {"id": "D3-SW-ENUM-MON", "name": "Software Enumeration Monitoring", "description": "Monitor for software enumeration"},
                            {"id": "D3-RESTRICT-SW-INFO", "name": "Restrict Software Information", "description": "Restrict software information access"},
                            {"id": "D3-SECURE-SW-CONFIG", "name": "Secure Software Configuration", "description": "Secure software configurations"},
                            {"id": "D3-DECEPTIVE-SW-INFO", "name": "Deceptive Software Information", "description": "Deploy deceptive software information"}
                        ]
                    },
                    {
                        "id": "T1082",
                        "name": "System Information Discovery",
                        "description": "System configuration discovery",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1038", "name": "Execution Prevention"},
                           {"id": "M1026", "name": "Privileged Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SYS-INFO-QUERY-MON", "name": "System Information Query Monitoring", "description": "Monitor system information queries"},
                            {"id": "D3-RESTRICT-SYS-INFO", "name": "Restrict System Information Access", "description": "Restrict system information access"},
                            {"id": "D3-SECURE-SYS-CONFIG", "name": "Secure System Configuration", "description": "Secure system configurations"},
                            {"id": "D3-HIDE-SYS-INFO", "name": "Hide System Information", "description": "Hide system information"},
                            {"id": "D3-DECEPTIVE-SYS-INFO", "name": "Deceptive System Information", "description": "Deploy deceptive system information"}
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
                        "mitre_mitigations": [
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-ENCRYPT-PASS-STORE", "name": "Encrypt Password Store", "description": "Encrypt password stores and credential storage"},
                            {"id": "D3-SECURE-CRED-STORE", "name": "Secure Credential Storage", "description": "Implement secure credential storage"},
                            {"id": "D3-CRED-STORE-MON", "name": "Credential Store Monitoring", "description": "Monitor credential store access"},
                            {"id": "D3-MFA-CRED-STORE", "name": "MFA for Credential Store", "description": "Require MFA for credential store access"},
                            {"id": "D3-PASS-FILE-MON", "name": "Password File Monitoring", "description": "Monitor password store file access"}
                        ]
                    },
                    {
                        "id": "T1552",
                        "name": "Unsecured Credentials",
                        "description": "Exploiting incorrectly configured SSL/TLS",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-TLS-CONFIG", "name": "TLS Configuration", "description": "Implement proper TLS configuration and monitoring"},
                            {"id": "D3-CERT-VALID", "name": "Certificate Validation", "description": "Implement certificate validation and pinning"},
                            {"id": "D3-ENCRYPT-COMM", "name": "Encrypt Communications", "description": "Encrypt all sensitive communications"},
                            {"id": "D3-SECURE-TLS-CONFIG", "name": "Secure SSL/TLS Configuration", "description": "Secure SSL/TLS configurations"},
                            {"id": "D3-TLS-VULN-ASSESS", "name": "SSL/TLS Vulnerability Assessment", "description": "Regular SSL/TLS vulnerability assessment"}
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
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1030", "name": "Network Segmentation"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-RATE-LIMIT", "name": "Rate Limiting", "description": "Implement rate limiting and throttling on public-facing services"},
                            {"id": "D3-LOAD-BAL", "name": "Load Balancing", "description": "Deploy load balancers to distribute traffic and absorb spikes"},
                            {"id": "D3-FIREWALL-IPS", "name": "Firewall/IPS Configuration", "description": "Configure firewalls and intrusion prevention systems to block DoS attack patterns"},
                            {"id": "D3-RESOURCE-ALLOC", "name": "Resource Allocation", "description": "Ensure sufficient server resources (CPU, memory, bandwidth)"},
                            {"id": "D3-APP-DOS", "name": "Application DoS Protection", "description": "Implement application-level DoS protections (e.g., CAPTCHA, request validation)"}
                        ]
                    },
                    {
                        "id": "T1499.001",
                        "name": "OS Exhaustion Flood",
                        "description": "Operating system resource exhaustion",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1030", "name": "Network Segmentation"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-OS-RES-MON", "name": "OS Resource Monitoring", "description": "Monitor OS resource consumption"},
                            {"id": "D3-RES-INT-LIMIT", "name": "Resource Intensive Limit", "description": "Limit resource-intensive operations"},
                            {"id": "D3-RES-EXHAUST-FILTER", "name": "Resource Exhaustion Filter", "description": "Filter resource exhaustion attacks"},
                            {"id": "D3-OS-RES-CONFIG", "name": "OS Resource Configuration", "description": "Configure OS resource limits"},
                            {"id": "D3-AUTO-RES-SCALE", "name": "Automatic Resource Scaling", "description": "Implement automatic resource scaling"}
                        ]
                    },
                    {
                        "id": "T1499.002",
                        "name": "Service Exhaustion Flood",
                        "description": "Service resource exhaustion",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1030", "name": "Network Segmentation"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SVC-RATE-LIMIT", "name": "Service Rate Limiting", "description": "Implement service-level rate limiting"},
                            {"id": "D3-SVC-RES-MON", "name": "Service Resource Monitoring", "description": "Monitor service resource consumption"},
                            {"id": "D3-SVC-LOAD-DIST", "name": "Service Load Distribution", "description": "Distribute service load"},
                            {"id": "D3-REQ-QUEUE", "name": "Request Queuing", "description": "Implement request queuing mechanisms"},
                            {"id": "D3-CIRCUIT-BREAKER", "name": "Circuit Breaker", "description": "Implement circuit breaker patterns"}
                        ]
                    },
                    {
                        "id": "T1499.003",
                        "name": "Application Exhaustion Flood",
                        "description": "Application-level resource exhaustion",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1030", "name": "Network Segmentation"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-WAF-DOS", "name": "WAF DoS Protection", "description": "Deploy WAF with DoS protection"},
                            {"id": "D3-APP-RATE-LIMIT", "name": "Application Rate Limiting", "description": "Implement application-level rate limiting"},
                            {"id": "D3-APP-RES-MON", "name": "Application Resource Monitoring", "description": "Monitor application resource usage"},
                            {"id": "D3-APP-CACHING", "name": "Application Caching", "description": "Implement application caching strategies"},
                            {"id": "D3-APP-INPUT-VALID", "name": "Application Input Validation", "description": "Validate all application inputs"}
                        ]
                    },
                    {
                        "id": "T1499.004",
                        "name": "Application or System Exploitation",
                        "description": "Exploiting vulnerabilities for DoS",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1030", "name": "Network Segmentation"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-VULN-ASSESS", "name": "Vulnerability Assessment", "description": "Regular vulnerability assessments"},
                            {"id": "D3-PATCH-MGMT", "name": "Patch Management", "description": "Maintain current security patches"},
                            {"id": "D3-COMP-INPUT-VALID", "name": "Comprehensive Input Validation", "description": "Implement comprehensive input validation"},
                            {"id": "D3-MEM-PROTECT", "name": "Memory Protection", "description": "Enable memory protection mechanisms"},
                            {"id": "D3-SANDBOX", "name": "Sandboxing", "description": "Use sandboxing for suspicious content"}
                        ]
                    },
                    {
                        "id": "T1498",
                        "name": "Network Denial of Service",
                        "description": "Network-level denial of service",
                        "defend_mitigations": [
                            {"id": "D3-DDOS-MITIGATION", "name": "DDoS Mitigation Services", "description": "Implement DDoS mitigation services (e.g., cloud-based DDoS protection)"},
                            {"id": "D3-NET-FILTER", "name": "Network Filtering", "description": "Configure network devices to filter and drop malicious traffic"},
                            {"id": "D3-BGP-FLOWSPEC", "name": "BGP Flowspec", "description": "Use BGP Flowspec to mitigate large-scale attacks"},
                            {"id": "D3-BANDWIDTH", "name": "Sufficient Bandwidth", "description": "Ensure network infrastructure has sufficient bandwidth"},
                            {"id": "D3-NET-SEG", "name": "Network Segmentation", "description": "Implement network segmentation"}
                        ]
                    },
                    {
                        "id": "T1498.001",
                        "name": "Direct Network Flood",
                        "description": "Direct network flooding attacks",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-DDOS-PROTECT", "name": "DDoS Protection", "description": "Deploy DDoS protection services"},
                            {"id": "D3-NET-FLOOD-FILTER", "name": "Network Flood Filtering", "description": "Filter and block network flood traffic"},
                            {"id": "D3-NET-RATE-LIMIT", "name": "Network Rate Limiting", "description": "Implement network-level rate limiting"},
                            {"id": "D3-NET-FLOOD-MON", "name": "Network Flood Monitoring", "description": "Monitor network traffic for flood patterns"}
                        ]
                    },
                    {
                        "id": "T1498.002",
                        "name": "Reflection Amplification",
                        "description": "Amplification-based DDoS attacks",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-DDOS-AMP-MIT", "name": "DDoS Amplification Mitigation", "description": "Deploy DDoS protection services with amplification attack mitigation"},
                            {"id": "D3-REFLECT-AMP-FILTER", "name": "Reflection/Amplification Filtering", "description": "Filter and block reflection/amplification traffic"},
                            {"id": "D3-SECURE-DNS", "name": "Secure DNS Resolvers", "description": "Secure DNS resolvers to prevent amplification"},
                            {"id": "D3-RATE-LIMIT-VULN", "name": "Rate Limiting Vulnerable Services", "description": "Implement rate limiting on vulnerable services"}
                        ]
                    },
                    {
                        "id": "T1496",
                        "name": "Resource Hijacking",
                        "description": "System resource hijacking",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1038", "name": "Execution Prevention"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SYS-RES-MON", "name": "System Resource Monitoring", "description": "Monitor system resource utilization for anomalies"},
                            {"id": "D3-HARDEN-SYS-CONFIG", "name": "Harden System Configuration", "description": "Harden system configurations to prevent resource hijacking"},
                            {"id": "D3-RESTRICT-PROC-EXEC", "name": "Restrict Process Execution", "description": "Restrict unauthorized process execution"},
                            {"id": "D3-PROC-RES-CONSUMP-MON", "name": "Process Resource Consumption Monitoring", "description": "Monitor process resource consumption"}
                        ]
                    },
                    {
                        "id": "T1489",
                        "name": "Service Stop",
                        "description": "Stopping critical services",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1018", "name": "User Account Control"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-ACCESS-CONTROL", "name": "Access Control", "description": "Implement robust access controls to prevent unauthorized service termination"},
                            {"id": "D3-SERVICE-MON", "name": "Service Monitoring", "description": "Monitor critical services for availability and unexpected shutdowns"},
                            {"id": "D3-AUTO-RESTART", "name": "Auto Restart", "description": "Configure services to automatically restart upon failure"},
                            {"id": "D3-HOST-FIREWALL", "name": "Host-Based Firewall", "description": "Use host-based firewalls to restrict access to service control ports"},
                            {"id": "D3-CONFIG-BACKUP", "name": "Configuration Backup", "description": "Regularly backup service configurations"}
                        ]
                    },
                    {
                        "id": "T1561",
                        "name": "Disk Wipe",
                        "description": "Disk wiping and data destruction",
                        "mitre_mitigations": [
                           {"id": "M1053", "name": "Data Backup"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-COMP-OFFSITE-BACKUP", "name": "Comprehensive Offsite Backup", "description": "Implement comprehensive and offsite data backups"},
                            {"id": "D3-FS-INTEG-WIPE-MON", "name": "File System Integrity for Wiping", "description": "Monitor file system integrity for wiping attempts"},
                            {"id": "D3-EDR-DISK-WIPE", "name": "EDR for Disk Wipe", "description": "Deploy EDR to detect and prevent disk wiping"},
                            {"id": "D3-MASS-FILE-MON", "name": "Mass File Monitoring", "description": "Monitor for mass file deletion or modification"}
                        ]
                    },
                    {
                        "id": "T1485",
                        "name": "Data Destruction",
                        "description": "Destructive data manipulation",
                        "mitre_mitigations": [
                           {"id": "M1053", "name": "Data Backup"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"},
                           {"id": "M1018", "name": "User Account Control"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-COMP-DATA-BACKUP", "name": "Comprehensive Data Backup", "description": "Implement comprehensive data backup and recovery"},
                            {"id": "D3-DATA-INTEG-MON", "name": "Data Integrity Monitoring", "description": "Monitor data integrity and detect unauthorized modification"},
                            {"id": "D3-UNAUTH-DATA-DEST-PREV", "name": "Unauthorized Data Destruction Prevention", "description": "Prevent unauthorized data destruction"},
                            {"id": "D3-DATA-ACCESS-MOD-MON", "name": "Data Access and Modification Monitoring", "description": "Monitor data access and modification activities"}
                        ]
                    },
                    {
                        "id": "T1499.004",
                        "name": "Application or System Exploitation",
                        "description": "XML Entity Expansion and XML Ping of Death attacks",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1030", "name": "Network Segmentation"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-XML-VALID", "name": "XML Validation", "description": "Validate XML inputs and disable external entities"},
                            {"id": "D3-WAF-XML", "name": "WAF XML Protection", "description": "Configure WAF to detect XML attacks"},
                            {"id": "D3-XML-RATE-LIMIT", "name": "XML Rate Limiting", "description": "Limit XML request frequency"},
                            {"id": "D3-APP-RES-XML-MON", "name": "Application Resource XML Monitoring", "description": "Monitor application resource usage for XML attacks"}
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
                            {"id": "D3-LEAST-PRIV", "name": "Least Privilege", "description": "Implement least privilege for all users and processes"},
                            {"id": "D3-UAC-CONFIG", "name": "UAC Configuration", "description": "Configure UAC (User Account Control) on Windows to the highest setting"},
                            {"id": "D3-ELEV-MON", "name": "Elevation Monitoring", "description": "Monitor for suspicious attempts to bypass elevation controls"},
                            {"id": "D3-ELEV-AUDIT", "name": "Elevation Audit", "description": "Regularly audit configurations of elevation mechanisms"},
                            {"id": "D3-ADMIN-AUTH", "name": "Admin Authentication", "description": "Implement strong authentication for administrative tasks"}
                        ]
                    },
                    {
                        "id": "T1548.001",
                        "name": "Setuid and Setgid",
                        "description": "Unix privilege escalation via setuid/setgid",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1038", "name": "Execution Prevention"},
                           {"id": "M1028", "name": "Operating System Configuration"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-RESTRICT-SETUID", "name": "Restrict Setuid/Setgid", "description": "Restrict execution of setuid/setgid binaries"},
                            {"id": "D3-MON-SETUID-CHANGE", "name": "Monitor Setuid/Setgid Changes", "description": "Monitor for unauthorized setuid/setgid changes"},
                            {"id": "D3-AUDIT-SETUID", "name": "Audit Setuid/Setgid Usage", "description": "Audit and minimize setuid/setgid usage"},
                            {"id": "D3-INTEG-SETUID-FILES", "name": "Integrity of Setuid/Setgid Files", "description": "Monitor integrity of setuid/setgid files"}
                        ]
                    },
                    {
                        "id": "T1548.002",
                        "name": "Bypass User Account Control",
                        "description": "Windows UAC bypass techniques",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1018", "name": "User Account Control"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-UAC-HIGH", "name": "UAC Highest Security", "description": "Configure UAC to highest security level"},
                            {"id": "D3-SYSCALL-UAC-MON", "name": "System Call Monitoring for UAC", "description": "Monitor system calls related to UAC bypass"},
                            {"id": "D3-RESTRICT-UAC-TOOLS", "name": "Restrict UAC Bypass Tools", "description": "Restrict execution of known UAC bypass tools"},
                            {"id": "D3-EDR-UAC", "name": "EDR for UAC Bypass", "description": "Deploy EDR to detect UAC bypass attempts"}
                        ]
                    },
                    {
                        "id": "T1548.003",
                        "name": "Sudo and Sudo Caching",
                        "description": "Sudo abuse for privilege escalation",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SUDO-POLICY", "name": "Sudo Policy", "description": "Implement strict sudo policies (least privilege)"},
                            {"id": "D3-SUDO-LOG-MON", "name": "Sudo Log Monitoring", "description": "Centralize and monitor sudo logs"},
                            {"id": "D3-PRIV-ACC-MON", "name": "Privileged Account Monitoring", "description": "Monitor privileged account activity"},
                            {"id": "D3-MFA-SUDO", "name": "MFA for Sudo", "description": "Require MFA for sudo access"}
                        ]
                    },
                    {
                        "id": "T1548.004",
                        "name": "Elevated Execution with Prompt",
                        "description": "Prompting for elevated execution",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-USER-EDU-ELEV", "name": "User Education on Elevation", "description": "Educate users about suspicious elevation prompts"},
                            {"id": "D3-RESTRICT-UNTRUSTED-EXEC", "name": "Restrict Untrusted Executables", "description": "Restrict execution of unsigned or untrusted executables"},
                            {"id": "D3-DETECT-ELEV-ATTEMPT", "name": "Detect Elevated Execution Attempts", "description": "Detect and block suspicious elevated execution attempts"},
                            {"id": "D3-SYSCALL-ELEV-MON", "name": "System Call Monitoring for Elevated Execution", "description": "Monitor system calls related to elevated execution"}
                        ]
                    },
                    {
                        "id": "T1055",
                        "name": "Process Injection",
                        "description": "Injecting code into privileged processes",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1038", "name": "Execution Prevention"},
                           {"id": "M1026", "name": "Privileged Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-MEM-PROTECT", "name": "Memory Protection", "description": "Implement memory protection mechanisms (ASLR, DEP)"},
                            {"id": "D3-EDR", "name": "EDR Solutions", "description": "Use Endpoint Detection and Response (EDR) solutions to detect and prevent process injection"},
                            {"id": "D3-APP-ALLOW", "name": "Application Allowlisting", "description": "Implement application allowlisting"},
                            {"id": "D3-PROC-MON", "name": "Process Monitoring", "description": "Monitor for suspicious process creation and modification"},
                            {"id": "D3-DEBUG-PRIV", "name": "Restrict Debug Privileges", "description": "Restrict debug privileges"}
                        ]
                    },
                    {
                        "id": "T1055.001",
                        "name": "Dynamic-link Library Injection",
                        "description": "DLL injection for privilege escalation",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1038", "name": "Execution Prevention"},
                           {"id": "M1026", "name": "Privileged Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-MEM-PROTECT", "name": "Memory Protection", "description": "Enable memory protection mechanisms"},
                            {"id": "D3-RESTRICT-UNSIGNED-DLL", "name": "Restrict Unsigned DLLs", "description": "Restrict loading of unsigned DLLs"},
                            {"id": "D3-DLL-MON", "name": "DLL Monitoring", "description": "Monitor for suspicious DLL creation/modification"},
                            {"id": "D3-SYSCALL-DLL-INJECT", "name": "System Call Monitoring for DLL Injection", "description": "Monitor system calls related to DLL injection"}
                        ]
                    },
                    {
                        "id": "T1068",
                        "name": "Exploitation for Privilege Escalation",
                        "description": "Exploiting vulnerabilities for privilege escalation",
                        "mitre_mitigations": [
                           {"id": "M1050", "name": "Exploit Protection"},
                           {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1018", "name": "User Account Control"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-PATCH-MGMT", "name": "Patch Management", "description": "Implement a robust patch management program to address known vulnerabilities promptly"},
                            {"id": "D3-LEAST-PRIV", "name": "Least Privilege", "description": "Apply the principle of least privilege to all users and processes"},
                            {"id": "D3-VULN-SCAN", "name": "Vulnerability Scanning", "description": "Regularly scan systems for vulnerabilities and misconfigurations"},
                            {"id": "D3-EDR", "name": "EDR Solutions", "description": "Use Endpoint Detection and Response (EDR) solutions to detect and prevent exploitation attempts"},
                            {"id": "D3-APP-ALLOW", "name": "Application Allowlisting", "description": "Implement application allowlisting to prevent the execution of unauthorized software"}
                        ]
                    },
                    {
                        "id": "T1078.001",
                        "name": "Default Accounts",
                        "description": "Using default credentials for elevation",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1036", "name": "Disable or Remove Feature or Program"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1018", "name": "User Account Control"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-CHANGE-DEFAULT-PASS", "name": "Change Default Passwords", "description": "Change all default passwords"},
                            {"id": "D3-MON-DEFAULT-ACC", "name": "Monitor Default Accounts", "description": "Monitor for activity on default accounts"},
                            {"id": "D3-DISABLE-UNUSED-ACC", "name": "Disable Unused Accounts", "description": "Disable or remove unused default accounts"},
                            {"id": "D3-MFA-ALL-ACC", "name": "MFA for All Accounts", "description": "Enforce MFA for all accounts"}
                        ]
                    },
                    {
                        "id": "T1078.002",
                        "name": "Domain Accounts",
                        "description": "Abusing domain accounts for elevation",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1036", "name": "Disable or Remove Feature or Program"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1018", "name": "User Account Control"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-LEAST-PRIV-DOMAIN", "name": "Least Privilege for Domain Accounts", "description": "Implement least privilege for domain accounts"},
                            {"id": "D3-DOMAIN-ACC-MON", "name": "Domain Account Monitoring", "description": "Monitor domain account activity and access patterns"},
                            {"id": "D3-MFA-DOMAIN", "name": "MFA for Domain Accounts", "description": "Enforce MFA for domain accounts"},
                            {"id": "D3-NET-MON-DOMAIN-AUTH", "name": "Network Monitoring for Domain Authentication", "description": "Monitor network traffic for suspicious domain authentication"}
                        ]
                    },
                    {
                        "id": "T1078.003",
                        "name": "Local Accounts",
                        "description": "Abusing local accounts for elevation",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1036", "name": "Disable or Remove Feature or Program"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1018", "name": "User Account Control"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-LOCAL-PASS", "name": "Local Password Policy", "description": "Implement strong password policies for local accounts"},
                            {"id": "D3-LOCAL-AUDIT", "name": "Local Account Audit", "description": "Regularly audit local account privileges"},
                            {"id": "D3-LOCAL-LOCKOUT", "name": "Local Account Lockout", "description": "Implement account lockout for local accounts"}
                        ]},
                    {
                        "id": "T1078.004",
                        "name": "Cloud Accounts",
                        "description": "Abusing cloud accounts for elevation",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1036", "name": "Disable or Remove Feature or Program"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1018", "name": "User Account Control"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-CLOUD-ACC-MON", "name": "Cloud Account Monitoring", "description": "Monitor cloud account activity and access"},
                            {"id": "D3-CLOUD-LEAST-PRIV", "name": "Cloud Least Privilege", "description": "Implement least privilege for cloud accounts"},
                            {"id": "D3-MFA-CLOUD", "name": "MFA for Cloud Accounts", "description": "Enforce MFA for cloud accounts"},
                            {"id": "D3-SECURE-CLOUD-CONFIG", "name": "Secure Cloud Configuration", "description": "Secure cloud configurations and policies"}
                        ]
                    },
                    {
                        "id": "T1134.001",
                        "name": "Token Impersonation/Theft",
                        "description": "Access token impersonation",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-TOKEN-USAGE-MON", "name": "Token Usage Monitoring", "description": "Monitor token usage and detect anomalies"},
                            {"id": "D3-SYSCALL-TOKEN-MON", "name": "System Call Monitoring for Token Manipulation", "description": "Monitor system calls related to token manipulation"},
                            {"id": "D3-LEAST-PRIV-TOKEN", "name": "Least Privilege for Tokens", "description": "Implement least privilege to reduce token exposure"},
                            {"id": "D3-DETECT-TOKEN-THEFT", "name": "Detect Token Theft", "description": "Detect and prevent token theft"}
                        ]
                    },
                    {
                        "id": "T1134.002",
                        "name": "Create Process with Token",
                        "description": "Process creation with stolen tokens",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-PROC-CREATE-MON", "name": "Process Creation Monitoring", "description": "Monitor process creation with suspicious tokens"},
                            {"id": "D3-SYSCALL-PROC-TOKEN-MON", "name": "System Call Monitoring for Process Creation with Tokens", "description": "Monitor system calls related to process creation with tokens"},
                            {"id": "D3-RESTRICT-UNAUTH-PROC", "name": "Restrict Unauthorized Processes", "description": "Restrict execution of unauthorized processes"},
                            {"id": "D3-DETECT-STOLEN-TOKEN-PROC", "name": "Detect Stolen Token Processes", "description": "Detect and block processes created with stolen tokens"}
                        ]
                    },
                    {
                        "id": "T1134.003",
                        "name": "Make and Impersonate Token",
                        "description": "Token creation and impersonation",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-TOKEN-CREATE-MON", "name": "Token Creation Monitoring", "description": "Monitor token creation and impersonation attempts"},
                            {"id": "D3-SYSCALL-TOKEN-CREATE-MON", "name": "System Call Monitoring for Token Creation", "description": "Monitor system calls related to token creation"},
                            {"id": "D3-RESTRICT-TOKEN-PRIV", "name": "Restrict Token Privileges", "description": "Restrict privileges for token creation"},
                            {"id": "D3-DETECT-TOKEN-IMP", "name": "Detect Token Impersonation", "description": "Detect and prevent token impersonation"}
                        ]
                    },
                    {
                        "id": "T1134.004",
                        "name": "Parent PID Spoofing",
                        "description": "Process parent spoofing for elevation",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-PROC-PARENT-MON", "name": "Process Parent Monitoring", "description": "Monitor process parent-child relationships for anomalies"},
                            {"id": "D3-SYSCALL-PROC-CREATE-MON", "name": "System Call Monitoring for Process Creation", "description": "Monitor system calls related to process creation"},
                            {"id": "D3-DETECT-PID-SPOOF", "name": "Detect PID Spoofing", "description": "Detect and block parent PID spoofing attempts"},
                            {"id": "D3-RESTRICT-SUSP-PID", "name": "Restrict Suspicious PIDs", "description": "Restrict execution of processes with suspicious parent PIDs"}
                        ]
                    },
                    {
                        "id": "T1134.005",
                        "name": "SID-History Injection",
                        "description": "SID history manipulation",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-SID-HIST-MON", "name": "SID History Monitoring", "description": "Monitor for suspicious SID history modifications"},
                            {"id": "D3-SEC-ID-INTEG", "name": "Security Identifier Integrity", "description": "Monitor integrity of security identifiers"},
                            {"id": "D3-SECURE-AD-CONFIG", "name": "Secure Active Directory Configuration", "description": "Secure Active Directory configurations"},
                            {"id": "D3-NET-MON-SID-INJECT", "name": "Network Monitoring for SID Injection", "description": "Monitor network traffic for SID history injection indicators"}
                        ]
                    },
                    {
                        "id": "T1484",
                        "name": "Domain Policy Modification",
                        "description": "Privilege abuse and policy manipulation",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"},
                           {"id": "M1026", "name": "Privileged Account Management"},
                           {"id": "M1017", "name": "User Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-DOMAIN-POLICY-CHANGE-CTRL", "name": "Domain Policy Change Control", "description": "Implement strict change control for domain policies"},
                            {"id": "D3-CENTRAL-DOMAIN-POLICY-MON", "name": "Centralized Domain Policy Monitoring", "description": "Centralize and monitor domain policy changes"},
                            {"id": "D3-PRIV-ACC-DOMAIN-POLICY-MON", "name": "Privileged Account Domain Policy Monitoring", "description": "Monitor privileged account activity related to domain policies"},
                            {"id": "D3-DOMAIN-POLICY-INTEG", "name": "Domain Policy Integrity", "description": "Monitor integrity of domain policy files"}
                        ]
                    },
                    {
                        "id": "T1021",
                        "name": "Remote Services",
                        "description": "Lateral movement using remote services",
                        "mitre_mitigations": [
                           {"id": "M1049", "name": "Antivirus/Antimalware"},
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1036", "name": "Disable or Remove Feature or Program"},
                           {"id": "M1033", "name": "Limit Access to Resource Over Network"},
                           {"id": "M1030", "name": "Network Segmentation"},
                           {"id": "M1026", "name": "Privileged Account Management"}
                        ],
                        "defend_mitigations": [
                            {"id": "D3-RESTRICT-ACCESS", "name": "Restrict Access", "description": "Restrict access to remote services to only necessary users and IP addresses"},
                            {"id": "D3-STRONG-AUTH", "name": "Strong Authentication", "description": "Use strong authentication (MFA) for all remote access"},
                            {"id": "D3-NET-SEG", "name": "Network Segmentation", "description": "Implement network segmentation to isolate remote services"},
                            {"id": "D3-REMOTE-LOG-MON", "name": "Remote Service Log Monitoring", "description": "Monitor remote service logs for suspicious activity"},
                            {"id": "D3-DISABLE-SERVICES", "name": "Disable Unused Services", "description": "Disable unused remote services"}
                        ]
                    }
                ]
            }
        }
        return mapping

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
                                # Add mitigations from markdown if available, using the technique ID as key
                                if technique_id in self.markdown_mitigations:
                                    mitigations_list = []
                                    for i, m in enumerate(self.markdown_mitigations[technique_id]):
                                        mitigations_list.append({'id': f'M-CUSTOM-{i+1}', 'name': m})
                                    tech_copy['mitre_mitigations'] = mitigations_list
                                # Add placeholder for D3FEND mitigations if not already present
                                if 'defend_mitigations' not in tech_copy:
                                    tech_copy['defend_mitigations'] = [{'id': 'D3-PLACEHOLDER', 'description': 'Placeholder - D3FEND mitigations not retrieved'}]
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
                                # Add mitigations from markdown if available, using the technique ID as key
                                if technique.get("id") in self.markdown_mitigations:
                                    mitigations_list = []
                                    for i, m in enumerate(self.markdown_mitigations[technique.get("id")]):
                                        mitigations_list.append({'id': f'M-CUSTOM-{i+1}', 'name': m})
                                    tech_copy['mitre_mitigations'] = mitigations_list
                                # Add placeholder for D3FEND mitigations if not already present
                                if 'defend_mitigations' not in tech_copy:
                                    tech_copy['defend_mitigations'] = [{'id': 'D3-PLACEHOLDER', 'description': 'Placeholder - D3FEND mitigations not retrieved'}]
                                found_techniques[technique.get("id")] = tech_copy
        
        return list(found_techniques.values())
    
    def get_d3fend_mitigations_for_technique(self, technique_id: str) -> List[Dict[str, str]]:
        """Retrieves D3FEND mitigations for a given MITRE ATT&CK technique ID."""
        if not self.d3fend_mappings:
            return []
        return self.d3fend_mappings.get(technique_id, [])

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
