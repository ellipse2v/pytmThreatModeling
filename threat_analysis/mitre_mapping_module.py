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
import pandas as pd
from threat_analysis.custom_threats import get_custom_threats

attack_d3fend_mapping = {
    "M1013 Application Developer Guidance": ["A future release of D3FEND will define a taxonomy of Source Code Hardening Techniques."],
    "M1015 Active Directory Configuration": ["D3-ANCI Authentication Cache Invalidation", "D3-DTP Domain Trust Policy", "D3-UAP User Account Permissions"],
    "M1016 Vulnerability Scanning": ["Future D3FEND releases will model the scanning and inventory domains."],
    "M1017 User Training": ["Modeling user training is outside the scope of D3FEND."],
    "M1018 User Account Management": ["D3-LFP Local File Permissions", "D3-SCF System Call Filtering", "D3-SCP System Configuration Permissions"],
    "M1019 Threat Intelligence Program": ["Establishing and running a Threat Intelligence Program is outside the scope of D3FEND."],
    "M1020 SSL/TLS Inspection": ["D3-NTA Network Traffic Analysis"],
    "M1021 Restrict Web-Based Content": ["D3-DNSAL DNS Allowlisting", "D3-DNSDL DNS Denylisting", "D3-FA File Analysis", "D3-ITF Inbound Traffic Filtering", "D3-NTA Network Traffic Analysis", "D3-OTF Outbound Traffic Filtering", "D3-UA URL Analysis"],
    "M1022 Restrict File and Directory Permissions": ["D3-LFP Local File Permissions"],
    "M1024 Restrict Registry Permission": ["D3-SCP System Configuration Permissions"],
    "M1025 Privileged Process Integrity": ["D3-BA Bootloader Authentication", "D3-DLIC Driver Load Integrity Checking", "D3-PSEP Process Segment Execution Prevention", "D3-SCF System Call Filtering"],
    "M1026 Privileged Account Management": ["D3-DAM Domain Account Monitoring", "D3-LAM Local Account Monitoring", "D3-SPP Strong Password Policy"],
    "M1027 Password Policies": ["D3-OTP One-time Password", "D3-SPP Strong Password Policy"],
    "M1028 Operating System Configuration": ["D3-PH Platform Hardening"],
    "M1029 Remote Data Storage": ["IT disaster recovery plans are outside the current scope of D3FEND."],
    "M1030 Network Segmentation": ["D3-BDI Broadcast Domain Isolation", "D3-ET Encrypted Tunnels", "D3-ISVA Inbound Session Volume Analysis", "D3-ITF Inbound Traffic Filtering"],
    "M1031 Network Intrusion Prevention": ["D3-ITF Inbound Traffic Filtering", "D3-NTA Network Traffic Analysis", "D3-OTF Outbound Traffic Filtering"],
    "M1032 Multi-factor Authentication": ["D3-MFA Multi-factor Authentication"],
    "M1033 Limit Software Installation": ["D3-EAL Executable Allowlisting", "D3-EDL Executable Denylisting"],
    "M1034 Limit Hardware Installation": ["D3-IOPR IO Port Restriction"],
    "M1035 Limit Access to Resource Over Network": ["D3-NI Network Isolation"],
    "M1036 Account Use Policies": ["D3-AL Account Locking", "D3-ANCI Authentication Cache Invalidation", "D3-ANET Authentication Event Thresholding"],
    "M1037 Filter Network Traffic": ["D3-NI Network Isolation"],
    "M1038 Execution Prevention": ["D3-DLIC Driver Load Integrity Checking", "D3-EAL Executable Allowlisting", "D3-EDL Executable Denylisting", "D3-PSEP Process Segment Execution Prevention"],
    "M1039 Environment Variable Permissions": ["D3-ACH Application Configuration Hardening", "D3-SFA System File Analysis"],
    "M1040 Behavior Prevention on Endpoint": ["D3-ANET Authentication Event Thresholding", "D3-AZET Authorization Event Thresholding", "D3-JFAPA Job Function Access Pattern Analysis", "D3-RAPA Resource Access Pattern Analysis", "D3-SDA Session Duration Analysis", "D3-UDTA User Data Transfer Analysis", "D3-UGLPA User Geolocation Logon Pattern Analysis", "D3-WSAA Web Session Activity Analysis"],
    "M1041 Encrypt Sensitive Information": ["D3-DENCR Disk Encryption", "D3-ET Encrypted Tunnels", "D3-FE File Encryption", "D3-MENCR Message Encryption"],
    "M1042 Disable or Remove Feature or Program": ["D3-ACH Application Configuration Hardening", "D3-EDL Executable Denylisting", "D3-SCF System Call Filtering"],
    "M1043 Credential Access Protection": ["D3-HBPI Hardware-based Process Isolation"],
    "M1044 Restrict Library Loading": ["D3-SCF System Call Filtering"],
    "M1045 Code Signing": ["D3-DLIC Driver Load Integrity Checking", "D3-EAL Executable Allowlisting", "D3-SBV Service Binary Verification"],
    "M1046 Boot Integrity": ["D3-BA Bootloader Authentication", "D3-TBI TPM Boot Integrity"],
    "M1047 Audit": ["D3-DAM Domain Account Monitoring", "D3-LAM Local Account Monitoring", "D3-SFA System File Analysis"],
    "M1048 Application Isolation and Sandboxing": ["D3-DA Dynamic Analysis", "D3-HBPI Hardware-based Process Isolation", "D3-SCF System Call Filtering"],
    "M1049 Antivirus/Antimalware": ["D3-FCR File Content Rules", "D3-FH File Hashing", "D3-PA Process Analysis"],
    "M1050 Exploit Protection": ["D3-SSC Shadow Stack Comparisons", "D3-AH Application Hardening", "D3-EHPV Exception Handler Pointer Validation", "D3-ITF Inbound Traffic Filtering"],
    "M1051 Update Software": ["D3-SU Software Update"],
    "M1052 User Account Control": ["D3-SCF System Call Filtering"],
    "M1053 Data Backup": ["Comprehensive IT disaster recovery plans are outside the current scope of D3FEND."],
    "M1054 Software Configuration": ["D3-ACH Application Configuration Hardening", "D3-CP Certificate Pinning"],
    "M1055 Do Not Mitigate": [], # No D3FEND techniques listed
    "M1056 Pre-compromise": ["D3-DE Decoy Environment", "D3-DO Decoy Object"]
}

class MitreMapping:
    """Class for managing MITRE ATT&CK mapping with D3FEND mitigations"""
    def __init__(self, threat_model=None, threat_model_path: str = '/mnt/d/dev/github/threatModelBypyTm/threat_model.md'):
        self.d3fend_details = self._initialize_d3fend_mapping()
        self.mapping = self._initialize_mapping()
        self.threat_patterns = self._initialize_threat_patterns()
        self.custom_threats = self._load_custom_threats(threat_model)
        self.custom_mitre_mappings = self._load_custom_mitre_mappings_from_markdown(threat_model_path)
        self.markdown_mitigations = {}
    def _load_custom_threats(self, threat_model) -> Dict[str, List[Dict[str, Any]]]:
        """Loads custom threats from the custom_threats module."""
        if threat_model:
            return get_custom_threats(threat_model)
        return {}
    def get_custom_threats(self) -> Dict[str, List[Dict[str, Any]]]:
        """Returns the loaded custom threats."""
        return self.custom_threats
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
                pattern = re.compile(r'- \*\*(.*?)\*\*:\s*({.*?})')
                for line in mappings_content.split('\n'):
                    line = line.strip()
                    match = pattern.match(line)
                    if match:
                        threat_name = match.group(1).strip()
                        json_like_string = match.group(2)
                        # Replace single quotes with double quotes for valid JSON
                        json_like_string = json_like_string.replace("'", '"')
                        # Add quotes around keys
                        json_like_string = re.sub(r'(\w+)=', r'"\1"=', json_like_string)
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
    def _initialize_d3fend_mapping(self) -> Dict[str, Dict[str, str]]:
        """Initializes D3FEND mitigations by loading from d3fend.csv."""
        d3fend_details = {}
        csv_file_path = os.path.join(os.path.dirname(__file__), 'd3fend.csv')
        try:
            df = pd.read_csv(csv_file_path)
            for _, row in df.iterrows():
                d3fend_id = row['ID']
                d3fend_name = row['D3FEND Technique'] if pd.notna(row['D3FEND Technique']) else d3fend_id
                d3fend_description = row['Definition'] if pd.notna(row['Definition']) else ""
                d3fend_details[d3fend_id] = {
                    "name": d3fend_name,
                    "description": d3fend_description
                }
        except FileNotFoundError:
            print(f"Error: d3fend.csv not found at {csv_file_path}. Using empty D3FEND mapping.")
        except Exception as e:
            print(f"Error loading d3fend.csv: {e}. Using empty D3FEND mapping.")
        return d3fend_details
    def _initialize_mapping(self) -> Dict[str, Dict[str, Any]]:
        """Initializes comprehensive STRIDE to MITRE ATT&CK mapping with D3FEND mitigations"""
        official_d3fend_mapping = self._initialize_d3fend_mapping()
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
                        ]
                    },
                    {
                        "id": "T1185",
                        "name": "Browser Session Hijacking",
                        "description": "Session hijacking attacks",
                        "mitre_mitigations": [
                            {"id": "M1028", "name": "Operating System Configuration"},
                            {"id": "M1017", "name": "User Account Management"}
                        ]
                    },
                    {
                        "id": "T1539",
                        "name": "Steal Web Session Cookie",
                        "description": "Steal Web Session Cookie",
                        "mitre_mitigations": [
                            {"id": "M1017", "name": "User Account Management"}
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
                        ]
                    },
                    {
                        "id": "T1598",
                        "name": "Phishing for Information",
                        "description": "Cross Site Request Forgery attacks",
                        "mitre_mitigations": [
                            {"id": "M1056", "name": "User Training"}
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
                        ]
                    },
                    {
                        "id": "T1083",
                        "name": "File and Directory Discovery",
                        "description": "Discovery of sensitive files and directories",
                        "defend_mitigations": [{"id": "D3F-FDD"}]
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
                        ]
                    },
                    {
                        "id": "T1071",
                        "name": "Application Layer Protocol",
                        "description": "Protocol manipulation and smuggling",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"},
                           {"id": "M1029", "name": "Network Intrusion Prevention"}
                        ]
                    },
                    {
                        "id": "T1071.001",
                        "name": "Web Protocols",
                        "description": "HTTP/HTTPS protocol manipulation",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"},
                           {"id": "M1029", "name": "Network Intrusion Prevention"}
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
                        ]
                    },
                    {
                        "id": "T1621",
                        "name": "Multi-Factor Authentication Request Generation",
                        "description": "Removing Important Client Functionality",
                        "mitre_mitigations": [
                            {"id": "M1033", "name": "Limit Access to Resource Over Network"},
                            {"id": "M1017", "name": "User Account Management"}
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
                        "description": "Degrading or blocking the availability of services on an endpoint.",
                        "mitre_mitigations": [
                            {"id": "M1050", "name": "Exploit Protection"},
                            {"id": "M1048", "name": "Application Isolation and Sandboxing"},
                            {"id": "M1029", "name": "Network Intrusion Prevention"}
                        ]
                    },
                    {
                        "id": "T1498",
                        "name": "Network Denial of Service",
                        "description": "Flooding a network with traffic to degrade or block the availability of services.",
                        "mitre_mitigations": [
                            {"id": "M1037", "name": "Filter Network Traffic"},
                            {"id": "M1030", "name": "Network Segmentation"}
                        ]
                    }
                ]
            },
            "ElevationOfPrivilege": {
                "tactics": ["Privilege Escalation", "Defense Evasion"],
                "techniques": [
                    {
                        "id": "T1068",
                        "name": "Exploitation for Privilege Escalation",
                        "description": "Exploiting software vulnerabilities to gain higher privileges.",
                        "mitre_mitigations": [
                            {"id": "M1050", "name": "Exploit Protection"},
                            {"id": "M1045", "name": "Code Signing"},
                            {"id": "M1026", "name": "Privileged Account Management"}
                        ]
                    },
                    {
                        "id": "T1548",
                        "name": "Abuse Elevation Control Mechanism",
                        "description": "Abusing built-in elevation control mechanisms to execute code with higher privileges.",
                        "mitre_mitigations": [
                            {"id": "M1043", "name": "Audit"},
                            {"id": "M1026", "name": "Privileged Account Management"},
                            {"id": "M1018", "name": "User Account Control"}
                        ]
                    },
                    {
                        "id": "T1055",
                        "name": "Process Injection",
                        "description": "Injecting code into other processes to evade defenses and escalate privileges.",
                        "mitre_mitigations": [
                            {"id": "M1050", "name": "Exploit Protection"},
                            {"id": "M1049", "name": "Antivirus/Antimalware"},
                            {"id": "M1048", "name": "Application Isolation and Sandboxing"}
                        ]
                    },
                    {
                        "id": "T1021",
                        "name": "Remote Services",
                        "description": "Using remote services to execute code on a remote system, potentially for lateral movement.",
                        "mitre_mitigations": [
                            {"id": "M1033", "name": "Limit Access to Resource Over Network"},
                            {"id": "M1030", "name": "Network Segmentation"},
                            {"id": "M1018", "name": "User Account Control"}
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
                        "defend_mitigations": [{"id": "D3F-DFLS"}]
                    },
                    {
                        "id": "T1041",
                        "name": "Exfiltration Over C2 Channel",
                        "description": "Data exfiltration via command and control",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ]
                    },
                    {
                        "id": "T1083",
                        "name": "File and Directory Discovery",
                        "description": "Discovery of sensitive files and directories",
                        "defend_mitigations": [{"id": "D3F-FDD"}]
                    },
                    {
                        "id": "T1040",
                        "name": "Network Sniffing",
                        "description": "Network traffic interception and sniffing",
                        "defend_mitigations": [{"id": "D3F-NS"}]
                    },
                    {
                        "id": "T1592",
                        "name": "Gather Victim Host Information",
                        "description": "Host information gathering and fingerprinting",
                        "defend_mitigations": [{"id": "D3F-GVHI"}]
                    },
                    {
                        "id": "T1592.002",
                        "name": "Software",
                        "description": "Software fingerprinting and enumeration",
                        "mitre_mitigations": [
                           {"id": "M1036", "name": "Disable or Remove Feature or Program"}
                        ]
                    },
                    {
                        "id": "T1595",
                        "name": "Active Scanning",
                        "description": "Active reconnaissance and scanning",
                        "defend_mitigations": [{"id": "D3F-AS"}]
                    },
                    {
                        "id": "T1595.001",
                        "name": "Scanning IP Blocks",
                        "description": "Network scanning and enumeration",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ]
                    },
                    {
                        "id": "T1595.002",
                        "name": "Vulnerability Scanning",
                        "description": "Vulnerability assessment and scanning",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ]
                    },
                    {
                        "id": "T1589",
                        "name": "Gather Victim Identity Information",
                        "description": "Identity information gathering",
                        "mitre_mitigations": [
                           {"id": "M1056", "name": "User Training"},
                           {"id": "M1017", "name": "User Account Management"}
                        ]
                    },
                    {
                        "id": "T1590",
                        "name": "Gather Victim Network Information",
                        "description": "Network information reconnaissance",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"},
                           {"id": "M1030", "name": "Network Segmentation"}
                        ]
                    },
                    {
                        "id": "T1591",
                        "name": "Gather Victim Org Information",
                        "description": "Organizational information gathering",
                        "mitre_mitigations": [
                           {"id": "M1056", "name": "User Training"}
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
                        ]
                    },
                    {
                        "id": "T1518",
                        "name": "Software Discovery",
                        "description": "Installed software discovery",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1038", "name": "Execution Prevention"}
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
                        ]
                    },
                    {
                        "id": "T1213",
                        "name": "Data from Information Repositories",
                        "description": "Lifting sensitive data from caches and repositories",
                        "mitre_mitigations": [
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"},
                           {"id": "M1017", "name": "User Account Management"}
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
                        ]
                    },
                    {
                        "id": "T1552",
                        "name": "Unsecured Credentials",
                        "description": "Exploiting incorrectly configured SSL/TLS",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"}
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
                        "defend_mitigations": [{"id": "D3F-DFLS"}]
                    },
                    {
                        "id": "T1041",
                        "name": "Exfiltration Over C2 Channel",
                        "description": "Data exfiltration via command and control",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ]
                    },
                    {
                        "id": "T1083",
                        "name": "File and Directory Discovery",
                        "description": "Discovery of sensitive files and directories",
                        "defend_mitigations": [{"id": "D3F-FDD"}]
                    },
                    {
                        "id": "T1040",
                        "name": "Network Sniffing",
                        "description": "Network traffic interception and sniffing",
                        "defend_mitigations": [{"id": "D3F-NS"}]
                    },
                    {
                        "id": "T1592",
                        "name": "Gather Victim Host Information",
                        "description": "Host information gathering and fingerprinting",
                        "defend_mitigations": [{"id": "D3F-GVHI"}]
                    },
                    {
                        "id": "T1592.002",
                        "name": "Software",
                        "description": "Software fingerprinting and enumeration",
                        "mitre_mitigations": [
                           {"id": "M1036", "name": "Disable or Remove Feature or Program"}
                        ]
                    },
                    {
                        "id": "T1595",
                        "name": "Active Scanning",
                        "description": "Active reconnaissance and scanning",
                        "defend_mitigations": [{"id": "D3F-AS"}]
                    },
                    {
                        "id": "T1595.001",
                        "name": "Scanning IP Blocks",
                        "description": "Network scanning and enumeration",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ]
                    },
                    {
                        "id": "T1595.002",
                        "name": "Vulnerability Scanning",
                        "description": "Vulnerability assessment and scanning",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"}
                        ]
                    },
                    {
                        "id": "T1589",
                        "name": "Gather Victim Identity Information",
                        "description": "Identity information gathering",
                        "mitre_mitigations": [
                           {"id": "M1056", "name": "User Training"},
                           {"id": "M1017", "name": "User Account Management"}
                        ]
                    },
                    {
                        "id": "T1590",
                        "name": "Gather Victim Network Information",
                        "description": "Network information reconnaissance",
                        "mitre_mitigations": [
                           {"id": "M1037", "name": "Filter Network Traffic"},
                           {"id": "M1030", "name": "Network Segmentation"}
                        ]
                    },
                    {
                        "id": "T1591",
                        "name": "Gather Victim Org Information",
                        "description": "Organizational information gathering",
                        "mitre_mitigations": [
                           {"id": "M1056", "name": "User Training"}
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
                        ]
                    },
                    {
                        "id": "T1518",
                        "name": "Software Discovery",
                        "description": "Installed software discovery",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1038", "name": "Execution Prevention"}
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
                        ]
                    },
                    {
                        "id": "T1213",
                        "name": "Data from Information Repositories",
                        "description": "Lifting sensitive data from caches and repositories",
                        "mitre_mitigations": [
                           {"id": "M1022", "name": "Restrict File and Directory Permissions"},
                           {"id": "M1017", "name": "User Account Management"}
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
                        ]
                    },
                    {
                        "id": "T1552",
                        "name": "Unsecured Credentials",
                        "description": "Exploiting incorrectly configured SSL/TLS",
                        "mitre_mitigations": [
                           {"id": "M1043", "name": "Audit"},
                           {"id": "M1028", "name": "Operating System Configuration"}
                        ]
                    }
                ]
            }
        }
        # Add the official D3FEND mapping to each technique
        for category in mapping.values():
            for technique in category.get("techniques", []):
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
            "T1190": r"(?i)exploit public.facing application|web application exploit|application vulnerability|unpatched.*vulnerabilities|injection|sql injection|xml injection|command injection|code injection|ldap injection|format string injection|server side include|ssi injection|remote code inclusion|argument injection|dtd injection|resource injection",
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
            "T1213": r"(?i)exploiting trust in client|data from information repositories|lifting sensitive data.*cache|insecure direct object references|idor",
            "T1555": r"(?i)reverse engineering|white box reverse engineering|credentials from password stores",
            "T1552": r"(?i)unsecured credentials|exploiting incorrectly configured ssl|ssl/tls misconfiguration|weak ssl/tls",
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
            "T1499": r"(?i)denial of service|dos attack|endpoint dos|resource exhaustion|flooding|excessive allocation|xml.*blowup|buffer overflow|removing.*functionality|xml entity expansion|xml ping of death|resource-intensive queries|exhaust its resources|disrupt air traffic control",
            "T1498": r"(?i)network denial of service|ddos|network flood|amplification",
            "T1489": r"(?i)service stop|disable.*service",
            "T1499.004": r"(?i)buffer manipulation|overflow buffers|xml entity expansion|xml ping of death",
            # Client Function Removal
            "T1621": r"(?i)removing important client functionality|multi.factor authentication request generation",
            # Log and Audit Manipulation
            "T1070": r"(?i)indicator removal|log deletion|clear.*logs|audit log manipulation|repudiation of critical actions|lack of monitoring|lack of logging",
            "T1070.001": r"(?i)clear windows event logs",
            "T1070.002": r"(?i)clear linux.*logs|clear mac.*logs",
            "T1562": r"(?i)impair defenses|disable.*security|functionality misuse|insecure security configuration|hardening",
            "T1562.001": r"(?i)firewall rule misconfiguration|disable or modify system firewall|firewall bypass",
            # PyTM STRIDE Categories
            "spoofing": "Spoofing",
            "tampering": "Tampering|unpatched.*vulnerabilities|sql.*injection|nosql.*injection|xss|cross.site scripting|data corruption|unauthorized write access|injection of false surveillance data|unauthorized access to or modification of flight plans|unpatched.*vulnerabilities",
            "repudiation": "Repudiation", 
            "informationdisclosure": "InformationDisclosure",
            "information disclosure": "InformationDisclosure",
            "denialofservice": "DenialOfService",
            "denial of service": "DenialOfService",
            "elevationofprivilege": "ElevationOfPrivilege",
            "elevation of privilege": "ElevationOfPrivilege|unauthorized privilege escalation|vulnerability in the management interface|compromise of the management interface|lateral movement"
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
                                # Add D3FEND mitigations
                                defend_mitigations_list = []
                                for d3_mitigation_id_dict in technique.get('defend_mitigations', []):
                                    d3_mitigation_id = d3_mitigation_id_dict.get('id')
                                    if d3_mitigation_id and d3_mitigation_id in self.d3fend_details:
                                        defend_mitigations_list.append({
                                            "id": d3_mitigation_id,
                                            "name": self.d3fend_details[d3_mitigation_id]['name'],
                                            "description": self.d3fend_details[d3_mitigation_id]['description']
                                        })
                                    else:
                                        # Fallback if D3FEND ID not found in CSV (e.g., placeholder or old data)
                                        defend_mitigations_list.append({
                                            "id": d3_mitigation_id_dict.get('id', 'UNKNOWN'),
                                            "name": d3_mitigation_id_dict.get('name', 'UNKNOWN'),
                                            "description": "D3FEND mitigation details not found in CSV."
                                        })
                                tech_copy['defend_mitigations'] = defend_mitigations_list
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
                                # Add D3FEND mitigations
                                defend_mitigations_list = []
                                for d3_mitigation_id_dict in technique.get('defend_mitigations', []):
                                    d3_mitigation_id = d3_mitigation_id_dict.get('id')
                                    if d3_mitigation_id and d3_mitigation_id in self.d3fend_details:
                                        defend_mitigations_list.append({
                                            "id": d3_mitigation_id,
                                            "name": self.d3fend_details[d3_mitigation_id]['name'],
                                            "description": self.d3fend_details[d3_mitigation_id]['description']
                                        })
                                    else:
                                        # Fallback if D3FEND ID not found in CSV (e.g., placeholder or old data)
                                        defend_mitigations_list.append({
                                            "id": d3_mitigation_id_dict.get('id', 'UNKNOWN'),
                                            "name": d3_mitigation_id_dict.get('name', 'UNKNOWN'),
                                            "description": "D3FEND mitigation details not found in CSV."
                                        })
                                tech_copy['defend_mitigations'] = defend_mitigations_list
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