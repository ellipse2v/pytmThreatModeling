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
MITRE ATT&CK mapping module
"""
from typing import Dict, List, Any
import re

from threat_analysis.custom_threats import get_custom_threats


class MitreMapping:
    """Class for managing MITRE ATT&CK mapping"""
    
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
        """Initializes comprehensive STRIDE to MITRE ATT&CK mapping"""
        return {
            "Spoofing": {
                "tactics": ["Initial Access", "Defense Evasion", "Credential Access"],
                "techniques": [
                    {
                        "id": "T1566",
                        "name": "Phishing",
                        "description": "Identity spoofing via phishing"
                    },
                    {
                        "id": "T1036",
                        "name": "Masquerading",
                        "description": "Disguising malicious processes"
                    },
                    {
                        "id": "T1134",
                        "name": "Access Token Manipulation",
                        "description": "Manipulation of access tokens"
                    },
                    {
                        "id": "T1078",
                        "name": "Valid Accounts",
                        "description": "Use of valid accounts for access"
                    },
                    {
                        "id": "T1078.003",
                        "name": "Local Accounts",
                        "description": "Abuse of local accounts"
                    },
                    {
                        "id": "T1110",
                        "name": "Brute Force",
                        "description": "Attempting to guess or crack passwords"
                    },
                    {
                        "id": "T1110.001",
                        "name": "Password Guessing",
                        "description": "Dictionary-based password attacks"
                    },
                    {
                        "id": "T1110.003",
                        "name": "Password Spraying",
                        "description": "Low-and-slow password attack"
                    },
                    {
                        "id": "T1110.004",
                        "name": "Credential Stuffing",
                        "description": "Using breached credential pairs"
                    },
                    {
                        "id": "T1185",
                        "name": "Browser Session Hijacking",
                        "description": "Session hijacking attacks"
                    },
                    {
                        "id": "T1539",
                        "name": "Steal Web Session Cookie",
                        "description": "Session credential theft"
                    },
                    {
                        "id": "T1212",
                        "name": "Exploitation for Credential Access",
                        "description": "Exploiting vulnerabilities to access credentials"
                    },
                    {
                        "id": "T1557",
                        "name": "Adversary-in-the-Middle",
                        "description": "Man-in-the-middle attacks"
                    },
                    {
                        "id": "T1556",
                        "name": "Modify Authentication Process",
                        "description": "Authentication bypass techniques"
                    },
                    {
                        "id": "T1598",
                        "name": "Phishing for Information",
                        "description": "Cross Site Request Forgery attacks"
                    },
                    {
                        "id": "T1213",
                        "name": "Data from Information Repositories",
                        "description": "Exploiting Trust in Client"
                    }
                ]
            },
            "Tampering": {
                "tactics": ["Defense Evasion", "Impact", "Initial Access", "Execution"],
                "techniques": [
                    {
                        "id": "T1565",
                        "name": "Data Manipulation",
                        "description": "Unauthorized data modification"
                    },
                    {
                        "id": "T1070",
                        "name": "Indicator Removal",
                        "description": "Deletion of activity traces"
                    },
                    {
                        "id": "T1027",
                        "name": "Obfuscated Files or Information",
                        "description": "Obfuscation of malicious content"
                    },
                    {
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "description": "Web application vulnerabilities exploitation"
                    },
                    {
                        "id": "T1059",
                        "name": "Command and Scripting Interpreter",
                        "description": "Command injection and execution"
                    },
                    {
                        "id": "T1059.007",
                        "name": "JavaScript",
                        "description": "JavaScript-based attacks including XSS"
                    },
                    {
                        "id": "T1505.003",
                        "name": "Web Shell",
                        "description": "Web shell installation and usage"
                    },
                    {
                        "id": "T1105",
                        "name": "Ingress Tool Transfer",
                        "description": "Remote file inclusion and malicious file upload"
                    },
                    {
                        "id": "T1211",
                        "name": "Exploitation for Defense Evasion",
                        "description": "Exploiting vulnerabilities to evade defenses"
                    },
                    {
                        "id": "T1055",
                        "name": "Process Injection",
                        "description": "Injecting code into privileged processes"
                    },
                    {
                        "id": "T1562",
                        "name": "Impair Defenses",
                        "description": "Disabling security controls"
                    },
                    {
                        "id": "T1562.001",
                        "name": "Disable or Modify System Firewall",
                        "description": "Firewall manipulation"
                    },
                    {
                        "id": "T1140",
                        "name": "Deobfuscate/Decode Files or Information",
                        "description": "Processing encoded/obfuscated content"
                    },
                    {
                        "id": "T1083",
                        "name": "File and Directory Discovery",
                        "description": "Discovery of sensitive files and directories"
                    },
                    {
                        "id": "T1574",
                        "name": "Hijack Execution Flow",
                        "description": "Execution flow manipulation"
                    },
                    {
                        "id": "T1071",
                        "name": "Application Layer Protocol",
                        "description": "Protocol manipulation and smuggling"
                    },
                    {
                        "id": "T1071.001",
                        "name": "Web Protocols",
                        "description": "HTTP/HTTPS protocol manipulation"
                    },
                    {
                        "id": "T1112",
                        "name": "Modify Registry",
                        "description": "Registry manipulation and information tampering"
                    },
                    {
                        "id": "T1565.001",
                        "name": "Stored Data Manipulation",
                        "description": "XML Schema Poisoning and nested payload attacks"
                    },
                    {
                        "id": "T1621",
                        "name": "Multi-Factor Authentication Request Generation",
                        "description": "Removing Important Client Functionality"
                    },
                    {
                        "id": "T1499.004",
                        "name": "Application or System Exploitation",
                        "description": "Buffer manipulation and overflow attacks"
                    }
                ]
            },
            "Repudiation": {
                "tactics": ["Defense Evasion", "Impact"],
                "techniques": [
                    {
                        "id": "T1070.001",
                        "name": "Clear Windows Event Logs",
                        "description": "Clearing Windows event logs"
                    },
                    {
                        "id": "T1070.002",
                        "name": "Clear Linux or Mac System Logs",
                        "description": "Clearing Unix/Linux system logs"
                    },
                    {
                        "id": "T1070.003",
                        "name": "Clear Command History",
                        "description": "Clearing command history"
                    },
                    {
                        "id": "T1070.004",
                        "name": "File Deletion",
                        "description": "Removing files to eliminate traces"
                    },
                    {
                        "id": "T1070.006",
                        "name": "Timestomp",
                        "description": "Modifying file timestamps"
                    },
                    {
                        "id": "T1562",
                        "name": "Impair Defenses",
                        "description": "Disabling logging and monitoring"
                    },
                    {
                        "id": "T1562.002",
                        "name": "Disable Windows Event Logging",
                        "description": "Disabling event logging"
                    },
                    {
                        "id": "T1562.006",
                        "name": "Indicator Blocking",
                        "description": "Blocking security indicators"
                    },
                    {
                        "id": "T1565.001",
                        "name": "Stored Data Manipulation",
                        "description": "Audit log manipulation"
                    }
                ]
            },
            "InformationDisclosure": {
                "tactics": ["Collection", "Exfiltration", "Discovery", "Reconnaissance"],
                "techniques": [
                    {
                        "id": "T1005",
                        "name": "Data from Local System",
                        "description": "Collecting local sensitive data"
                    },
                    {
                        "id": "T1041",
                        "name": "Exfiltration Over C2 Channel",
                        "description": "Data exfiltration via command and control"
                    },
                    {
                        "id": "T1083",
                        "name": "File and Directory Discovery",
                        "description": "Discovery of sensitive files and directories"
                    },
                    {
                        "id": "T1040",
                        "name": "Network Sniffing",
                        "description": "Network traffic interception and sniffing"
                    },
                    {
                        "id": "T1592",
                        "name": "Gather Victim Host Information",
                        "description": "Host information gathering and fingerprinting"
                    },
                    {
                        "id": "T1592.002",
                        "name": "Software",
                        "description": "Software fingerprinting and enumeration"
                    },
                    {
                        "id": "T1595",
                        "name": "Active Scanning",
                        "description": "Active reconnaissance and scanning"
                    },
                    {
                        "id": "T1595.001",
                        "name": "Scanning IP Blocks",
                        "description": "Network scanning and enumeration"
                    },
                    {
                        "id": "T1595.002",
                        "name": "Vulnerability Scanning",
                        "description": "Vulnerability assessment and scanning"
                    },
                    {
                        "id": "T1589",
                        "name": "Gather Victim Identity Information",
                        "description": "Identity information gathering"
                    },
                    {
                        "id": "T1590",
                        "name": "Gather Victim Network Information",
                        "description": "Network information reconnaissance"
                    },
                    {
                        "id": "T1591",
                        "name": "Gather Victim Org Information",
                        "description": "Organizational information gathering"
                    },
                    {
                        "id": "T1613",
                        "name": "Container and Resource Discovery",
                        "description": "Container and cloud resource discovery"
                    },
                    {
                        "id": "T1046",
                        "name": "Network Service Discovery",
                        "description": "Service enumeration and discovery"
                    },
                    {
                        "id": "T1087",
                        "name": "Account Discovery",
                        "description": "User and account enumeration"
                    },
                    {
                        "id": "T1518",
                        "name": "Software Discovery",
                        "description": "Installed software discovery"
                    },
                    {
                        "id": "T1082",
                        "name": "System Information Discovery",
                        "description": "System configuration discovery"
                    },
                    {
                        "id": "T1213",
                        "name": "Data from Information Repositories",
                        "description": "Lifting sensitive data from caches and repositories"
                    },
                    {
                        "id": "T1555",
                        "name": "Credentials from Password Stores",
                        "description": "Reverse engineering and white box analysis"
                    },
                    {
                        "id": "T1552",
                        "name": "Unsecured Credentials",
                        "description": "Exploiting incorrectly configured SSL/TLS"
                    }
                ]
            },
            "DenialOfService": {
                "tactics": ["Impact"],
                "techniques": [
                    {
                        "id": "T1499",
                        "name": "Endpoint Denial of Service",
                        "description": "Endpoint-focused denial of service"
                    },
                    {
                        "id": "T1499.001",
                        "name": "OS Exhaustion Flood",
                        "description": "Operating system resource exhaustion"
                    },
                    {
                        "id": "T1499.002",
                        "name": "Service Exhaustion Flood",
                        "description": "Service resource exhaustion"
                    },
                    {
                        "id": "T1499.003",
                        "name": "Application Exhaustion Flood",
                        "description": "Application-level resource exhaustion"
                    },
                    {
                        "id": "T1499.004",
                        "name": "Application or System Exploitation",
                        "description": "Exploiting vulnerabilities for DoS"
                    },
                    {
                        "id": "T1498",
                        "name": "Network Denial of Service",
                        "description": "Network-level denial of service"
                    },
                    {
                        "id": "T1498.001",
                        "name": "Direct Network Flood",
                        "description": "Direct network flooding attacks"
                    },
                    {
                        "id": "T1498.002",
                        "name": "Reflection Amplification",
                        "description": "Amplification-based DDoS attacks"
                    },
                    {
                        "id": "T1496",
                        "name": "Resource Hijacking",
                        "description": "System resource hijacking"
                    },
                    {
                        "id": "T1489",
                        "name": "Service Stop",
                        "description": "Stopping critical services"
                    },
                    {
                        "id": "T1561",
                        "name": "Disk Wipe",
                        "description": "Disk wiping and data destruction"
                    },
                    {
                        "id": "T1485",
                        "name": "Data Destruction",
                        "description": "Destructive data manipulation"
                    },
                    {
                        "id": "T1499.004",
                        "name": "Application or System Exploitation",
                        "description": "XML Entity Expansion and XML Ping of Death attacks"
                    }
                ]
            },
            "ElevationOfPrivilege": {
                "tactics": ["Privilege Escalation", "Defense Evasion", "Persistence"],
                "techniques": [
                    {
                        "id": "T1548",
                        "name": "Abuse Elevation Control Mechanism",
                        "description": "Exploiting elevation control mechanisms"
                    },
                    {
                        "id": "T1548.001",
                        "name": "Setuid and Setgid",
                        "description": "Unix privilege escalation via setuid/setgid"
                    },
                    {
                        "id": "T1548.002",
                        "name": "Bypass User Account Control",
                        "description": "Windows UAC bypass techniques"
                    },
                    {
                        "id": "T1548.003",
                        "name": "Sudo and Sudo Caching",
                        "description": "Sudo abuse for privilege escalation"
                    },
                    {
                        "id": "T1548.004",
                        "name": "Elevated Execution with Prompt",
                        "description": "Prompting for elevated execution"
                    },
                    {
                        "id": "T1055",
                        "name": "Process Injection",
                        "description": "Injecting code into privileged processes"
                    },
                    {
                        "id": "T1055.001",
                        "name": "Dynamic-link Library Injection",
                        "description": "DLL injection for privilege escalation"
                    },
                    {
                        "id": "T1068",
                        "name": "Exploitation for Privilege Escalation",
                        "description": "Exploiting vulnerabilities for privilege escalation"
                    },
                    {
                        "id": "T1078.001",
                        "name": "Default Accounts",
                        "description": "Using default credentials for elevation"
                    },
                    {
                        "id": "T1078.002",
                        "name": "Domain Accounts",
                        "description": "Abusing domain accounts for elevation"
                    },
                    {
                        "id": "T1078.003",
                        "name": "Local Accounts",
                        "description": "Abusing local accounts for elevation"
                    },
                    {
                        "id": "T1078.004",
                        "name": "Cloud Accounts",
                        "description": "Abusing cloud accounts for elevation"
                    },
                    {
                        "id": "T1134.001",
                        "name": "Token Impersonation/Theft",
                        "description": "Access token impersonation"
                    },
                    {
                        "id": "T1134.002",
                        "name": "Create Process with Token",
                        "description": "Process creation with stolen tokens"
                    },
                    {
                        "id": "T1134.003",
                        "name": "Make and Impersonate Token",
                        "description": "Token creation and impersonation"
                    },
                    {
                        "id": "T1134.004",
                        "name": "Parent PID Spoofing",
                        "description": "Process parent spoofing for elevation"
                    },
                    {
                        "id": "T1134.005",
                        "name": "SID-History Injection",
                        "description": "SID history manipulation"
                    },
                    {
                        "id": "T1484",
                        "name": "Domain Policy Modification",
                        "description": "Privilege abuse and policy manipulation"
                    },
                    {
                        "id": "T1021",
                        "name": "Remote Services",
                        "description": "Lateral movement using remote services"
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