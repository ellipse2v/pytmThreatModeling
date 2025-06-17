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


class MitreMapping:
    """Class for managing MITRE ATT&CK mapping"""
    
    def __init__(self):
        self.mapping = self._initialize_mapping()
        self.threat_patterns = self._initialize_threat_patterns()
        
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
                        "description": "Code injection into running processes"
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
                        "description": "Path traversal and directory enumeration"
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
            "T1552": r"(?i)exploiting incorrectly configured ssl|unsecured credentials",
            
            # JSON and API Attacks
            "T1041": r"(?i)json hijacking|javascript hijacking|api manipulation|exploit.*apis|exploit test apis|exploit script.based apis",
            
            # Registry and Environment
            "T1112": r"(?i)modify registry|manipulate registry|registry manipulation|manipulate registry information",
            "T1574": r"(?i)hijack execution flow|subverting environment variable|environment variable manipulation|command delimiters",
            
            # Content and Interface Attacks
            "T1036": r"(?i)content spoofing|masquerading|iframe overlay",
            
            # Privilege Escalation
            "T1068": r"(?i)privilege escalation|exploitation for privilege escalation|elevation of privilege",
            "T1548": r"(?i)abuse elevation control|exploiting incorrectly configured access control|functionality misuse|hijacking.*privileged process|catching exception.*privileged",
            "T1055": r"(?i)process injection|hijacking.*privileged process|embedding scripts",
            "T1484": r"(?i)privilege abuse|domain policy modification",
            
            # Denial of Service and Buffer Attacks
            "T1499": r"(?i)denial of service|dos attack|endpoint dos|resource exhaustion|flooding|excessive allocation|xml.*blowup|buffer overflow|removing.*functionality|xml entity expansion|xml ping of death",
            "T1498": r"(?i)network denial of service|ddos|network flood|amplification",
            "T1489": r"(?i)service stop|disable.*service",
            "T1499.004": r"(?i)buffer manipulation|overflow buffers|xml entity expansion|xml ping of death",
            
            # Client Function Removal
            "T1621": r"(?i)removing important client functionality|multi.factor authentication request generation",
            
            # Log and Audit Manipulation
            "T1070": r"(?i)indicator removal|log deletion|clear.*logs|audit log manipulation",
            "T1070.001": r"(?i)clear windows event logs",
            "T1070.002": r"(?i)clear linux.*logs|clear mac.*logs",
            "T1562": r"(?i)impair defenses|disable.*security|functionality misuse",
            
            # Specific Named Attacks
            "HTTP Request Splitting": "T1071.001",
            "HTTP Response Smuggling": "T1071.001", 
            "HTTP Request Smuggling": "T1071.001",
            "Cross Site Tracing": "T1040",
            "JSON Hijacking": "T1041",
            "JavaScript Hijacking": "T1041",
            "API Manipulation": "T1041",
            "Authentication Abuse": "T1556",
            "Authentication ByPass": "T1556",
            "Double Encoding": "T1027",
            "Exploit Test APIs": "T1041",
            "Exploit Script-Based APIs": "T1041",
            "Path Traversal": "T1083",
            "Relative Path Traversal": "T1083", 
            "Subverting Environment Variable Values": "T1574",
            "Content Spoofing": "T1036",
            "Command Delimiters": "T1574",
            "Dictionary-based Password Attack": "T1110.001",
            "Using Malicious Files": "T1105",
            "PHP Remote File Inclusion": "T1105",
            "Principal Spoof": "T1078",
            "Session Credential Falsification": "T1539",
            "Session Credential Falsification through Forging": "T1539",
            "Session Credential Falsification through Prediction": "T1539",
            "Session Credential Falsification through Manipulation": "T1539",
            "Encryption Brute Forcing": "T1110",
            "Manipulate Registry Information": "T1112",
            "Exploitation of Trusted Credentials": "T1078",
            "Communication Channel Manipulation": "T1071",
            "XML Routing Detour Attacks": "T1071.001",
            "Client-Server Protocol Manipulation": "T1071.001",
            "iFrame Overlay": "T1036",
            "Session Hijacking - ServerSide": "T1185",
            "Session Hijacking - ClientSide": "T1185",
            "Reusing Session IDs": "T1539",
            "Session Replay": "T1539",
            "Cross Site Request Forgery": "T1598",
            "Schema Poisoning": "T1565.001",
            "XML Nested Payloads": "T1565.001",
            "XML Schema Poisoning": "T1565.001",
            "Exploiting Trust in Client": "T1213",
            "Exploiting Incorrectly Configured SSL": "T1552",
            "Removing Important Client Functionality": "T1621",
            "Lifting Sensitive Data Embedded in Cache": "T1213",
            "Reverse Engineering": "T1555",
            "White Box Reverse Engineering": "T1555",
            "XML Entity Expansion": "T1499.004",
            "XML Ping of the Death": "T1499.004",
            "Try All Common Switches": "T1083",
            "Privilege Abuse": "T1484",
            "Buffer Manipulation": "T1499.004",
            "Overflow Buffers": "T1499.004",
            
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
                        # To avoid over-mapping, we only add if no specific T-ID was found for this description.
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
        #print(f"\n=== Analyzing {len(pytm_threats_list)} PyTM threats ===")
        
        results = {
            "total_threats": len(pytm_threats_list),
            "stride_distribution": {},
            "mitre_techniques_count": 0,
            "processed_threats": []
        }
        
        for i, threat_tuple in enumerate(pytm_threats_list):
            #print(f"\nDEBUG --- Processing threat {i+1}/{len(pytm_threats_list)} ---")
            
            if isinstance(threat_tuple, tuple):
                threat, target = threat_tuple
                #print(f"DEBUG Tuple format - Threat: {type(threat)}, Target: {type(target)}")
            else:
                threat = threat_tuple
                target = getattr(threat, 'target', None)
                #print(f"DEBUG Single object - Threat: {type(threat)}, Target: {type(target) if target else 'None'}")
            
            # Debug threat object
            #print(f"DEBUG Threat class: {threat.__class__.__name__}")
            #print(f"DEBUG Threat attributes: {[attr for attr in dir(threat) if not attr.startswith('_')]}")
            
            # Get threat description
            threat_description = getattr(threat, 'description', '')
            #print(f"DEBUG Threat description: '{threat_description}'")
            
            # Debug STRIDE classification
            #print("DEBUG Attempting STRIDE classification...")
            stride_category = self.classify_pytm_threat(threat)
            #print(f"DEBUG STRIDE result: '{stride_category}'")
            
            # Debug MITRE mapping
            #print("DEBUG Attempting MITRE mapping...")
            mitre_techniques = self.map_threat_to_mitre(threat_description)
            #print(f"DEBUG MITRE techniques found: {len(mitre_techniques)}")
            #if mitre_techniques:
            #    for tech in mitre_techniques[:2]:  # Show first 2
            #        print(f"  - {tech.get('id', 'No ID')}: {tech.get('name', 'No Name')}")
            
            # Debug MITRE tactics
            mitre_tactics = self.get_tactics_for_threat(stride_category)
            #print(f"DEBUG MITRE tactics: {mitre_tactics}")
            
            processed_threat = {
                "threat_name": str(threat.__class__.__name__),
                "description": threat_description,
                "target": str(target) if target else "Unknown",
                "stride_category": stride_category,
                "mitre_tactics": mitre_tactics,
                "mitre_techniques": mitre_techniques,
                "original_threat": threat
            }
            
            results["processed_threats"].append(processed_threat)
            
            # Update STRIDE distribution
            if stride_category:
                if stride_category not in results["stride_distribution"]:
                    results["stride_distribution"][stride_category] = 0
                results["stride_distribution"][stride_category] += 1
            else:
                print("WARNING: No STRIDE category assigned!")
            
            results["mitre_techniques_count"] += len(mitre_techniques)
        
        print(f"\n=== Final Results ===")
        print(f"Total threats: {results['total_threats']}")
        print(f"STRIDE distribution: {results['stride_distribution']}")
        print(f"Total MITRE techniques: {results['mitre_techniques_count']}")
        
        return results

    def classify_pytm_threat(self, threat) -> str:
        """
        Enhanced classify_pytm_threat with proper STRIDE classification.
        """
        #print(f"\n DEBUG Classifying threat: {threat.__class__.__name__}")
        
        # Get threat class name
        threat_class = threat.__class__.__name__
        #print(f"  DEBUG Threat class name: {threat_class}")
        
        # Get threat description
        description = getattr(threat, 'description', '').lower()
        #print(f"  DEBUG Description: '{description}'")
        
        # Get threat ID if available
        threat_id = getattr(threat, 'id', '')
        #print(f" DEBUG Threat ID: '{threat_id}'")
        
        # First, try PyTM-specific threat class mappings
        pytm_class_mappings = {
            # Common PyTM threat classes
            'Spoofing': 'Spoofing',
            'Tampering': 'Tampering',
            'Repudiation': 'Repudiation',
            'InformationDisclosure': 'Information Disclosure',
            'DenialOfService': 'Denial of Service', 
            'ElevationOfPrivilege': 'Elevation of Privilege',
            # Handle generic "Threat" class by looking at other attributes
            'Threat': None  # Will be handled by description analysis
        }
        
        if threat_class in pytm_class_mappings and pytm_class_mappings[threat_class]:
            result = pytm_class_mappings[threat_class]
            #print(f"  Found in PyTM class mapping: {result}")
            return result
        
        # Enhanced description-based classification for "Data Leak" and similar
        stride_patterns = {
            'Information Disclosure': [
                # Data exposure
                'data leak', 'information leak', 'disclosure', 'expose', 'reveal', 
                'unauthorized access', 'data breach', 'sensitive data', 'confidential',
                'privacy', 'leak', 'dump', 'exfiltrat', 
                # Configuration issues
                'ssl', 'tls', 'encryption', 'incorrectly configured', 'misconfigured', 'configuration',
                # Reconnaissance and discovery
                'footprinting', 'fingerprinting', 'reconnaissance', 'discovery', 'enumeration',
                'web application fingerprinting', 'reverse engineering', 'white box reverse engineering',
                'excavation', 'sniffing', 'interception', 'eavesdropping'
            ],
            'Tampering': [
                # Code injection and modification
                'tamper', 'modify', 'alter', 'corrupt', 'inject', 'overflow',
                'buffer overflow', 'sql injection', 'code injection', 'malicious input',
                'xss', 'cross-site scripting', 'reflected xss', 'stored xss', 'dom xss',
                'script injection', 'csrf', 'cross-site request forgery',
                # Protocol manipulation
                'response smuggling', 'http smuggling', 'smuggling', 'request splitting',
                'http request splitting', 'schema poisoning', 'poisoning', 'remote code', 
                'code inclusion', 'xml external entities', 'xxe', 'xml blowup', 
                'protocol manipulation', 'manipulation', 'detour', 'routing', 
                'channel manipulation', 'communication manipulation',
                # File and path attacks
                'path traversal', 'relative path traversal', 'directory traversal',
                'double encoding', 'encoding', 'malicious files', 'file upload',
                # Script and API attacks
                'embedding scripts', 'scripts within scripts', 'iframe overlay',
                'exploit apis', 'exploit test apis', 'exploit script-based apis',
                # Environment manipulation
                'environment variable', 'subverting environment', 'command delimiters',
                # Cross-site attacks
                'cross site tracing', 'cross-site tracing'
            ],
            'Spoofing': [
                # Identity and trust
                'spoof', 'impersonat', 'fake', 'forge', 'masquerad', 'identity theft',
                'credential theft', 'session hijack', 'man in the middle',
                'exploiting trust', 'trust', 'client trust',
                # Session attacks
                'session sidejacking', 'sidejacking', 'session replay', 'reusing session',
                'session fixation', 'json hijacking', 'javascript hijacking', 'hijacking'
            ],
            'Denial of Service': [
                # Resource exhaustion
                'denial of service', 'dos', 'ddos', 'flood', 'exhaust', 'overload',
                'resource exhaustion', 'availability', 'crash', 'hang', 'blowup',
                'excessive allocation', 'allocation', 'memory exhaustion',
                # Functionality removal
                'removing functionality', 'functionality removal', 'disable'
            ],
            'Elevation of Privilege': [
                # Privilege escalation
                'privilege escalation', 'elevat', 'escalat', 'admin', 'root',
                'unauthorized privilege', 'bypass authorization', 'privilege abuse',
                'privileged block', 'exception', 'signal', 'catching exception',
                # Password attacks
                'dictionary attack', 'password attack', 'brute force', 'credential stuffing',
                'try all common', 'common switches'
            ],
            'Repudiation': [
                # Audit and logging
                'repudiat', 'deny', 'non-repudiation', 'audit trail', 'logging',
                'accountability', 'trace', 'attribution', 'audit log', 'log manipulation',
                'audit manipulation', 'functionality misuse', 'misuse'
            ]
        }
        
        #print(f"  Analyzing description for STRIDE patterns...")
        
        # Score each STRIDE category based on keyword matches
        category_scores = {}
        for stride_cat, patterns in stride_patterns.items():
            score = 0
            matched_patterns = []
            
            for pattern in patterns:
                if pattern in description:
                    score += 1
                    matched_patterns.append(pattern)
            
            if score > 0:
                category_scores[stride_cat] = (score, matched_patterns)
                #print(f"    {stride_cat}: {score} matches {matched_patterns}")
        
        # Return the category with the highest score
        if category_scores:
            best_category = max(category_scores.keys(), key=lambda k: category_scores[k][0])
            score, patterns = category_scores[best_category]
            #print(f"  Best match: {best_category} (score: {score}, patterns: {patterns})")
            return best_category
        
        # Check threat ID patterns (some PyTM models use specific ID patterns)
        if threat_id:
            id_patterns = {
                'Information Disclosure': ['INF', 'DISC', 'LEAK', 'PRIV'],
                'Tampering': ['TAMP', 'MOD', 'CORR', 'INJ'],
                'Spoofing': ['SPOOF', 'IMP', 'FAKE'],
                'Denial of Service': ['DOS', 'DDOS', 'AVAIL'],
                'Elevation of Privilege': ['PRIV', 'ESC', 'ELEV'],
                'Repudiation': ['REP', 'AUD', 'LOG']
            }
            
            threat_id_upper = threat_id.upper()
            for stride_cat, id_keywords in id_patterns.items():
                for keyword in id_keywords:
                    if keyword in threat_id_upper:
                        #print(f"  Found ID pattern '{keyword}' -> {stride_cat}")
                        return stride_cat
        
        
        # Check if there are severity, likelihood, or other indicators
        severity = getattr(threat, 'severity', None)
        likelihood = getattr(threat, 'likelihood', None)
        
        #if severity or likelihood:
        #    print(f"  Additional context - Severity: {severity}, Likelihood: {likelihood}")
        
        # Final fallback based on common threat descriptions
        common_threat_mappings = {
            # Web attacks and protocol manipulation - Tampering
            'smuggling': 'Tampering',
            'splitting': 'Tampering',
            'poisoning': 'Tampering', 
            'manipulation': 'Tampering',
            'inclusion': 'Tampering',
            'entities': 'Tampering',
            'blowup': 'Tampering',
            'detour': 'Tampering',
            'protocol': 'Tampering',
            'channel': 'Tampering',
            'remote code': 'Tampering',
            'xxe': 'Tampering',
            'xml': 'Tampering',
            'xss': 'Tampering',
            'cross-site': 'Tampering',
            'injection': 'Tampering',
            'reflected': 'Tampering',
            'stored': 'Tampering',
            'csrf': 'Tampering',
            'traversal': 'Tampering',
            'encoding': 'Tampering',
            'malicious': 'Tampering',
            'embedding': 'Tampering',
            'iframe': 'Tampering',
            'exploit': 'Tampering',
            'api': 'Tampering',
            'environment': 'Tampering',
            'subverting': 'Tampering',
            'delimiter': 'Tampering',
            'tracing': 'Tampering',
            
            # Session and identity attacks - Spoofing  
            'sidejacking': 'Spoofing',
            'hijacking': 'Spoofing',
            'replay': 'Spoofing',
            'reusing': 'Spoofing',
            'trust': 'Spoofing',
            'exploiting trust': 'Spoofing',
            'client trust': 'Spoofing',
            'credential': 'Spoofing',
            'authentication': 'Spoofing',
            'session': 'Spoofing',
            'json': 'Spoofing',
            'javascript': 'Spoofing',
            
            # Information gathering and disclosure - Information Disclosure
            'sniffing': 'Information Disclosure',
            'interception': 'Information Disclosure',
            'excavation': 'Information Disclosure',
            'footprinting': 'Information Disclosure',
            'fingerprinting': 'Information Disclosure',
            'reverse engineering': 'Information Disclosure',
            'white box': 'Information Disclosure',
            'ssl': 'Information Disclosure',
            'tls': 'Information Disclosure', 
            'configured': 'Information Disclosure',
            'configuration': 'Information Disclosure',
            'data': 'Information Disclosure',
            'information': 'Information Disclosure', 
            'access': 'Information Disclosure',
            
            # Resource exhaustion - Denial of Service
            'allocation': 'Denial of Service',
            'excessive': 'Denial of Service',
            'removing': 'Denial of Service',
            'functionality': 'Denial of Service',
            'service': 'Denial of Service',
            'resource': 'Denial of Service',
            
            # Privilege and password attacks - Elevation of Privilege
            'dictionary': 'Elevation of Privilege',
            'password': 'Elevation of Privilege',
            'attack': 'Elevation of Privilege',
            'common switches': 'Elevation of Privilege',
            'try all': 'Elevation of Privilege',
            'privileged': 'Elevation of Privilege',
            'privilege': 'Elevation of Privilege',
            'exception': 'Elevation of Privilege',
            'signal': 'Elevation of Privilege',
            'authorization': 'Elevation of Privilege',
            
            # Audit and logging - Repudiation
            'audit': 'Repudiation',
            'log': 'Repudiation',
            'misuse': 'Repudiation',
            
            # General patterns
            'input': 'Tampering',
            'validation': 'Tampering'
        }
        
        for keyword, stride_cat in common_threat_mappings.items():
            if keyword in description:
                #print(f"  Fallback mapping '{keyword}' -> {stride_cat}")
                return stride_cat
        
        print(f"  No classification found, checking if this is a data/information related threat...")
        
        # Since your example shows "Data Leak", default to Information Disclosure for data-related threats
        # But first check for other specific threat types
        if any(word in description for word in ['xss', 'cross-site', 'injection', 'reflected', 'stored']):
            print(f"  Detected web application attack, defaulting to Tampering")
            return 'Tampering'
        elif any(word in description for word in ['data', 'information', 'leak']):
            print(f"  Detected data-related threat, defaulting to Information Disclosure")
            return 'Information Disclosure'
        
        print(f"  Returning 'Unknown' - no patterns matched")
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
        #print(f"  Mapped {stride_category} to tactics: {tactics}")
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