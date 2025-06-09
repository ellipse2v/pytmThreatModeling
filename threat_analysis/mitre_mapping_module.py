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
        """Initializes STRIDE to MITRE ATT&CK mapping"""
        return {
            "Spoofing": {
                "tactics": ["Initial Access", "Defense Evasion"],
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
                    { # Added for Session Sidejacking / Credential Falsification related to Spoofing
                        "id": "T1078.003",
                        "name": "Kerberoasting", # Often related to session/credential abuse
                        "description": "Attempting to obtain service principal names and then crack them offline."
                    },
                    { # Added for general authentication bypass/abuse
                        "id": "T1110",
                        "name": "Brute Force",
                        "description": "Repeatedly trying to guess authentication credentials."
                    }
                ]
            },
            "Tampering": {
                "tactics": ["Defense Evasion", "Impact"],
                "techniques": [
                    {
                        "id": "T1565",
                        "name": "Data Manipulation",
                        "description": "Unauthorized data modification"
                    },
                    {
                        "id": "T1070",
                        "name": "Indicator Removal on Host",
                        "description": "Deletion of activity traces"
                    },
                    {
                        "id": "T1027",
                        "name": "Obfuscated Files or Information",
                        "description": "Obfuscation of malicious files"
                    },
                    { # Added for Injection types (SQL, Command, Code, LDAP, Format String, Parameter)
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "description": "Exploiting vulnerabilities in applications accessible from the internet."
                    },
                     { # Specifically for Cross-Site Scripting (XSS)
                        "id": "T1190.001", # Custom sub-technique for web-based injections (if T1190 is too broad for XSS)
                        "name": "Cross-Site Scripting (XSS)",
                        "description": "Exploiting vulnerabilities in web applications to inject malicious scripts into trusted websites."
                    },
                    { # For File Content Injection, Remote Code Inclusion
                        "id": "T1505.003",
                        "name": "Server Software Component: Web Shell",
                        "description": "Install a web shell to gain persistent access."
                    },
                     { # For XML related tampering, and general defense impairment
                        "id": "T1562.001",
                        "name": "Impair Defenses: Disable or Modify System Firewall", # This is just an example, more specific TIDs might be needed
                        "description": "Modify firewall rules to allow unauthorized access."
                    }
                ]
            },
            "Repudiation": {
                "tactics": ["Defense Evasion"],
                "techniques": [
                    {
                        "id": "T1070.002",
                        "name": "Clear Linux or Mac System Logs",
                        "description": "Clearing system logs"
                    },
                    {
                        "id": "T1070.001",
                        "name": "Clear Windows Event Logs",
                        "description": "Clearing Windows event logs"
                    },
                    {
                        "id": "T1562",
                        "name": "Impair Defenses",
                        "description": "Disabling defense mechanisms"
                    },
                    { # For Audit Log Manipulation
                        "id": "T1070.004",
                        "name": "File Deletion",
                        "description": "Removing or deleting files to remove traces of activity."
                    }
                ]
            },
            "InformationDisclosure": {
                "tactics": ["Collection", "Exfiltration"],
                "techniques": [
                    {
                        "id": "T1005",
                        "name": "Data from Local System",
                        "description": "Collecting local data"
                    },
                    {
                        "id": "T1041",
                        "name": "Exfiltration Over C2 Channel",
                        "description": "Exfiltration via C2 channel"
                    },
                    {
                        "id": "T1083",
                        "name": "File and Directory Discovery",
                        "description": "Discovery of sensitive files"
                    },
                    { # For Sniffing, Interception, Cross Site Tracing, JSON Hijacking
                        "id": "T1040",
                        "name": "Network Sniffing",
                        "description": "Capturing network traffic to collect sensitive information."
                    },
                    { # For Footprinting, Web Application Fingerprinting, Reverse Engineering
                        "id": "T1592",
                        "name": "Gather Victim Host Information",
                        "description": "Gathering information about the target host through various means."
                    },
                    {
                        "id": "T1595",
                        "name": "Active Scanning",
                        "description": "Using active scanning techniques to gain information about the target."
                    },
                    { # For Path Traversal, Subverting Environment Variable Values (as info disclosure)
                        "id": "T1592.002", # Sub-technique for specific host information gathering
                        "name": "Gather Victim Host Information: Software",
                        "description": "Gathering information about software installed on a victim host."
                    }
                ]
            },
            "DenialOfService": {
                "tactics": ["Impact"],
                "techniques": [
                    {
                        "id": "T1499",
                        "name": "Endpoint Denial of Service",
                        "description": "Denial of service on endpoints"
                    },
                    {
                        "id": "T1498",
                        "name": "Network Denial of Service",
                        "description": "Network denial of service"
                    },
                    {
                        "id": "T1496",
                        "name": "Resource Hijacking",
                        "description": "System resource hijacking"
                    },
                    { # For Flooding, Excessive Allocation, XML DoS types, Buffer Overflow
                        "id": "T1499.001",
                        "name": "Endpoint Denial of Service: Application or System Impairment",
                        "description": "Causing an application or system to become unresponsive or crash."
                    }
                ]
            },
            "ElevationOfPrivilege": {
                "tactics": ["Privilege Escalation", "Persistence"],
                "techniques": [
                    {
                        "id": "T1548",
                        "name": "Abuse Elevation Control Mechanism",
                        "description": "Exploiting elevation mechanisms"
                    },
                    {
                        "id": "T1055",
                        "name": "Process Injection",
                        "description": "Injecting into processes"
                    },
                    {
                        "id": "T1068",
                        "name": "Exploitation for Privilege Escalation",
                        "description": "Exploiting vulnerabilities for elevation"
                    },
                    { # For Hijacking a privileged process, Catching exception throw/signal
                        "id": "T1055.001",
                        "name": "Process Injection: Dynamic-link Library Injection",
                        "description": "Injecting malicious code into a running process using DLL injection."
                    },
                    { # For Functionality Misuse, Exploiting Incorrectly Configured Access Control/SSL
                        "id": "T1078.001",
                        "name": "Valid Accounts: Default Accounts",
                        "description": "Using default credentials to gain unauthorized access."
                    }
                ]
            },
            "Protocol Tampering": {
                "tactics": ["Impact", "Defense Evasion"],
                "techniques": [
                    {
                        "id": "T1565",
                        "name": "Data Manipulation",
                        "description": "Unauthorized data modification"
                    },
                    {
                        "id": "T1499",
                        "name": "Endpoint Denial of Service",
                        "description": "Denial of service on endpoints"
                    },
                    { # Specifically for protocol-level manipulation
                        "id": "T1573",
                        "name": "Encrypted Channel",
                        "description": "Communicating over a custom or modified encrypted channel to evade detection."
                    }
                ]
            }
        }
    
    def _initialize_threat_patterns(self) -> Dict[str, str]:
        """
        Initializes threat recognition patterns for STRIDE classification.
        These patterns map specific threat descriptions to a MITRE ATT&CK Technique ID
        (T-ID) or directly to a STRIDE category.
        
        Note: The 'get_techniques_count()' method counts the distinct MITRE T-IDs
        defined in the '_initialize_mapping' dictionary, not every single pattern listed here.
        Many specific attack vectors (like 'Buffer Overflow via Environment Variables')
        map to broader MITRE techniques (like 'Endpoint Denial of Service' or 'Exploitation for Privilege Escalation').
        """
        return {
            # === Patterns for common PyTM classes (already broad MITRE IDs) ===
            "T1566": r"(?i)phishing|identity spoofing|social engineering",
            "T1036": r"(?i)masquerading|impersonation|disguise",
            "T1078": r"(?i)valid accounts|compromised credentials|stolen accounts|authentication abuse|authentication bypass|weak authentication|insecure credentials|exploitation of trusted credentials|reusing session ids|session replay|principal spoof|session credential falsification", # Expanded
            "T1561": r"(?i)disk wipe|data erasure|file deletion",
            "T1485": r"(?i)data destruction|data corruption|data deletion",
            "T1565": r"(?i)data manipulation|process tampering|alteration of data|input data manipulation|buffer manipulation|shared data manipulation|parameter injection|leverage alternate encoding|schema poisoning|xml schema poisoning|xml attribute blowup|xml nested payloads|file content injection|audit log manipulation", # Expanded significantly
            "T1070": r"(?i)log deletion|indicator removal|trace removal|audit log manipulation|clear (linux|mac|windows) system logs", # Already in 1565, but can be distinct for repudiation
            "T1489": r"(?i)service stop|process termination|disabling services",
            "T1005": r"(?i)sensitive data disclosure|local data exfiltration|data access|data leak|unprotected sensitive data|lifting sensitive data embedded in cache|credentials aging", # Expanded
            "T1041": r"(?i)c2 exfiltration|command and control exfiltration|data exfiltration|data theft",
            "T1020": r"(?i)automated exfiltration|mass data transfer",
            "T1498": r"(?i)defacement|website alteration|interface modification",
            "T1499": r"(?i)denial of service|DoS attack|resource exhaustion|flooding|excessive allocation|xml ping of the death|xml entity expansion|xml external entities blowup|soap array overflow|buffer overflow|overflow buffers|client-side injection-induced buffer overflow|filter failure through buffer overflow|ddos|dos|removing important client functionality", # Expanded
            "T1490": r"(?i)inhibit system recovery|prevent recovery|backup destruction",
            "T1068": r"(?i)privilege escalation|root access|admin rights|exploitation for privilege escalation", # Expanded
            "T1548": r"(?i)abuse elevation control mechanism|bypass UAC|elevation bypass|privilege abuse|exploiting incorrectly configured access control security levels|exploiting trust in client|functionality misuse|exploiting incorrectly configured ssl|unauthorized access|access control bypass|hijacking a privileged process|catching exception throw/signal from privileged block", # Expanded
            "T1190": r"(?i)injection|sql injection|xml injection|command injection|code injection|ldap injection|format string injection|server side include|ssi injection|soap parameter tampering|remote code inclusion|imap/smtp command injection|argument injection|dtd injection|resource injection", # Broad injection techniques
            "T1190.001": r"(?i)xss|cross site scripting|dom-based xss|reflected xss|stored xss|xss targeting (non-script elements|error pages|html attributes|uri placeholders)|xss using (alternate syntax|doubled characters|invalid characters|mime type mismatch)|embedding scripts within scripts", # Specific XSS
            "T1040": r"(?i)sniffing attacks|interception|session sidejacking", # Network sniffing and interception
            "T1592": r"(?i)footprinting|web application fingerprinting|reverse engineering|white box reverse engineering|excavation|fuzzing and observing application log data/errors for application mapping", # Information gathering
            "T1595": r"(?i)fuzzing|try all common switches", # Active Scanning (could also be part of T1592 if purely for info)
            "T1055": r"(?i)process injection|hijacking a privileged process|catching exception throw/signal from privileged block|embedding scripts within scripts", # Process Injection/Execution (overlaps with T1548 for priv esc)
            "T1133": r"(?i)external remote services|unauthorized access", # Access via remote services
            "T1573": r"(?i)client-server protocol manipulation|communication channel manipulation|http request splitting|http request smuggling|http response smuggling|protocol tampering|xml routing detour attacks", # Protocol Manipulation

            # Specific threat names from the provided list, mapping to the most relevant T-ID or STRIDE category
            # If a T-ID is already defined, we map to that T-ID. Otherwise, we map to STRIDE.
            "Buffer Overflow via Environment Variables": "DenialOfService", # Could be EoP too, depending on context
            "Cross Site Tracing": "InformationDisclosure",
            "Command Line Execution through SQL Injection": "Tampering", # Specific injection
            "SQL Injection through SOAP Parameter Tampering": "Tampering", # Specific injection
            "JSON Hijacking": "InformationDisclosure",
            "JavaScript Hijacking": "InformationDisclosure",
            "API Manipulation": "Tampering",
            "Exploit Test APIs": "Tampering",
            "Exploit Script-Based APIs": "Tampering",
            "Using Malicious Files": "Tampering", # Broad, could lead to various impacts
            "Command Delimiters": "Tampering", # Specific injection technique
            "Subverting Environment Variable Values": "Tampering", # Leads to tampering/EoP
            "Content Spoofing": "Spoofing",
            "Dictionary-based Password Attack": "Spoofing", # maps to T1110 (Brute Force)
            "PHP Remote File Inclusion": "Tampering", # Maps to T1505.003 or T1190
            "Manipulate Registry Information": "Tampering",
            "Unprotected Sensitive Data": "InformationDisclosure",
            
            # === PyTM direct class names and their variations ===
            "spoofing": "Spoofing",
            "tampering": "Tampering", 
            "repudiation": "Repudiation",
            "informationdisclosure": "InformationDisclosure",
            "denialofservice": "DenialOfService", 
            "elevationofprivilege": "ElevationOfPrivilege",
            "information disclosure": "InformationDisclosure",
            "denial of service": "DenialOfService",
            "elevation of privilege": "ElevationOfPrivilege",
            "protocol tampering": "Protocol Tampering" # Added for clarity
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
    
    
    def classify_threat_by_description(self, description: str) -> str:
        """Classifies a threat according to STRIDE based on its description"""
        if not description:
            return "Threat"
            
        description_lower = description.lower()
        
        # Search for the best match (most specific pattern)
        best_match_category = None
        best_pattern_length = 0
        
        for pattern_str, mapped_value in self.threat_patterns.items():
            if re.search(pattern_str, description_lower):
                current_pattern_length = len(pattern_str) # Simple score: longer pattern is more specific

                if current_pattern_length > best_pattern_length:
                    # If mapped_value is a STRIDE category string
                    if mapped_value in self.mapping:
                        best_match_category = mapped_value
                        best_pattern_length = current_pattern_length
                    # If mapped_value is a T-ID, find its STRIDE category
                    elif re.match(r'T\d{4}(?:\.\d{3})?', mapped_value):
                        for category_name, category_info in self.mapping.items():
                            for tech in category_info.get("techniques", []):
                                if tech.get("id") == mapped_value:
                                    best_match_category = category_name
                                    best_pattern_length = current_pattern_length
                                    break
                            if best_match_category:
                                break
        
        return best_match_category or "Threat"
    
    def classify_threat_by_name_and_description(self, threat_name: str, description: str = "") -> str:
        """
        Classifies a threat based on its name AND description,
        optimized for PyTM threat objects.
        """
        if not threat_name and not description:
            return "Threat"
        
        combined_text = f"{threat_name} {description}".lower()
        
        best_match_category = None
        best_pattern_length = 0
        
        for pattern_str, mapped_value in self.threat_patterns.items():
            if re.search(pattern_str, combined_text):
                current_pattern_length = len(pattern_str)

                if current_pattern_length > best_pattern_length:
                    if mapped_value in self.mapping:
                        best_match_category = mapped_value
                        best_pattern_length = current_pattern_length
                    elif re.match(r'T\d{4}(?:\.\d{3})?', mapped_value):
                        for category_name, category_info in self.mapping.items():
                            for tech in category_info.get("techniques", []):
                                if tech.get("id") == mapped_value:
                                    best_match_category = category_name
                                    best_pattern_length = current_pattern_length
                                    break
                            if best_match_category:
                                break
        
        return best_match_category or "Threat"
    
    def classify_pytm_threat(self, threat_obj: Any) -> str:
        """
        Classifies a PyTM threat object to its STRIDE category.
        """
        threat_name = str(threat_obj.__class__.__name__)
        threat_description = getattr(threat_obj, 'description', '')
        threat_details = getattr(threat_obj, 'details', '')
        
        # Combine all available information from the PyTM object
        full_context = f"{threat_name} {threat_description} {threat_details}"
        
        return self.classify_threat_by_name_and_description(threat_name, full_context)
    
    def get_mapping_for_threat(self, threat_type: str) -> Dict[str, Any]:
        """Returns the MITRE mapping for a threat type (STRIDE category)."""
        return self.mapping.get(threat_type, {})
    
    def get_mapping_for_threat_description(self, description: str) -> Dict[str, Any]:
        """Returns the MITRE mapping based on the threat description."""
        stride_category = self.classify_threat_by_description(description)
        return self.get_mapping_for_threat(stride_category)
    
    def get_mapping_for_pytm_threat(self, threat_obj: Any) -> Dict[str, Any]:
        """
        Returns the MITRE mapping for a PyTM threat object.
        """
        stride_category = self.classify_pytm_threat(threat_obj)
        return self.get_mapping_for_threat(stride_category)
    
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
    
    def add_custom_threat_pattern(self, pattern: str, target: str):
        """
        Adds a custom pattern for threat classification.
        Target can be a STRIDE category (e.g., "Spoofing") or a MITRE T-ID (e.g., "T1078").
        """
        self.threat_patterns[pattern.lower()] = target
    
    def get_tactics_for_threat(self, threat_type: str) -> List[str]:
        """Returns tactics for a STRIDE threat type."""
        return self.mapping.get(threat_type, {}).get("tactics", [])
    
    def get_techniques_for_threat(self, threat_type: str) -> List[Dict[str, str]]:
        """Returns techniques for a STRIDE threat type."""
        return self.mapping.get(threat_type, {}).get("techniques", [])
    
    def get_techniques_for_description(self, description: str) -> List[Dict[str, str]]:
        """Returns MITRE techniques based on the threat description by inferring STRIDE category."""
        stride_category = self.classify_threat_by_description(description)
        return self.get_techniques_for_threat(stride_category)
    
    def get_techniques_for_pytm_threat(self, threat_obj: Any) -> List[Dict[str, str]]:
        """
        Returns MITRE techniques for a PyTM threat object.
        """
        stride_category = self.classify_pytm_threat(threat_obj)
        return self.get_techniques_for_threat(stride_category)
    
    def analyze_threats_list(self, threats_list: List[Dict]) -> Dict[str, Any]:
        """Analyzes a list of threats (dictionaries) and applies MITRE mapping."""
        results = {
            "total_threats": len(threats_list),
            "stride_distribution": {},
            "mitre_techniques_count": 0,
            "processed_threats": []
        }
        
        for threat in threats_list:
            description = threat.get("description", "")
            stride_category = self.classify_threat_by_description(description)
            
            mitre_techniques = self.map_threat_to_mitre(description)
            
            processed_threat = threat.copy()
            processed_threat["stride_category"] = stride_category
            processed_threat["mitre_techniques"] = mitre_techniques
            
            results["processed_threats"].append(processed_threat)
            
            if stride_category not in results["stride_distribution"]:
                results["stride_distribution"][stride_category] = 0
            results["stride_distribution"][stride_category] += 1
            
            results["mitre_techniques_count"] += len(mitre_techniques) # This counts mapped techniques for THIS threat
        
        return results
    
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
        
        for threat_tuple in pytm_threats_list:
            if isinstance(threat_tuple, tuple):
                threat, target = threat_tuple
            else:
                threat = threat_tuple
                target = getattr(threat, 'target', None)
            
            stride_category = self.classify_pytm_threat(threat)
            
            threat_description_for_mapping = getattr(threat, 'description', '')
            mitre_techniques = self.map_threat_to_mitre(threat_description_for_mapping)
            
            mitre_tactics = self.get_tactics_for_threat(stride_category)
            
            processed_threat = {
                "threat_name": str(threat.__class__.__name__),
                "description": threat_description_for_mapping,
                "target": str(target) if target else "Unknown",
                "stride_category": stride_category,
                "mitre_tactics": mitre_tactics,
                "mitre_techniques": mitre_techniques,
                "original_threat": threat
            }
            
            results["processed_threats"].append(processed_threat)
            
            if stride_category not in results["stride_distribution"]:
                results["stride_distribution"][stride_category] = 0
            results["stride_distribution"][stride_category] += 1
            
            results["mitre_techniques_count"] += len(mitre_techniques)
        
        return results
    
    def get_stride_categories(self) -> List[str]:
        """Returns the list of available STRIDE categories."""
        return list(self.mapping.keys())
    
    def get_threat_patterns(self) -> Dict[str, str]:
        """Returns the threat recognition patterns."""
        return self.threat_patterns.copy()
    
    def search_techniques_by_id(self, technique_id: str) -> List[Dict[str, Any]]:
        """Searches for techniques by MITRE ID."""
        found_techniques = []
        for category, mapping_info in self.mapping.items():
            for technique in mapping_info.get("techniques", []):
                if technique.get("id") == technique_id:
                    result = technique.copy()
                    result["stride_category"] = category
                    result["tactics"] = mapping_info.get("tactics", [])
                    found_techniques.append(result)
        return found_techniques
    
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