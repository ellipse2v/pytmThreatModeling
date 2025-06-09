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
                    }
                ]
            }
        }
    
    def _initialize_threat_patterns(self) -> Dict[str, str]:
        """Initializes threat recognition patterns for STRIDE classification"""
        return {
            # Spoofing patterns
            "phishing": "Spoofing",
            "principal spoof": "Spoofing",
            "masquerading": "Spoofing",
            "content spoofing": "Spoofing",
            "authentication abuse": "Spoofing",
            "authentication bypass": "Spoofing",
            "session credential falsification": "Spoofing",
            "session sidejacking": "Spoofing",
            
            # Tampering patterns
            "data manipulation": "Tampering",
            "input data manipulation": "Tampering",
            "buffer manipulation": "Tampering",
            "shared data manipulation": "Tampering",
            "sql injection": "Tampering",
            "xml injection": "Tampering",
            "command injection": "Tampering",
            "code injection": "Tampering",
            "parameter injection": "Tampering",
            "ldap injection": "Tampering",
            "format string injection": "Tampering",
            "file content injection": "Tampering",
            "argument injection": "Tampering",
            "resource injection": "Tampering",
            "dtd injection": "Tampering",
            "imap/smtp command injection": "Tampering",
            "server side include": "Tampering",
            "soap parameter tampering": "Tampering",
            "registry manipulation": "Tampering",
            "double encoding": "Tampering",
            "client-server protocol manipulation": "Protocol Tampering",
            "communication channel manipulation": "Protocol Tampering",
            "http request splitting": "Protocol Tampering",
            "http request smuggling": "Protocol Tampering",
            "http response smuggling": "Protocol Tampering",
            
            # Repudiation patterns
            "audit log manipulation": "Repudiation",
            
            # Information Disclosure patterns
            "data leak": "InformationDisclosure",
            "unprotected sensitive data": "InformationDisclosure",
            "lifting sensitive data": "InformationDisclosure",
            "sniffing attacks": "InformationDisclosure",
            "interception": "InformationDisclosure",
            "excavation": "InformationDisclosure",
            "footprinting": "InformationDisclosure",
            "web application fingerprinting": "InformationDisclosure",
            "reverse engineering": "InformationDisclosure",
            "white box reverse engineering": "InformationDisclosure",
            "cross site tracing": "InformationDisclosure",
            "json hijacking": "InformationDisclosure",
            "javascript hijacking": "InformationDisclosure",
            
            # Denial of Service patterns
            "flooding": "DenialOfService",
            "excessive allocation": "DenialOfService",
            "xml ping of the death": "DenialOfService",
            "xml entity expansion": "DenialOfService",
            "xml external entities blowup": "DenialOfService",
            "xml attribute blowup": "DenialOfService",
            "xml nested payloads": "DenialOfService",
            "soap array overflow": "DenialOfService",
            "buffer overflow": "DenialOfService",
            "overflow buffers": "DenialOfService",
            "client-side injection-induced buffer overflow": "DenialOfService",
            "filter failure through buffer overflow": "DenialOfService",
            "resource hijacking": "DenialOfService",
            "removing important client functionality": "DenialOfService",
            
            # Elevation of Privilege patterns
            "privilege escalation": "ElevationOfPrivilege",
            "privilege abuse": "ElevationOfPrivilege",
            "hijacking a privileged process": "ElevationOfPrivilege",
            "exploitation of trusted credentials": "ElevationOfPrivilege",
            "exploiting incorrectly configured access control": "ElevationOfPrivilege",
            "exploiting trust in client": "ElevationOfPrivilege",
            "catching exception throw": "ElevationOfPrivilege",
            "functionality misuse": "ElevationOfPrivilege",
            "exploiting incorrectly configured ssl": "ElevationOfPrivilege"
        }
    
    def classify_threat_by_description(self, description: str) -> str:
        """Classifies a threat according to STRIDE based on its description"""
        if not description:
            return "Threat"
            
        description_lower = description.lower()
        
        # Search for the best match (most specific)
        best_match = None
        best_score = 0
        
        for pattern, stride_category in self.threat_patterns.items():
            if pattern in description_lower:
                # Score based on pattern length to prioritize more specific matches
                score = len(pattern)
                if score > best_score:
                    best_score = score
                    best_match = stride_category
        
        return best_match or "Threat"
    
    def get_mapping_for_threat(self, threat_type: str) -> Dict[str, Any]:
        """Returns the MITRE mapping for a threat type"""
        return self.mapping.get(threat_type, {})
    
    def get_mapping_for_threat_description(self, description: str) -> Dict[str, Any]:
        """Returns the MITRE mapping based on the threat description"""
        stride_category = self.classify_threat_by_description(description)
        return self.get_mapping_for_threat(stride_category)
    
    def get_all_techniques(self) -> List[Dict[str, str]]:
        """Returns all MITRE techniques"""
        techniques = []
        for threat_info in self.mapping.values():
            techniques.extend(threat_info.get("techniques", []))
        return techniques
    
    def get_techniques_count(self) -> int:
        """Returns the total number of techniques"""
        return len(self.get_all_techniques())
    
    def add_custom_mapping(self, threat_type: str, tactics: List[str], techniques: List[Dict[str, str]]):
        """Adds a custom mapping"""
        self.mapping[threat_type] = {
            "tactics": tactics,
            "techniques": techniques
        }
    
    def add_custom_threat_pattern(self, pattern: str, stride_category: str):
        """Adds a custom pattern for threat classification"""
        self.threat_patterns[pattern.lower()] = stride_category
    
    def get_tactics_for_threat(self, threat_type: str) -> List[str]:
        """Returns tactics for a threat type"""
        return self.mapping.get(threat_type, {}).get("tactics", [])
    
    def get_techniques_for_threat(self, threat_type: str) -> List[Dict[str, str]]:
        """Returns techniques for a threat type"""
        return self.mapping.get(threat_type, {}).get("techniques", [])
    
    def get_techniques_for_description(self, description: str) -> List[Dict[str, str]]:
        """Returns MITRE techniques based on the threat description"""
        stride_category = self.classify_threat_by_description(description)
        return self.get_techniques_for_threat(stride_category)
    
    def analyze_threats_list(self, threats_list: List[Dict]) -> Dict[str, Any]:
        """Analyzes a list of threats and applies MITRE mapping"""
        results = {
            "total_threats": len(threats_list),
            "stride_distribution": {},
            "mitre_techniques_count": 0,
            "processed_threats": []
        }
        
        for threat in threats_list:
            # STRIDE classification
            description = threat.get("description", "")
            stride_category = self.classify_threat_by_description(description)
            
            # MITRE mapping
            mitre_techniques = self.get_techniques_for_description(description)
            
            # Update threat
            processed_threat = threat.copy()
            processed_threat["stride_category"] = stride_category
            processed_threat["mitre_techniques"] = mitre_techniques
            
            results["processed_threats"].append(processed_threat)
            
            # Statistics
            if stride_category not in results["stride_distribution"]:
                results["stride_distribution"][stride_category] = 0
            results["stride_distribution"][stride_category] += 1
            
            results["mitre_techniques_count"] += len(mitre_techniques)
        
        return results
    
    def get_stride_categories(self) -> List[str]:
        """Returns the list of available STRIDE categories"""
        return list(self.mapping.keys())
    
    def get_threat_patterns(self) -> Dict[str, str]:
        """Returns the threat recognition patterns"""
        return self.threat_patterns.copy()
    
    def search_techniques_by_id(self, technique_id: str) -> List[Dict[str, Any]]:
        """Searches for techniques by MITRE ID"""
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
        """Returns mapping statistics"""
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