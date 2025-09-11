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
import json
import logging
from typing import Dict, List, Any, Optional
import re
import ast
import xml.etree.ElementTree as ET

from pathlib import Path
from threat_analysis.custom_threats import get_custom_threats
from threat_analysis import data_loader
from threat_analysis.mitigation_suggestions import MitigationStixMapper, get_framework_mitigation_suggestions

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
    "M1055 Do Not Mitigate": [],
    "M1056 Pre-compromise": ["D3-DE Decoy Environment", "D3-DO Decoy Object"]
}

class MitreMapping:
    """Class for managing MITRE ATT&CK mapping with D3FEND mitigations"""
    def __init__(self, threat_model=None, threat_model_path: str = ""):
        self.d3fend_details = data_loader.load_d3fend_mapping()
        self.capec_to_mitre_map = data_loader.load_capec_to_mitre_mapping()
        self.stride_to_capec = data_loader.load_stride_to_capec_map()
        self.all_attack_techniques = data_loader.load_attack_techniques()
        self.mitigation_stix_mapper = MitigationStixMapper()
        self.technique_to_mitigation_map = self.mitigation_stix_mapper.attack_to_mitigations_map
        logging.info(f"MitreMapping initialized. technique_to_mitigation_map size: {len(self.technique_to_mitigation_map)}")
        self.custom_threats = self._load_custom_threats(threat_model)
        self.custom_mitre_mappings = []
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        if threat_model_path:
            full_markdown_path = os.path.join(project_root, threat_model_path)
            if os.path.exists(full_markdown_path):
                self.custom_mitre_mappings = self._load_custom_mitre_mappings_from_markdown(full_markdown_path)
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
                pattern = re.compile(r'- \*\*(.*?)\*\*:\s*(.*)')
                for line in mappings_content.split('\n'):
                    line = line.strip()
                    match = pattern.match(line)
                    if match:
                        threat_name = match.group(1).strip()
                        raw_mapping_string = match.group(2).strip()

                        try:
                            parsed_mapping = ast.literal_eval(raw_mapping_string)
                            tactics = parsed_mapping.get('tactics', [])
                            techniques = parsed_mapping.get('techniques', [])
                        except (SyntaxError, ValueError) as e:
                            logging.error(f"Error evaluating custom MITRE mapping for '{threat_name}': {e}")
                            tactics = []
                            techniques = []

                        custom_mappings.append({
                            "threat_name": threat_name,
                            "tactics": tactics,
                            "techniques": techniques
                        })
        except Exception as e:
            logging.error(f"Error loading custom MITRE mappings from markdown: {e}")
        return custom_mappings

    def _get_d3fend_mitigations_for_mitre_id(self, mitigation_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves D3FEND mitigations for a given MITRE mitigation ID.
        """
        d3fend_mitigations = []
        # Find the matching MITRE mitigation in the attack_d3fend_mapping
        for attack_d3fend_key, d3fend_entries in attack_d3fend_mapping.items():
            if mitigation_id in attack_d3fend_key:
                for d3fend_entry in d3fend_entries:
                    # Extract D3FEND ID
                    d3fend_id_match = re.match(r'^(D3-[A-Z0-9]+)', d3fend_entry)
                    if d3fend_id_match:
                        d3fend_id = d3fend_id_match.group(1)
                        # Check if we have details for this D3FEND ID
                        if d3fend_id in self.d3fend_details:
                            # Create a URL-friendly name from the description
                            name_part = self.d3fend_details[d3fend_id]['name']
                            url_friendly_name = name_part.replace(' ', '-')
                            
                            d3fend_mitigations.append({
                                "id": d3fend_id,
                                "name": name_part,
                                "description": self.d3fend_details[d3fend_id]['description'],
                                "url_friendly_name": url_friendly_name
                            })
                        else:
                            # Fallback if no details are found
                            name_part = d3fend_entry.split(' ', 1)[1] if ' ' in d3fend_entry else d3fend_entry
                            url_friendly_name = name_part.replace(' ', '-')
                            d3fend_mitigations.append({
                                "id": "UNKNOWN",
                                "name": name_part,
                                "description": "D3FEND mitigation details not found or not applicable.",
                                "url_friendly_name": url_friendly_name
                            })
                # Since we found the matching MITRE ID, we can stop searching
                break
        return d3fend_mitigations

    def map_threat_to_mitre(self, threat: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Maps a threat to MITRE ATT&CK techniques and CAPEC patterns.
        It uses a dynamic mapping from the loaded JSON data.
        """
        found_techniques = {}
        found_capecs = {}
        stride_category = threat.get("stride_category", "")

        direct_capec_ids = threat.get("capec_ids", [])
        if not direct_capec_ids:
            normalized_stride = stride_category.replace(" ", "")
            if "DenialOfService" in normalized_stride:
                 normalized_stride = "DenialOfService"
            capec_list = self.stride_to_capec.get(normalized_stride, [])
            direct_capec_ids = [c['capec_id'] for c in capec_list]
            for capec_info in capec_list:
                if capec_info['capec_id'] not in found_capecs:
                    found_capecs[capec_info['capec_id']] = capec_info

        for capec_id in direct_capec_ids:
            if capec_id not in found_capecs:
                 for cat_capecs in self.stride_to_capec.values():
                    for capec_info in cat_capecs:
                        if capec_info['capec_id'] == capec_id:
                            found_capecs[capec_id] = capec_info
                            break
            
            technique_ids = self.capec_to_mitre_map.get(capec_id, [])
            #if not technique_ids:
                #logging.warning(f"WARNING: No ATT&CK techniques found for CAPEC ID {capec_id}")
            for tech_id in technique_ids:
                if tech_id in self.all_attack_techniques and tech_id not in found_techniques:
                    technique_data = self.all_attack_techniques[tech_id].copy()
                    
                    technique_data['mitre_mitigations'] = self.technique_to_mitigation_map.get(tech_id, [])
                    d3fend_list = []
                    for mitre_mitigation in technique_data['mitre_mitigations']:
                        mitigation_id = mitre_mitigation.get('id')
                        if mitigation_id:
                            d3fend_list.extend(self._get_d3fend_mitigations_for_mitre_id(mitigation_id))
                    technique_data['defend_mitigations'] = d3fend_list

                    framework_mitigations = get_framework_mitigation_suggestions([tech_id])
                    technique_data['owasp_mitigations'] = [m for m in framework_mitigations if m.get('framework') == 'OWASP ASVS']
                    technique_data['nist_mitigations'] = [m for m in framework_mitigations if m.get('framework') == 'NIST']
                    technique_data['cis_mitigations'] = [m for m in framework_mitigations if m.get('framework') == 'CIS']

                    found_techniques[tech_id] = technique_data
        
        return {
            "techniques": list(found_techniques.values()),
            "capecs": list(found_capecs.values())
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
            
            threat_dict = {
                "description": threat_description,
                "stride_category": stride_category,
                "capec_ids": getattr(threat, 'capec_ids', [])
            }
            mapping_results = self.map_threat_to_mitre(threat_dict)

            mitre_techniques = mapping_results.get('techniques', [])
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
        logging.info(f"\n=== Final Results ====")
        logging.info(f"Total threats: {results['total_threats']}")
        return results

    def classify_pytm_threat(self, threat) -> str:
        """
        Classifies a threat into a STRIDE category based on its properties.
        """
        if hasattr(threat, 'stride_category') and threat.stride_category:
            return threat.stride_category
        threat_class_name = threat.__class__.__name__
        if threat_class_name in ['Spoofing', 'Tampering', 'Repudiation', 'InformationDisclosure', 'DenialOfService', 'ElevationOfPrivilege']:
            return threat_class_name
        description = getattr(threat, 'description', '').lower()
        if not description:
            return 'Unknown'
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
            'Information Disclosure': ['Collection', 'Exfiltration', 'Discovery'],
            'Tampering': ['Defense Evasion', 'Impact', 'Initial Access', 'Execution'],
            'Spoofing': ['Initial Access', 'Credential Access', 'Defense Evasion'],
            'Denial of Service': ['Impact'],
            'Elevation of Privilege': ['Privilege Escalation', 'Defense Evasion'],
            'Repudiation': ['Defense Evasion', 'Impact']
        }
        tactics = stride_to_tactics.get(stride_category, [])
        return tactics
    
    def get_stride_categories(self) -> List[str]:
        """Returns the list of available STRIDE categories."""
        return list(self.stride_to_capec.keys())