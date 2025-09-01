#!/usr/bin/env python
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
This module contains static dictionaries for MITRE ATT&CK mappings.
"""

ATTACK_D3FEND_MAPPING = {
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

STATIC_TECHNIQUE_MAPPING = {
    "Spoofing": {
        "tactics": ["Initial Access", "Defense Evasion", "Credential Access"],
        "techniques": [
            {
                "id": "T1566",
                "name": "Phishing",
                "description": "Identity spoofing via phishing",
                "url": "https://attack.mitre.org/techniques/T1566/",
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
                "url": "https://attack.mitre.org/techniques/T1036/",
                "mitre_mitigations": [
                    {"id": "M1049", "name": "Antivirus/Antimalware"},
                    {"id": "M1045", "name": "Code Signing"},
                    {"id": "M1038", "name": "Execution Prevention"},
                    {"id": "M1026", "name": "Privileged Account Management"}
                ]
            }
        ]
    }
}

THREAT_PATTERNS = {
    "T1566": r"(?i)phishing|identity spoofing|social engineering|spear phishing",
    "T1036": r"(?i)masquerading|impersonation|disguise|process masquerading"
}
