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

THREAT_RULES = {
    "servers": [
        {
            "conditions": {},
            "threats": [
                {"description": "Unpatched OS or software vulnerabilities on {name} leading to system compromise", "stride_category": "Tampering", "impact": 4, "likelihood": 4},
                {"description": "Insecure security configuration or hardening on {name} leading to information exposure", "stride_category": "Information Disclosure", "impact": 3, "likelihood": 3},
                {"description": "Unauthorized privilege escalation on {name} due to misconfiguration or vulnerability", "stride_category": "Elevation of Privilege", "impact": 5, "likelihood": 4},
                {"description": "Lack of monitoring or logging on {name}, preventing detection of malicious activities and enabling repudiation", "stride_category": "Repudiation", "impact": 3, "likelihood": 4},
            ]
        },
        {
            "conditions": {"type": "database"},
            "threats": [
                {"description": "Unauthorized access to sensitive data stored in {name} leading to data breach", "stride_category": "Information Disclosure", "impact": 5, "likelihood": 4},
                {"description": "Data exfiltration or leakage from {name} to external systems", "stride_category": "Information Disclosure", "impact": 5, "likelihood": 4},
                {"description": "Data corruption or tampering in {name} via unauthorized write access or SQL injection", "stride_category": "Tampering", "impact": 5, "likelihood": 4},
                {"description": "Denial of Service against {name} through resource-intensive queries or excessive connections", "stride_category": "Denial of Service", "impact": 4, "likelihood": 3},
            ]
        },
        {
            "conditions": {"type": "app-server"},
            "threats": [
                {"description": "SQL or NoSQL injection vulnerability in the application on {name} allowing command execution or data manipulation", "stride_category": "Tampering", "impact": 5, "likelihood": 5},
                {"description": "Cross-Site Scripting (XSS) vulnerability allowing script injection on {name} affecting user sessions", "stride_category": "Tampering", "impact": 3, "likelihood": 4},
                {"description": "Insecure Direct Object References (IDOR) leading to unauthorized data access on {name} by bypassing authorization", "stride_category": "Information Disclosure", "impact": 4, "likelihood": 4},
            ]
        },
        {
            "conditions": {"type": "firewall"},
            "threats": [
                {"description": "Firewall rule misconfiguration allowing unintended traffic to bypass {name} and reach internal networks", "stride_category": "Spoofing", "impact": 4, "likelihood": 4},
                {"description": "Denial of Service (DoS) attack targeting {name} to exhaust its resources and disrupt network connectivity", "stride_category": "Denial of Service", "impact": 5, "likelihood": 4},
                {"description": "Vulnerability in the management interface of {name} leading to critical privilege escalation", "stride_category": "Elevation of Privilege", "impact": 5, "likelihood": 5},
                {"description": "Firewall bypass through fragmented packets or other evasion techniques against {name}", "stride_category": "Spoofing", "impact": 4, "likelihood": 4},
            ]
        },
        {
            "conditions": {"type": "load-balancer"},
            "threats": [
                {"description": "Session hijacking or fixation attack against the {name} leading to unauthorized access", "stride_category": "Spoofing", "impact": 3, "likelihood": 3},
                {"description": "Weak SSL/TLS configuration or ciphers used by {name} leading to information disclosure", "stride_category": "Information Disclosure", "impact": 3, "likelihood": 3},
            ]
        },
        {
            "conditions": {"type": "switch"},
            "threats": [
                {"description": "VLAN hopping attack to gain access to unauthorized network segments through {name} for privilege escalation", "stride_category": "Elevation of Privilege", "impact": 4, "likelihood": 4},
                {"description": "MAC flooding attack on {name} to force it into a hub-like state, enabling network sniffing and information disclosure", "stride_category": "Information Disclosure", "impact": 3, "likelihood": 3},
            ]
        },
        {
            "conditions": {"is_public": True},
            "threats": [
                {"description": "Denial of Service (DoS) attack targeting the public-facing asset {name} causing service unavailability", "stride_category": "Denial of Service", "impact": 5, "likelihood": 4},
            ]
        },
        {
            "conditions": {"can_pivot": True},
            "threats": [
                {"description": "Lateral movement from {name} to other systems in the network for further compromise", "stride_category": "Elevation of Privilege", "impact": 4, "likelihood": 4},
            ]
        },
        {
            "conditions": {"has_management_interface": True},
            "threats": [
                {"description": "Compromise of the management interface of {name} leading to critical system control", "stride_category": "Elevation of Privilege", "impact": 5, "likelihood": 5},
            ]
        }
    ],
    "dataflows": [
        {
            "conditions": {"is_encrypted": False},
            "threats": [
                {"description": "Data interception on an unencrypted channel from {source.name} to {sink.name} (Man-in-the-Middle attack)", "stride_category": "Information Disclosure", "impact": 4, "likelihood": 4}
            ]
        },
        {
            "conditions": {"is_authenticated": False},
            "threats": [
                {"description": "Spoofing of data from {source.name} to {sink.name} due to lack of authentication, allowing unauthorized data injection", "stride_category": "Spoofing", "impact": 3, "likelihood": 3}
            ]
        },
        {
            "conditions": {"contains_sensitive_data": True, "is_encrypted": False},
            "threats": [
                {"description": "Sensitive data (PII) transmitted in cleartext from {source.name} to {sink.name}, leading to critical information disclosure", "stride_category": "Information Disclosure", "impact": 5, "likelihood": 5}
            ]
        },
        {
            "conditions": {"crosses_trust_boundary": True, "is_authenticated": False},
            "threats": [
                {"description": "Potential for spoofing attacks on data crossing trust boundaries from {source.name} to {sink.name} without proper authentication", "stride_category": "Spoofing", "impact": 4, "likelihood": 4}
            ]
        }
    ],
    "actors": [
        {
            "conditions": {}, # Apply to all actors
            "threats": [
                {"description": "Identity spoofing of the actor {name} via phishing or credential theft", "stride_category": "Spoofing", "impact": 3, "likelihood": 3},
                {"description": "Repudiation of critical actions performed by {name} due to insufficient logging or non-repudiation controls", "stride_category": "Repudiation", "impact": 3, "likelihood": 3},
            ]
        }
    ]
}
