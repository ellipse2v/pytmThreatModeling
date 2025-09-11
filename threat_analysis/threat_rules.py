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

# -----------------------------------------------------------------------------
# Threat Rule Structure
# -----------------------------------------------------------------------------
# Each threat rule is a dictionary with the following keys:
#
# - "description": A string describing the threat.
#   - It can contain placeholders like {name}, {source.name}, {sink.name}
#     that will be formatted with the component's properties.
#
# - "stride_category": The STRIDE category of the threat.
#   - Must be one of: "Spoofing", "Tampering", "Repudiation",
#     "Information Disclosure", "Denial of Service", "Elevation of Privilege".
#
# - "impact": An integer from 1 to 5 representing the potential impact of the
#   threat.
#
# - "likelihood": An integer from 1 to 5 representing the likelihood of the
#   threat occurring.
#
# Example:
# {
#   "description": "SQL injection on {name}",
#   "stride_category": "Tampering",
#   "impact": 5,
#   "likelihood": 5
# }
# -----------------------------------------------------------------------------

THREAT_RULES = {
    "servers": [
        {
            "conditions": {},
            "threats": [
                {
                    "description": "Unpatched OS or software vulnerabilities on {name} leading to system compromise",
                    "stride_category": "Tampering",
                    "impact": 4,
                    "likelihood": 4
                },
                {
                    "description": "Insecure security configuration or hardening on {name} leading to information exposure",
                    "stride_category": "Information Disclosure",
                    "impact": 3,
                    "likelihood": 3,
                    "capec_ids": ["CAPEC-511"]
                },
                {
                    "description": "Unauthorized privilege escalation on {name} due to misconfiguration or vulnerability",
                    "stride_category": "Elevation of Privilege",
                    "impact": 5,
                    "likelihood": 4,
                    "capec_ids": ["CAPEC-180", "CAPEC-233"]
                },
                {
                    "description": "Lack of monitoring or logging on {name}, preventing detection of malicious activities and enabling repudiation",
                    "stride_category": "Repudiation",
                    "impact": 3,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"type": "database"},
            "threats": [
                {
                    "description": "Unauthorized access to sensitive data stored in {name} leading to data breach",
                    "stride_category": "Information Disclosure",
                    "impact": 5,
                    "likelihood": 4
                },
                {
                    "description": "Data exfiltration or leakage from {name} to external systems",
                    "stride_category": "Information Disclosure",
                    "impact": 5,
                    "likelihood": 4
                },
                {
                    "description": "Data corruption or tampering in {name} via unauthorized write access or SQL injection",
                    "stride_category": "Tampering",
                    "impact": 5,
                    "likelihood": 4
                },
                {
                    "description": "Denial of Service against {name} through resource-intensive queries or excessive connections",
                    "stride_category": "Denial of Service",
                    "impact": 4,
                    "likelihood": 3
                }
            ]
        },
        {
            "conditions": {"type": "app-server"},
            "threats": [
                {
                    "description": "SQL or NoSQL injection vulnerability in the application on {name} allowing command execution or data manipulation",
                    "stride_category": "Tampering",
                    "impact": 5,
                    "likelihood": 5
                },
                {
                    "description": "Cross-Site Scripting (XSS) vulnerability allowing script injection on {name} affecting user sessions",
                    "stride_category": "Tampering",
                    "impact": 3,
                    "likelihood": 4
                },
                {
                    "description": "Insecure Direct Object References (IDOR) leading to unauthorized data access on {name} by bypassing authorization",
                    "stride_category": "Information Disclosure",
                    "impact": 4,
                    "likelihood": 4
                },
                {
                    "description": "Server-Side Request Forgery (SSRF) on {name} allowing an attacker to induce the server to make requests to an arbitrary domain.",
                    "stride_category": "Spoofing",
                    "impact": 4,
                    "likelihood": 3
                }
            ]
        },
        {
            "conditions": {"type": "firewall"},
            "threats": [
                {
                    "description": "Firewall rule misconfiguration allowing unintended traffic to bypass {name} and reach internal networks",
                    "stride_category": "Spoofing",
                    "impact": 4,
                    "likelihood": 4
                },
                {
                    "description": "Denial of Service (DoS) attack targeting {name} to exhaust its resources and disrupt network connectivity",
                    "stride_category": "Denial of Service",
                    "impact": 5,
                    "likelihood": 4
                },
                {
                    "description": "Vulnerability in the management interface of {name} leading to critical privilege escalation",
                    "stride_category": "Elevation of Privilege",
                    "impact": 5,
                    "likelihood": 5
                },
                {
                    "description": "Firewall bypass through fragmented packets or other evasion techniques against {name}",
                    "stride_category": "Spoofing",
                    "impact": 4,
                    "likelihood": 4
                },
                {
                    "description": "Privilege escalation on {name} by accessing functionality not properly constrained by ACLs",
                    "stride_category": "Elevation of Privilege",
                    "impact": 4,
                    "likelihood": 4,
                    "capec_ids": ["CAPEC-1"]
                }
            ]
        },
        {
            "conditions": {"type": "load-balancer"},
            "threats": [
                {
                    "description": "Session hijacking or fixation attack against the {name} leading to unauthorized access",
                    "stride_category": "Spoofing",
                    "impact": 3,
                    "likelihood": 3
                },
                {
                    "description": "Weak SSL/TLS configuration or ciphers used by {name} leading to information disclosure",
                    "stride_category": "Information Disclosure",
                    "impact": 3,
                    "likelihood": 3
                }
            ]
        },
        {
            "conditions": {"type": "switch"},
            "threats": [
                {
                    "description": "VLAN hopping attack to gain access to unauthorized network segments through {name} for privilege escalation",
                    "stride_category": "Elevation of Privilege",
                    "impact": 4,
                    "likelihood": 4
                },
                {
                    "description": "MAC flooding attack on {name} to force it into a hub-like state, enabling network sniffing and information disclosure",
                    "stride_category": "Information Disclosure",
                    "impact": 3,
                    "likelihood": 3
                }
            ]
        },
        {
            "conditions": {"is_public": True},
            "threats": [
                {
                    "description": "Denial of Service (DoS) attack targeting the public-facing asset {name} causing service unavailability",
                    "stride_category": "Denial of Service",
                    "impact": 5,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"can_pivot": True},
            "threats": [
                {
                    "description": "Lateral movement from {name} to other systems in the network for further compromise",
                    "stride_category": "Elevation of Privilege",
                    "impact": 4,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"has_management_interface": True},
            "threats": [
                {
                    "description": "Compromise of the management interface of {name} leading to critical system control",
                    "stride_category": "Elevation of Privilege",
                    "impact": 5,
                    "likelihood": 5
                },
                {
                    "description": "Authentication bypass on the management interface of {name}",
                    "stride_category": "Elevation of Privilege",
                    "impact": 5,
                    "likelihood": 4,
                    "capec_ids": ["CAPEC-115"]
                }
            ]
        },
        {
            "conditions": {"type": "api-gateway"},
            "threats": [
                {
                    "description": "Improper rate limiting on API Gateway {name}, leading to Denial of Service.",
                    "stride_category": "Denial of Service",
                    "impact": 4,
                    "likelihood": 4
                },
                {
                    "description": "Weak or missing authentication on routes managed by API Gateway {name}, allowing unauthorized access to backend services.",
                    "stride_category": "Spoofing",
                    "impact": 5,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"type": "docker-registry"},
            "threats": [
                {
                    "description": "Use of vulnerable or untrusted base images in Docker Registry {name}, leading to supply chain compromise.",
                    "stride_category": "Tampering",
                    "impact": 5,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"type": "s3-bucket", "is_public": True},
            "threats": [
                {
                    "description": "Critical Information Disclosure: S3 Bucket {name} is publicly accessible.",
                    "stride_category": "Information Disclosure",
                    "impact": 5,
                    "likelihood": 5
                }
            ]
        },
        {
            "conditions": {"type": "domain-controller"},
            "threats": [
                {
                    "description": "Kerberoasting attack against Domain Controller {name} to extract service account credentials.",
                    "stride_category": "Credential Access",
                    "impact": 5,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"type": "bastion"},
            "threats": [
                {
                    "description": "Lateral movement from bastion host {name} to other systems in the network for further compromise.",
                    "stride_category": "Elevation of Privilege",
                    "impact": 4,
                    "likelihood": 4,
                    "capec_ids": ["CAPEC-555", "CAPEC-645"]
                }
            ]
        },
        {
            "conditions": {"type": "management-server"},
            "threats": [
                {
                    "description": "Lateral movement from management server {name} to other systems in the network for further compromise.",
                    "stride_category": "Elevation of Privilege",
                    "impact": 4,
                    "likelihood": 4
                }
            ]
        }
    ],
    "dataflows": [
        {
            "conditions": {"is_encrypted": False},
            "threats": [
                {
                    "description": "Data interception on an unencrypted channel from {source.name} to {sink.name} (Man-in-the-Middle attack)",
                    "stride_category": "Information Disclosure",
                    "impact": 4,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"is_authenticated": False},
            "threats": [
                {
                    "description": "Spoofing of data from {source.name} to {sink.name} due to lack of authentication",
                    "stride_category": "Spoofing",
                    "impact": 3,
                    "likelihood": 3
                }
            ]
        },
        {
            "conditions": {"contains_sensitive_data": True, "is_encrypted": False},
            "threats": [
                {
                    "description": "Sensitive data (PII) transmitted in cleartext from {source.name} to {sink.name}, leading to critical information disclosure",
                    "stride_category": "Information Disclosure",
                    "impact": 5,
                    "likelihood": 5
                }
            ]
        },
        {
            "conditions": {"crosses_trust_boundary": True, "is_authenticated": False},
            "threats": [
                {
                    "description": "Potential for spoofing attacks on data crossing trust boundaries from {source.name} to {sink.name} without proper authentication",
                    "stride_category": "Spoofing",
                    "impact": 4,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"source_boundary": "DMZ", "sink_boundary": "Internal"},
            "threats": [
                {
                    "description": "Insufficient traffic filtering between DMZ and internal network, allowing attacks from {source.name} to {sink.name}",
                    "stride_category": "Elevation of Privilege",
                    "impact": 4,
                    "likelihood": 3
                }
            ]
        },
        {
            "conditions": {"source_boundary": None, "sink_boundary": "DMZ"},
            "threats": [
                {
                    "description": "Insufficient inspection of inbound traffic from the internet to the DMZ, from {source.name} to {sink.name}",
                    "stride_category": "Tampering",
                    "impact": 4,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"data.type": "credentials", "is_encrypted": False},
            "threats": [
                {
                    "description": "Critical Spoofing/Info Disclosure: Credentials for {sink.name} are sent unencrypted from {source.name}.",
                    "stride_category": "Information Disclosure",
                    "impact": 5,
                    "likelihood": 5
                }
            ]
        },
        {
            "conditions": {"sink.type": "database", "is_authenticated": False},
            "threats": [
                {
                    "description": "Critical Elevation of Privilege: Unauthenticated data flow from {source.name} is allowed to interact with a critical database {sink.name}.",
                    "stride_category": "Elevation of Privilege",
                    "impact": 5,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"protocol": "FTP"},
            "threats": [
                {
                    "description": "Information Disclosure: Insecure FTP protocol between {source.name} and {sink.name} exposes credentials.",
                    "stride_category": "Information Disclosure",
                    "impact": 4,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"source.type": "git-repo", "data.type": "secret"},
            "threats": [
                {
                    "description": "Critical Information Disclosure: Secrets are being transferred from Git Repository {source.name}, likely indicating they are committed in source code.",
                    "stride_category": "Information Disclosure",
                    "impact": 5,
                    "likelihood": 5
                }
            ]
        },
        {
            "conditions": {"sink.type": "docker-registry", "is_authenticated": False},
            "threats": [
                {
                    "description": "Tampering: Unauthenticated access to Docker Registry {sink.name} allows for potential image poisoning (Supply Chain Attack).",
                    "stride_category": "Tampering",
                    "impact": 5,
                    "likelihood": 4
                }
            ]
        },
        {
            "conditions": {"source.type": "iot-device", "is_authenticated": False},
            "threats": [
                {
                    "description": "Spoofing: IoT device {source.name} communicates with {sink.name} without authentication, allowing device impersonation.",
                    "stride_category": "Spoofing",
                    "impact": 4,
                    "likelihood": 5
                }
            ]
        },
        {
            "conditions": {"source.type": "app-service", "sink.type": "app-service", "is_authenticated": False, "source.boundary.isTrusted": True, "sink.boundary.isTrusted": True},
            "threats": [
                {
                    "description": "Elevation of Privilege: Lack of authentication in East-West traffic between microservices ({source.name} to {sink.name}) inside a trusted zone breaks Zero Trust principles.",
                    "stride_category": "Elevation of Privilege",
                    "impact": 4,
                    "likelihood": 4
                }
            ]
        }
    ],
    "actors": [
        {
            "conditions": {},
            "threats": [
                {
                    "description": "Identity spoofing of the actor {name} via phishing or credential theft",
                    "stride_category": "Spoofing",
                    "impact": 3,
                    "likelihood": 3
                },
                {
                    "description": "Repudiation of critical actions performed by {name} due to insufficient logging or non-repudiation controls",
                    "stride_category": "Repudiation",
                    "impact": 3,
                    "likelihood": 3
                },
                {
                    "description": "Privilege abuse by actor {name} to gain unauthorized access or perform unauthorized actions",
                    "stride_category": "Elevation of Privilege",
                    "impact": 4,
                    "likelihood": 3,
                    "capec_ids": ["CAPEC-122"]
                }
            ]
        }
    ]
}