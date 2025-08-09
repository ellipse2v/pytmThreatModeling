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
# - "mitigations": A list of strings, where each string is a suggested
#   mitigation for the threat.
#
# Example:
# {
#   "description": "SQL injection on {name}",
#   "stride_category": "Tampering",
#   "impact": 5,
#   "likelihood": 5,
#   "mitigations": [
#     "Use parameterized queries or prepared statements.",
#     "Implement input validation and sanitization.",
#     "Apply the principle of least privilege for database access."
#   ]
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
                    "likelihood": 4,
                    "mitigations": [
                        "Implement a robust patch management process.",
                        "Regularly scan for vulnerabilities using automated tools.",
                        "Apply security patches in a timely manner."
                    ]
                },
                {
                    "description": "Insecure security configuration or hardening on {name} leading to information exposure",
                    "stride_category": "Information Disclosure",
                    "impact": 3,
                    "likelihood": 3,
                    "mitigations": [
                        "Follow security hardening guides (e.g., CIS Benchmarks).",
                        "Disable unnecessary services and ports.",
                        "Regularly audit security configurations."
                    ]
                },
                {
                    "description": "Unauthorized privilege escalation on {name} due to misconfiguration or vulnerability",
                    "stride_category": "Elevation of Privilege",
                    "impact": 5,
                    "likelihood": 4,
                    "mitigations": [
                        "Apply the principle of least privilege.",
                        "Regularly review user and service account permissions.",
                        "Keep systems patched to prevent vulnerability exploitation."
                    ]
                },
                {
                    "description": "Lack of monitoring or logging on {name}, preventing detection of malicious activities and enabling repudiation",
                    "stride_category": "Repudiation",
                    "impact": 3,
                    "likelihood": 4,
                    "mitigations": [
                        "Implement centralized logging for security events.",
                        "Configure alerts for suspicious activities.",
                        "Protect logs from tampering."
                    ]
                },
            ]
        },
        {
            "conditions": {"type": "database"},
            "threats": [
                {
                    "description": "Unauthorized access to sensitive data stored in {name} leading to data breach",
                    "stride_category": "Information Disclosure",
                    "impact": 5,
                    "likelihood": 4,
                    "mitigations": [
                        "Enforce strong access controls and authentication.",
                        "Encrypt sensitive data at rest.",
                        "Monitor database access and audit logs."
                    ]
                },
                {
                    "description": "Data exfiltration or leakage from {name} to external systems",
                    "stride_category": "Information Disclosure",
                    "impact": 5,
                    "likelihood": 4,
                    "mitigations": [
                        "Implement Data Loss Prevention (DLP) solutions.",
                        "Restrict outbound traffic from the database server.",
                        "Monitor for large or unusual data transfers."
                    ]
                },
                {
                    "description": "Data corruption or tampering in {name} via unauthorized write access or SQL injection",
                    "stride_category": "Tampering",
                    "impact": 5,
                    "likelihood": 4,
                    "mitigations": [
                        "Use parameterized queries or prepared statements.",
                        "Implement strict input validation.",
                        "Enforce the principle of least privilege for database accounts."
                    ]
                },
                {
                    "description": "Denial of Service against {name} through resource-intensive queries or excessive connections",
                    "stride_category": "Denial of Service",
                    "impact": 4,
                    "likelihood": 3,
                    "mitigations": [
                        "Implement query throttling and connection pooling.",
                        "Optimize database queries and indexes.",
                        "Use a firewall to limit access to the database."
                    ]
                },
            ]
        },
        {
            "conditions": {"type": "app-server"},
            "threats": [
                {
                    "description": "SQL or NoSQL injection vulnerability in the application on {name} allowing command execution or data manipulation",
                    "stride_category": "Tampering",
                    "impact": 5,
                    "likelihood": 5,
                    "mitigations": [
                        "Use parameterized queries or Object-Relational Mapping (ORM).",
                        "Validate and sanitize all user-supplied input.",
                        "Follow OWASP ASVS guidelines for input validation.",
                        "Implement the principle of least privilege for database accounts."
                    ]
                },
                {
                    "description": "Cross-Site Scripting (XSS) vulnerability allowing script injection on {name} affecting user sessions",
                    "stride_category": "Tampering",
                    "impact": 3,
                    "likelihood": 4,
                    "mitigations": [
                        "Implement output encoding for all user-supplied data.",
                        "Use a Content Security Policy (CSP).",
                        "Use modern web frameworks with built-in XSS protection.",
                        "Set the HttpOnly flag on session cookies."
                    ]
                },
                {
                    "description": "Insecure Direct Object References (IDOR) leading to unauthorized data access on {name} by bypassing authorization",
                    "stride_category": "Information Disclosure",
                    "impact": 4,
                    "likelihood": 4,
                    "mitigations": [
                        "Implement access control checks for every request.",
                        "Use indirect references (e.g., session-based) instead of direct object references.",
                        "Verify that the user is authorized to access the requested resource."
                    ]
                },
                {
                    "description": "Server-Side Request Forgery (SSRF) on {name} allowing an attacker to induce the server to make requests to an arbitrary domain.",
                    "stride_category": "Spoofing",
                    "impact": 4,
                    "likelihood": 3,
                    "mitigations": [
                        "Validate and sanitize all URLs provided by users.",
                        "Use a whitelist of allowed domains and protocols.",
                        "Disable unused URL schemas."
                    ]
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
                    "likelihood": 4,
                    "mitigations": [
                        "Regularly audit firewall rules.",
                        "Implement a strict 'deny-all' default policy.",
                        "Use automated tools to check for rule conflicts and anomalies."
                    ]
                },
                {
                    "description": "Denial of Service (DoS) attack targeting {name} to exhaust its resources and disrupt network connectivity",
                    "stride_category": "Denial of Service",
                    "impact": 5,
                    "likelihood": 4,
                    "mitigations": [
                        "Enable DoS protection features on the firewall.",
                        "Use a cloud-based DoS mitigation service.",
                        "Implement rate limiting for incoming traffic."
                    ]
                },
                {
                    "description": "Vulnerability in the management interface of {name} leading to critical privilege escalation",
                    "stride_category": "Elevation of Privilege",
                    "impact": 5,
                    "likelihood": 5,
                    "mitigations": [
                        "Isolate the management interface from the production network.",
                        "Enforce multi-factor authentication for management access.",
                        "Keep the firewall firmware up to date."
                    ]
                },
                {
                    "description": "Firewall bypass through fragmented packets or other evasion techniques against {name}",
                    "stride_category": "Spoofing",
                    "impact": 4,
                    "likelihood": 4,
                    "mitigations": [
                        "Use a stateful firewall that can reassemble packets.",
                        "Enable Intrusion Prevention System (IPS) features.",
                        "Keep the firewall's threat signatures up to date."
                    ]
                },
            ]
        },
        {
            "conditions": {"type": "load-balancer"},
            "threats": [
                {
                    "description": "Session hijacking or fixation attack against the {name} leading to unauthorized access",
                    "stride_category": "Spoofing",
                    "impact": 3,
                    "likelihood": 3,
                    "mitigations": [
                        "Regenerate session IDs after login.",
                        "Use secure, http-only cookies.",
                        "Implement session timeouts."
                    ]
                },
                {
                    "description": "Weak SSL/TLS configuration or ciphers used by {name} leading to information disclosure",
                    "stride_category": "Information Disclosure",
                    "impact": 3,
                    "likelihood": 3,
                    "mitigations": [
                        "Use strong, up-to-date TLS protocols and cipher suites.",
                        "Disable support for legacy protocols like SSLv3 and TLS 1.0/1.1.",
                        "Regularly scan the configuration with tools like SSL Labs."
                    ]
                },
            ]
        },
        {
            "conditions": {"type": "switch"},
            "threats": [
                {
                    "description": "VLAN hopping attack to gain access to unauthorized network segments through {name} for privilege escalation",
                    "stride_category": "Elevation of Privilege",
                    "impact": 4,
                    "likelihood": 4,
                    "mitigations": [
                        "Disable Dynamic Trunking Protocol (DTP) on user-facing ports.",
                        "Manually configure trunk ports.",
                        "Use a dedicated VLAN for management traffic."
                    ]
                },
                {
                    "description": "MAC flooding attack on {name} to force it into a hub-like state, enabling network sniffing and information disclosure",
                    "stride_category": "Information Disclosure",
                    "impact": 3,
                    "likelihood": 3,
                    "mitigations": [
                        "Enable port security to limit the number of MAC addresses per port.",
                        "Use a network monitoring tool to detect MAC flooding attacks.",
                        "Implement 802.1X for port-based access control."
                    ]
                },
            ]
        },
        {
            "conditions": {"is_public": True},
            "threats": [
                {
                    "description": "Denial of Service (DoS) attack targeting the public-facing asset {name} causing service unavailability",
                    "stride_category": "Denial of Service",
                    "impact": 5,
                    "likelihood": 4,
                    "mitigations": [
                        "Use a Content Delivery Network (CDN) with DoS protection.",
                        "Implement rate limiting and traffic shaping.",
                        "Have a DoS response plan in place."
                    ]
                },
            ]
        },
        {
            "conditions": {"can_pivot": True},
            "threats": [
                {
                    "description": "Lateral movement from {name} to other systems in the network for further compromise",
                    "stride_category": "Elevation of Privilege",
                    "impact": 4,
                    "likelihood": 4,
                    "mitigations": [
                        "Implement network segmentation to limit lateral movement.",
                        "Use a host-based firewall to restrict outbound connections.",
                        "Monitor for unusual internal network traffic."
                    ]
                },
            ]
        },
        {
            "conditions": {"has_management_interface": True},
            "threats": [
                {
                    "description": "Compromise of the management interface of {name} leading to critical system control",
                    "stride_category": "Elevation of Privilege",
                    "impact": 5,
                    "likelihood": 5,
                    "mitigations": [
                        "Isolate the management interface on a separate, secure network.",
                        "Enforce strong authentication and multi-factor authentication (MFA).",
                        "Restrict access to the management interface to authorized personnel."
                    ]
                },
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
                    "likelihood": 4,
                    "mitigations": [
                        "Encrypt all data in transit using strong TLS configurations.",
                        "Use a Virtual Private Network (VPN) for untrusted networks.",
                        "Implement certificate pinning to prevent MITM attacks."
                    ]
                }
            ]
        },
        {
            "conditions": {"is_authenticated": False},
            "threats": [
                {
                    "description": "Spoofing of data from {source.name} to {sink.name} due to lack of authentication, allowing unauthorized data injection",
                    "stride_category": "Spoofing",
                    "impact": 3,
                    "likelihood": 3,
                    "mitigations": [
                        "Implement strong authentication for all dataflows.",
                        "Use mutual TLS (mTLS) for service-to-service communication.",
                        "Sign data with a digital signature to ensure integrity and authenticity."
                    ]
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
                    "likelihood": 5,
                    "mitigations": [
                        "Encrypt all sensitive data in transit using TLS.",
                        "Ensure that data is also encrypted at rest.",
                        "Implement Data Loss Prevention (DLP) to detect and block the transmission of sensitive data."
                    ]
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
                    "likelihood": 4,
                    "mitigations": [
                        "Authenticate all dataflows that cross trust boundaries.",
                        "Use a gateway or proxy to enforce authentication.",
                        "Apply a zero-trust security model."
                    ]
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
                    "likelihood": 3,
                    "mitigations": [
                        "Implement strict firewall rules to only allow necessary traffic from DMZ to internal network.",
                        "Use a proxy or gateway for all communication between DMZ and internal network.",
                        "Regularly audit firewall and proxy rules."
                    ]
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
                    "likelihood": 4,
                    "mitigations": [
                        "Use a Web Application Firewall (WAF) to inspect all inbound web traffic.",
                        "Implement an Intrusion Prevention System (IPS) to detect and block malicious traffic.",
                        "Keep WAF and IPS signatures up to date."
                    ]
                }
            ]
        }
    ],
    "actors": [
        {
            "conditions": {}, # Apply to all actors
            "threats": [
                {
                    "description": "Identity spoofing of the actor {name} via phishing or credential theft",
                    "stride_category": "Spoofing",
                    "impact": 3,
                    "likelihood": 3,
                    "mitigations": [
                        "Provide security awareness training to users.",
                        "Implement multi-factor authentication (MFA).",
                        "Use anti-phishing solutions."
                    ]
                },
                {
                    "description": "Repudiation of critical actions performed by {name} due to insufficient logging or non-repudiation controls",
                    "stride_category": "Repudiation",
                    "impact": 3,
                    "likelihood": 3,
                    "mitigations": [
                        "Implement comprehensive logging for all actions.",
                        "Use digital signatures to ensure non-repudiation.",
                        "Protect logs from tampering and unauthorized access."
                    ]
                },
            ]
        }
    ]
}
