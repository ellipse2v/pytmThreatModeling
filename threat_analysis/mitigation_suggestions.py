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
Mitigation Suggestions Module

This module provides mitigation suggestions for MITRE ATT&CK techniques based on
well-known security frameworks like OWASP, NIST, and CIS.

The `MITIGATION_MAP` dictionary maps MITRE ATT&CK technique IDs to a list of
mitigation suggestions. Each suggestion is a dictionary with the following
keys:
- "name": A descriptive name for the mitigation.
- "description": A brief explanation of the mitigation.
- "framework": The source framework and control ID (e.g., "OWASP ASVS V14.2.2").
- "url": A link to the framework's documentation for verification.

To add new mitigation suggestions:
1. Identify the MITRE ATT&CK technique ID (e.g., "T1190").
2. Find relevant mitigations from OWASP, NIST, or CIS.
3. Add a new entry to the `MITIGATION_MAP` dictionary for the technique, or
   append to an existing entry.
4. Ensure all fields ("name", "description", "framework", "url") are filled out.
"""

MITIGATION_MAP = {
    # T1190: Exploit Public-Facing Application (e.g., SQL Injection)
    "T1190": [
        {
            "name": "OWASP ASVS V5.3.3: Parameterized Queries",
            "description": "Use parameterized queries (also known as prepared statements) to prevent SQL injection vulnerabilities.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "OWASP ASVS V5.3.4: Input Validation",
            "description": "Validate that all user input is well-formed and matches the expected data type and format.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 SI-10: Information Input Validation",
            "description": "Ensure that inputs are validated to detect and filter malicious content at the application and network level.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "NIST SP 800-53 SA-11: Developer Testing and Evaluation",
            "description": "Require developers to perform static and dynamic code analysis to identify vulnerabilities like injection.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 16.10: Web Application Firewalls",
            "description": "Deploy and configure a Web Application Firewall (WAF) to inspect and filter traffic to public-facing web applications.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/application-software-security"
        }
    ],
    # T1059: Command and Scripting Interpreter (e.g., Command Injection)
    "T1059": [
        {
            "name": "OWASP ASVS V5.3.1: OS Command Injection Prevention",
            "description": "Avoid calling OS commands directly. If unavoidable, use structured APIs and ensure all user input is sanitized.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 CM-7: Least Privilege",
            "description": "Ensure that the application's execution context has the minimum level of privileges required, preventing broad system access from a single vulnerability.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 2.5: Limit Administrative Privileges",
            "description": "Limit the use of administrative privileges to dedicated administrator accounts to reduce the impact of command injection.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/inventory-and-control-of-software-assets"
        }
    ],
    # T1059.007: JavaScript (e.g., XSS)
    "T1059.007": [
        {
            "name": "OWASP ASVS V5.2.1: Content Security Policy (CSP)",
            "description": "Implement a strong, restrictive Content Security Policy (CSP) to mitigate the risk and impact of XSS attacks.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "OWASP ASVS V5.2.2: Contextual Output Encoding",
            "description": "Apply contextual output encoding to all user-supplied data when it is rendered in HTML, JavaScript, CSS, or other contexts.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 SI-10 (Enhancement 5): Restrict User-Supplied Content",
            "description": "Restrict the use of user-supplied content and scripts, and validate or sanitize all such input before use.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 16.9: Use of Secure Libraries",
            "description": "Use modern, secure libraries and frameworks (e.g., React, Angular) that have built-in XSS protection mechanisms.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/application-software-security"
        }
    ],
    # T1557: Adversary-in-the-Middle (e.g., weak TLS)
    "T1557": [
        {
            "name": "OWASP ASVS V9.1.1: Strong TLS Configuration",
            "description": "Use strong, validated TLS protocols (TLS 1.2, TLS 1.3) and ciphers for all network communications.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 SC-13: Cryptographic Protection",
            "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of information during transmission.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 9.1: Ensure Only Secure Ports, Protocols, and Services Are Running",
            "description": "Block or disable all ports and services that are not essential for business purposes, and ensure that all used protocols are secure.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/network-monitoring-and-defense"
        }
    ],
    # T1078: Valid Accounts (e.g., weak passwords)
    "T1078": [
        {
            "name": "OWASP ASVS V2.1.1: Password Strength Requirements",
            "description": "Enforce strong password policies, including length, complexity, and resistance to common passwords.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 IA-5: Authenticator Management",
            "description": "Manage authenticators by defining strong verification mechanisms and protecting them accordingly.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "NIST SP 800-53 IA-2: Identification and Authentication (Multi-Factor)",
            "description": "Implement multi-factor authentication for access to privileged and non-privileged accounts.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 5.3: Disable Dormant Accounts",
            "description": "Automatically disable accounts after a defined period of inactivity.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/account-management"
        }
    ],
    # T1110: Brute Force
    "T1110": [
        {
            "name": "OWASP ASVS V2.2.1: Account Lockout",
            "description": "Implement account lockout mechanisms after a configured number of failed login attempts to slow down brute-force attacks.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "OWASP ASVS V2.2.2: CAPTCHA",
            "description": "Use CAPTCHA or other automated threat detection mechanisms to prevent credential stuffing and brute-force attacks.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 AC-7: Unsuccessful Logon Attempts",
            "description": "Enforce a limit of consecutive unsuccessful logon attempts by a user during a specified time period.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 4.4: Implement and Manage a Firewall on Servers",
            "description": "Implement a host-based firewall or port-filtering tool on servers to limit connections, which can help mitigate brute-force attempts.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software"
        }
    ],
    # T1068: Exploitation for Privilege Escalation
    "T1068": [
        {
            "name": "OWASP ASVS V1.4.1: Access Control Design",
            "description": "Ensure a robust and well-designed access control mechanism is in place to prevent vertical and horizontal privilege escalation.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 SI-2: Flaw Remediation",
            "description": "Identify, report, and correct system flaws and vulnerabilities in a timely manner through a robust patch management process.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 7: Continuous Vulnerability Management",
            "description": "Develop a plan to continuously assess and track vulnerabilities to remediate them in a timely manner.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/continuous-vulnerability-management"
        }
    ],
    # T1499: Endpoint Denial of Service
    "T1499": [
        {
            "name": "OWASP ASVS V13.2.1: Resource Limiting",
            "description": "Implement rate limiting and resource controls on application endpoints to prevent resource exhaustion from a single user or source.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 CP-7: Contingency Planning",
            "description": "Develop and implement a contingency plan for system availability, including measures to mitigate DoS attacks.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 12: Network Infrastructure Management",
            "description": "Implement network infrastructure defenses, such as traffic filtering and rate limiting, to mitigate DoS attacks at the network layer.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/network-infrastructure-management"
        }
    ]
}


def get_mitigation_suggestions(technique_ids: list[str]) -> list[dict]:
    """
    Retrieves a list of mitigation suggestions for the given MITRE ATT&CK
    technique IDs.

    Args:
        technique_ids: A list of MITRE ATT&CK technique IDs.

    Returns:
        A list of mitigation suggestion dictionaries. Each dictionary contains
        the name, description, framework, and URL of the mitigation.
    """
    suggestions = []
    for tech_id in technique_ids:
        if tech_id in MITIGATION_MAP:
            suggestions.extend(MITIGATION_MAP[tech_id])
    return suggestions
