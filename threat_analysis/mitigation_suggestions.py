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
            "name": "OWASP ASVS V5.3.3: Output Encoding",
            "description": "Use output encoding to prevent injection attacks when rendering user-controllable data.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 SI-10: Information Input Validation",
            "description": "Ensure that inputs are validated to detect and filter malicious content.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 16: Application Software Security",
            "description": "Implement security best practices in the software development lifecycle.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/application-software-security"
        }
    ],
    # T1059: Command and Scripting Interpreter (e.g., Command Injection)
    "T1059": [
        {
            "name": "OWASP ASVS V5.3.1: Input Validation and Sanitization",
            "description": "Validate and sanitize all user-supplied input to prevent command injection.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 CM-7: Least Privilege",
            "description": "Ensure that the application runs with the minimum level of privileges required.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 7: Continuous Vulnerability Management",
            "description": "Regularly scan for and remediate vulnerabilities in applications and systems.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/continuous-vulnerability-management"
        }
    ],
    # T1059.007: JavaScript (e.g., XSS)
    "T1059.007": [
        {
            "name": "OWASP ASVS V5.2.1: Content Security Policy (CSP)",
            "description": "Implement a strong Content Security Policy to mitigate XSS attacks.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 SI-10: Information Input Validation",
            "description": "Validate and encode user input to prevent script injection.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 16.9: Use of Secure Libraries",
            "description": "Use modern, secure libraries and frameworks that have built-in XSS protection.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/application-software-security"
        }
    ],
    # T1557: Adversary-in-the-Middle (e.g., weak TLS)
    "T1557": [
        {
            "name": "OWASP ASVS V9.1.1: TLS Configuration",
            "description": "Use strong, validated TLS configurations for all network communications.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 SC-8: Transmission Confidentiality and Integrity",
            "description": "Protect the confidentiality and integrity of transmitted information.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 9: Network Monitoring and Defense",
            "description": "Monitor network traffic for signs of MITM attacks.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/network-monitoring-and-defense"
        }
    ],
    # T1078: Valid Accounts (e.g., weak passwords)
    "T1078": [
        {
            "name": "OWASP ASVS V2.1.1: Password Strength",
            "description": "Enforce strong password policies to prevent guessing.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 IA-5: Authenticator Management",
            "description": "Manage authenticators by defining strength mechanisms.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 5: Account Management",
            "description": "Use processes and tools to manage the lifecycle of user accounts.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/account-management"
        }
    ],
    # T1110: Brute Force
    "T1110": [
        {
            "name": "OWASP ASVS V2.2.1: Account Lockout",
            "description": "Implement account lockout mechanisms after a set number of failed login attempts.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 AC-7: Unsuccessful Logon Attempts",
            "description": "Enforce a limit on the number of unsuccessful logon attempts.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 4: Secure Configuration",
            "description": "Establish and maintain secure configurations for enterprise assets.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software"
        }
    ],
    # T1566: Phishing
    "T1566": [
        {
            "name": "CIS Control 14: Security Awareness and Skills Training",
            "description": "Establish and maintain a security awareness program to educate users about phishing.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/security-awareness-and-skills-training"
        },
        {
            "name": "NIST SP 800-53 AT-2: Security Awareness Training",
            "description": "Provide security awareness training to all system users.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        }
    ],
    # T1068: Exploitation for Privilege Escalation
    "T1068": [
        {
            "name": "OWASP ASVS V1.1.1: Secure Software Development Lifecycle",
            "description": "Integrate security throughout the software development lifecycle to prevent vulnerabilities.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 SI-2: Flaw Remediation",
            "description": "Identify, report, and correct system flaws in a timely manner.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 2: Inventory and Control of Software Assets",
            "description": "Maintain an inventory of all software and remove unauthorized software.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/inventory-and-control-of-software-assets"
        }
    ],
    # T1499: Endpoint Denial of Service
    "T1499": [
        {
            "name": "OWASP ASVS V13.2.1: Resource Limiting",
            "description": "Implement rate limiting and resource controls to prevent resource exhaustion.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 CP-7: Contingency Planning",
            "description": "Develop a contingency plan to ensure the availability of essential services.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 12: Network Infrastructure Management",
            "description": "Implement network infrastructure defenses to mitigate DoS attacks.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/network-infrastructure-management"
        }
    ],
    # T1040: Network Sniffing
    "T1040": [
        {
            "name": "OWASP ASVS V9.1.1: Encrypted Communications",
            "description": "Encrypt all network traffic to prevent sniffing and interception.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 SC-12: Cryptographic Key Establishment and Management",
            "description": "Manage cryptographic keys to ensure the security of encrypted communications.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 9: Network Monitoring",
            "description": "Monitor network traffic for anomalies and signs of sniffing.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/network-monitoring-and-defense"
        }
    ],
    # T1083: File and Directory Discovery (Path Traversal)
    "T1083": [
        {
            "name": "OWASP ASVS V5.3.8: Path Traversal Prevention",
            "description": "Prevent path traversal by validating file paths and using canonical paths.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 AC-3: Access Control Enforcement",
            "description": "Enforce access controls to prevent unauthorized access to files and directories.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 3: Data Protection",
            "description": "Implement data protection measures to secure sensitive files and directories.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/data-protection"
        }
    ],
    # T1213: Data from Information Repositories (IDOR)
    "T1213": [
        {
            "name": "OWASP ASVS V4.1.2: Authorization Checks",
            "description": "Verify that the user is authorized for the requested data in every request.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 AC-16: Security Attributes",
            "description": "Use security attributes to enforce access control decisions.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 6: Access Control Management",
            "description": "Manage access credentials and privileges to prevent unauthorized data access.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/access-control-management"
        }
    ],
    # T1552: Unsecured Credentials
    "T1552": [
        {
            "name": "OWASP ASVS V2.4.1: Credential Storage",
            "description": "Store credentials securely using strong, salted hashing algorithms.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 IA-5(1): Password-based Authentication",
            "description": "Protect passwords from unauthorized disclosure and modification.",
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 5.4: Restrict Administrator Privileges",
            "description": "Restrict and manage administrative privileges to limit exposure of powerful credentials.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/account-management"
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
