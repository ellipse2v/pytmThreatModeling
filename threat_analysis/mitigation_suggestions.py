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
    "T1190": [
        {
            "name": "OWASP ASVS V14.2.2: Input Validation",
            "description": (
                "Validate all incoming data to prevent injection attacks and "
                "ensure it is safe to process."
            ),
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        {
            "name": "NIST SP 800-53 AC-3: Access Enforcement",
            "description": (
                "Enforce approved authorizations for logical access to "
                "information and system resources in accordance with "
                "applicable access control policies."
            ),
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        },
        {
            "name": "CIS Control 18: Application Software Security",
            "description": (
                "Manage the security life cycle of all in-house developed, "
                "hosted, or acquired software to prevent, detect, and "
                "correct security weaknesses."
            ),
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/application-software-security"
        }
    ],
    "T1566": [
        {
            "name": "CIS Control 14: Security Awareness and Skills Training",
            "description": (
                "Establish and maintain a security awareness program to "
                "influence behavior among the workforce to be security "
                "conscious and properly skilled."
            ),
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/security-awareness-and-skills-training"
        },
        {
            "name": "NIST SP 800-53 AT-2: Security Awareness Training",
            "description": (
                "Provide basic security awareness training to all system "
                "users before authorizing access to the system, and "
                "periodically thereafter."
            ),
            "framework": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        }
    ],
    "T1199": [
        {
            "name": "CIS Control 6: Access Control Management",
            "description": "Use processes and tools to create, assign, manage, and revoke access credentials and privileges.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/access-control-management"
        }
    ],
    "T1485": [
        {
            "name": "CIS Control 11: Data Recovery",
            "description": "Establish and maintain a data recovery process and procedure to restore data.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/data-recovery"
        }
    ],
    "T1496": [
        {
            "name": "CIS Control 2: Inventory and Control of Software Assets",
            "description": "Actively manage (inventory, track, and correct) all software on the network.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/inventory-and-control-of-software-assets"
        }
    ],
    "T1547": [
        {
            "name": "CIS Control 4: Secure Configuration of Enterprise Assets and Software",
            "description": "Establish and maintain the secure configuration of enterprise assets and software.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software"
        }
    ],
    "T1204": [
        {
            "name": "CIS Control 14: Security Awareness and Skills Training",
            "description": "Establish and maintain a security awareness program.",
            "framework": "CIS",
            "url": "https://www.cisecurity.org/controls/security-awareness-and-skills-training"
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
