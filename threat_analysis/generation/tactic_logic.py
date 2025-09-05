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
Defines the logical progression of MITRE ATT&CK tactics for attack path generation.

This module provides a structured representation of a typical attack lifecycle,
grouping tactics into sequential phases. This sequence is used by the
attack_flow_generator to build plausible chains of attack techniques.

The progression is defined as a list of phases, where each phase contains
one or more tactics that are likely to occur at that stage of an attack.
"""

# The logical sequence of MITRE ATT&CK tactics.
# Each inner list represents a phase of an attack, and techniques from a given
# phase can be considered prerequisites for techniques in the subsequent phase.
TACTIC_PROGRESSION = [
    ["initial-access"],
    ["execution"],
    ["persistence", "privilege-escalation", "defense-evasion"],
    ["credential-access", "discovery"],
    ["lateral-movement"],
    ["collection"],
    ["command-and-control"],
    ["exfiltration"],
    ["impact"]
]

# A mapping from MITRE ATT&CK tactic names (as used in the framework)
# to their official short names (slugs) and official Tactic IDs.
TACTIC_INFO = {
    "Initial Access": {"slug": "initial-access", "id": "TA0001"},
    "Execution": {"slug": "execution", "id": "TA0002"},
    "Persistence": {"slug": "persistence", "id": "TA0003"},
    "Privilege Escalation": {"slug": "privilege-escalation", "id": "TA0004"},
    "Defense Evasion": {"slug": "defense-evasion", "id": "TA0005"},
    "Credential Access": {"slug": "credential-access", "id": "TA0006"},
    "Discovery": {"slug": "discovery", "id": "TA0007"},
    "Lateral Movement": {"slug": "lateral-movement", "id": "TA0008"},
    "Collection": {"slug": "collection", "id": "TA0009"},
    "Command and Control": {"slug": "command-and-control", "id": "TA0011"},
    "Exfiltration": {"slug": "exfiltration", "id": "TA0010"},
    "Impact": {"slug": "impact", "id": "TA0040"},
}