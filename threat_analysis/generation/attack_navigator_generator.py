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
MITRE ATT&CK Navigator Layer Generation Module
"""

import json
from typing import List, Dict, Any

class AttackNavigatorGenerator:
    """Generates a MITRE ATT&CK Navigator layer from threat analysis results."""

    def __init__(self, threat_model_name: str, all_detailed_threats: List[Dict[str, Any]]):
        self.threat_model_name = threat_model_name
        self.all_detailed_threats = all_detailed_threats
        self.layer_name = f"{threat_model_name} - Identified Techniques"
        self.layer_description = f"MITRE ATT&CK techniques identified in the '{self.threat_model_name}' threat model."

    def _get_unique_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Extracts unique techniques and aggregates their scores and comments."""
        techniques = {}
        for threat in self.all_detailed_threats:
            for tech in threat.get('mitre_techniques', []):
                tech_id = tech.get('id')
                if not tech_id:
                    continue

                severity_score = threat.get('severity', {}).get('score', 0)
                comment = f"- Threat: {str(threat['description'])}\n- Target: {str(threat['target'])}\n- Severity: {severity_score:.1f}/10.0"

                if tech_id not in techniques:
                    techniques[tech_id] = {
                        "techniqueID": tech_id,
                        "score": severity_score,
                        "comment": comment,
                        "count": 1
                    }
                else:
                    # Aggregate comments and use the highest severity score
                    techniques[tech_id]["comment"] += f"\n\n{comment}"
                    if severity_score > techniques[tech_id]["score"]:
                        techniques[tech_id]["score"] = severity_score
                    techniques[tech_id]["count"] += 1
        
        # For techniques seen multiple times, we can adjust the score or just keep the highest severity.
        # Let's also add the occurrence count to the comment.
        for tech_id, tech_data in techniques.items():
            tech_data["comment"] = f"Occurrences: {tech_data['count']}\n\n{tech_data['comment']}"

        return techniques

    def generate_layer(self) -> Dict[str, Any]:
        """Generates the full ATT&CK Navigator layer JSON object."""
        
        unique_techniques = self._get_unique_techniques()

        layer = {
            "name": self.layer_name,
            "versions": {
                "attack": "17", # Specify a version of the ATT&CK matrix
                "navigator": "4.8.2",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": self.layer_description,
            "filters": {
                "platforms": [
                    "Linux",
                    "macOS",
                    "Windows",
                    "Network",
                    "PRE",
                    "Containers",
                    "Office 365",
                    "SaaS",
                    "Google Workspace",
                    "IaaS",
                    "Azure AD"
                ]
            },
            "sorting": 2, # Sort by score, descending
            "layout": {
                "layout": "side",
                "showID": True,
                "showName": True
            },
            "gradient": {
                "colors": [
                    "#f5f5f5", # Low severity
                    "#ffc107", # Medium
                    "#fd7e14", # High
                    "#dc3545"  # Critical
                ],
                "minValue": 1,
                "maxValue": 10
            },
            "techniques": list(unique_techniques.values())
        }
        return layer

    def save_layer_to_file(self, output_path: str):
        """Generates and saves the layer to a file."""
        layer_json = self.generate_layer()
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(layer_json, f, indent=4)
