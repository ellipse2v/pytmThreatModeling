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
STIX Report generation module
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any

class StixGenerator:
    """Class for generating STIX reports with Attack Flow extension"""

    def __init__(self, threat_model, all_detailed_threats: List[Dict[str, Any]]):
        self.threat_model = threat_model
        self.all_detailed_threats = all_detailed_threats
        self.stix_objects = []
        self.bundle_id = f"bundle--{uuid.uuid4()}"
        self.identity_id = f"identity--{uuid.uuid4()}"
        self.extension_id = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"  # static id for attack-flow

    def _get_current_time_iso(self):
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    def _create_extension_definition(self):
        return {
            "type": "extension-definition",
            "id": self.extension_id,
            "spec_version": "2.1",
            "created": "2022-08-02T19:34:35.143Z",
            "modified": "2022-08-02T19:34:35.143Z",
            "name": "Attack Flow",
            "description": "Extends STIX 2.1 with features to create Attack Flows.",
            "created_by_ref": self.identity_id,
            "schema": "https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json",
            "version": "2.0.0",
            "extension_types": ["new-sdo"],
        }

    def _create_identity(self):
        return {
            "type": "identity",
            "id": self.identity_id,
            "spec_version": "2.1",
            "created": self._get_current_time_iso(),
            "modified": self._get_current_time_iso(),
            "name": "Threat Model Analysis Tool",
            "identity_class": "tool",
        }

    def _create_attack_flow(self, start_refs):
        return {
            "type": "attack-flow",
            "spec_version": "2.1",
            "id": f"attack-flow--{uuid.uuid4()}",
            "created_by_ref": self.identity_id,
            "created": self._get_current_time_iso(),
            "modified": self._get_current_time_iso(),
            "name": f"Attack Flow for {self.threat_model.tm.name}",
            "description": f"This Attack Flow was generated from the threat model '{self.threat_model.tm.name}'.",
            "scope": "attack-tree",
            "start_refs": start_refs,
            "extensions": {
                self.extension_id: {
                    "extension_type": "new-sdo"
                }
            }
        }

    def _create_attack_action(self, threat):
        action_id = f"attack-action--{uuid.uuid4()}"
        technique = threat.get('mitre_techniques', [{}])[0] if threat.get('mitre_techniques') else {}

        action = {
            "type": "attack-action",
            "spec_version": "2.1",
            "id": action_id,
            "created": self._get_current_time_iso(),
            "modified": self._get_current_time_iso(),
            "name": str(threat.get('description', 'Unnamed Action')),
            "description": str(threat.get('description', 'No description available.')),
            "technique_id": technique.get('id'),
            "extensions": {
                self.extension_id: {
                    "extension_type": "new-sdo"
                }
            }
        }
        return action

    def _create_attack_asset(self, threat):
        asset_id = f"attack-asset--{uuid.uuid4()}"
        asset = {
            "type": "attack-asset",
            "spec_version": "2.1",
            "id": asset_id,
            "created": self._get_current_time_iso(),
            "modified": self._get_current_time_iso(),
            "name": str(threat.get('target', 'Unnamed Asset')),
            "description": f"Asset targeted by threat: {str(threat.get('description'))}",
            "extensions": {
                self.extension_id: {
                    "extension_type": "new-sdo"
                }
            }
        }
        return asset

    def _create_relationship(self, source_ref, target_ref, relationship_type="uses"):
        return {
            "type": "relationship",
            "id": f"relationship--{uuid.uuid4()}",
            "spec_version": "2.1",
            "created": self._get_current_time_iso(),
            "modified": self._get_current_time_iso(),
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref
        }

    def generate_stix_bundle(self):
        """Generates the STIX bundle."""
        self.stix_objects.append(self._create_extension_definition())
        self.stix_objects.append(self._create_identity())

        start_refs = []

        for threat in self.all_detailed_threats:
            action = self._create_attack_action(threat)
            asset = self._create_attack_asset(threat)
            relationship = self._create_relationship(action['id'], asset['id'], "targets")

            action['asset_refs'] = [asset['id']]

            self.stix_objects.append(action)
            self.stix_objects.append(asset)
            self.stix_objects.append(relationship)

            start_refs.append(action['id'])

        attack_flow_obj = self._create_attack_flow(start_refs)
        self.stix_objects.append(attack_flow_obj)

        bundle = {
            "type": "bundle",
            "id": self.bundle_id,
            "spec_version": "2.1",
            "objects": self.stix_objects
        }

        return bundle
