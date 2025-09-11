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

from .threat_rules import THREAT_RULES
import logging

class RuleBasedThreatGenerator:
    """
    A class to generate threats for a given threat model based on a set of expressive rules.
    The engine can handle nested property checks (e.g., 'source.boundary.isTrusted').
    """
    def __init__(self, threat_model):
        self.threat_model = threat_model
        self.threats = []
        self.id_counter = 1
        self.rules = THREAT_RULES

    def _add_threat(self, component_name, description, stride_category, impact, likelihood, mitigations=None, capec_ids=None):
        threat = {
            "id": self.id_counter,
            "component": component_name,
            "description": description,
            "stride_category": stride_category,
            "impact": impact,
            "likelihood": likelihood,
            "mitigations": mitigations or [],
            "capec_ids": capec_ids or []
        }
        self.threats.append(threat)
        self.id_counter += 1

    def _get_property(self, component, key):
        """Gets a property from a component, handling dot notation for nested objects."""
        value = component
        try:
            for part in key.split('.'):
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = getattr(value, part, None)
                if value is None:
                    return None
        except AttributeError:
            return None
        return value

    def _matches(self, component, conditions):
        """
        Checks if a component's properties match the given conditions, supporting dot notation
        and special computed conditions.
        """
        if not conditions:
            return True

        for key, expected_value in conditions.items():
            # Handle special computed conditions first
            if key == 'crosses_trust_boundary':
                source_boundary = self._get_property(component, 'source.inBoundary')
                sink_boundary = self._get_property(component, 'sink.inBoundary')
                if not source_boundary or not sink_boundary:
                    return False # Cannot determine if boundaries are crossed
                
                is_crossing = source_boundary.isTrusted != sink_boundary.isTrusted
                if is_crossing != expected_value:
                    return False
                continue # Move to the next condition

            if key == 'contains_sensitive_data':
                data_list = self._get_property(component, 'data')
                if not isinstance(data_list, list):
                    return False # Data is not in the expected list format
                
                has_sensitive = any(
                    self._get_property(d, 'classification.name').lower() in ['secret', 'top_secret', 'sensitive'] 
                    for d in data_list
                )
                if has_sensitive != expected_value:
                    return False
                continue # Move to the next condition

            # Handle direct property lookups
            prop_value = self._get_property(component, key)
            
            if hasattr(prop_value, 'name'):
                prop_value = prop_value.name.lower()

            if isinstance(prop_value, str) and isinstance(expected_value, str):
                if prop_value.lower() != expected_value.lower():
                    return False
            elif prop_value != expected_value:
                return False
        return True

    def generate_threats(self):
        """
        Generates all threats for the threat model by applying rules to each component.
        """
        for server_info in self.threat_model.servers:
            for rule in self.rules.get("servers", []):
                if self._matches(server_info, rule["conditions"]):
                    for threat_template in rule["threats"]:
                        # Format description separately and pass other args via kwargs
                        formatted_description = threat_template["description"].format(name=server_info['name'])
                        threat_args = {k: v for k, v in threat_template.items() if k != 'description'}
                        self._add_threat(server_info['name'], formatted_description, **threat_args)

        for flow in self.threat_model.dataflows:
            for rule in self.rules.get("dataflows", []):
                if self._matches(flow, rule["conditions"]):
                    for threat_template in rule["threats"]:
                        formatted_description = threat_template["description"].format(source=flow.source, sink=flow.sink)
                        threat_args = {k: v for k, v in threat_template.items() if k != 'description'}
                        self._add_threat(f"Flow from {flow.source.name} to {flow.sink.name}", formatted_description, **threat_args)

        for actor_info in self.threat_model.actors:
            for rule in self.rules.get("actors", []):
                if self._matches(actor_info, rule["conditions"]):
                    for threat_template in rule["threats"]:
                        formatted_description = threat_template["description"].format(name=actor_info['name'])
                        threat_args = {k: v for k, v in threat_template.items() if k != 'description'}
                        self._add_threat(actor_info['name'], formatted_description, **threat_args)
        
        return self.threats

def get_custom_threats(threat_model):
    """
    Generates a list of threats based on the components in the threat model.
    """
    generator = RuleBasedThreatGenerator(threat_model)
    return generator.generate_threats()
