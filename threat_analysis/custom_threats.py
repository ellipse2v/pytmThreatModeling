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


def _create_threat_dict(component_name, description, stride_category, impact, likelihood, mitigations=None):
    """Creates a threat dictionary with a placeholder for the ID."""
    return {
        "component": component_name,
        "description": description,
        "stride_category": stride_category,
        "impact": impact,
        "likelihood": likelihood,
        "mitigations": mitigations or [],
    }


class RuleBasedThreatGenerator:
    """
    A class to generate threats for a given threat model based on a set of rules.
    """
    def __init__(self, threat_model):
        self.threat_model = threat_model
        self.threats = []
        self.id_counter = 1
        self.rules = THREAT_RULES

    def _add_threat(self, component_name, description, stride_category, impact, likelihood, mitigations=None):
        """Adds a new threat to the list with a unique ID."""
        threat = _create_threat_dict(component_name, description, stride_category, impact, likelihood, mitigations)
        threat["id"] = self.id_counter
        self.threats.append(threat)
        self.id_counter += 1

    def _matches(self, component_properties, conditions):
        """
        Checks if a component's properties match the given conditions.
        This check is case-insensitive for string comparisons.
        """
        if not conditions:  # If conditions are empty, it's a match for any component
            return True
        for key, value in conditions.items():
            prop_value = component_properties.get(key)
            # Make string comparison case-insensitive
            if isinstance(prop_value, str) and isinstance(value, str):
                if prop_value.lower() != value.lower():
                    return False
            elif prop_value != value:
                return False
        return True

    def generate_threats(self):
        """
        Generates all threats for the threat model by applying rules.
        """
        self._generate_server_threats()
        self._generate_dataflow_threats()
        self._generate_actor_threats()
        return self.threats

    def _generate_server_threats(self):
        """Generates threats for all servers based on rules."""
        for server_info in self.threat_model.servers:
            for rule in self.rules.get("servers", []):
                if self._matches(server_info, rule["conditions"]):
                    for threat_template in rule["threats"]:
                        self._add_threat(
                            server_info['name'],
                            threat_template["description"].format(name=server_info['name']),
                            threat_template["stride_category"],
                            threat_template["impact"],
                            threat_template["likelihood"],
                            threat_template.get("mitigations")
                        )

    def _generate_dataflow_threats(self):
        """
        Generates threats for all dataflows based on rules, including those
        specific to network boundaries like DMZ and Gateway.
        """
        for flow in self.threat_model.dataflows:
            contains_sensitive_data = False
            if hasattr(flow, 'data') and flow.data:
                for data_obj in flow.data:
                    if hasattr(data_obj, 'classification') and data_obj.classification == 'pii':
                        contains_sensitive_data = True
                        break

            source_boundary_name = None
            if hasattr(flow.source, 'inBoundary') and flow.source.inBoundary:
                source_boundary_name = flow.source.inBoundary.name

            sink_boundary_name = None
            if hasattr(flow.sink, 'inBoundary') and flow.sink.inBoundary:
                sink_boundary_name = flow.sink.inBoundary.name

            crosses_trust_boundary = source_boundary_name != sink_boundary_name

            flow_properties = {
                "is_encrypted": flow.is_encrypted,
                "is_authenticated": flow.is_authenticated,
                "contains_sensitive_data": contains_sensitive_data,
                "crosses_trust_boundary": crosses_trust_boundary,
                "source_boundary": source_boundary_name,
                "sink_boundary": sink_boundary_name,
            }
            for rule in self.rules.get("dataflows", []):
                if self._matches(flow_properties, rule["conditions"]):
                    for threat_template in rule["threats"]:
                        self._add_threat(
                            f"Flow from {flow.source.name} to {flow.sink.name}",
                            threat_template["description"].format(source=flow.source, sink=flow.sink),
                            threat_template["stride_category"],
                            threat_template["impact"],
                            threat_template["likelihood"],
                            threat_template.get("mitigations")
                        )

    def _generate_actor_threats(self):
        """Generates threats for all actors based on rules."""
        for actor_info in self.threat_model.actors:
            for rule in self.rules.get("actors", []):
                if self._matches(actor_info, rule["conditions"]):
                    for threat_template in rule["threats"]:
                        self._add_threat(
                            actor_info['name'],
                            threat_template["description"].format(name=actor_info['name']),
                            threat_template["stride_category"],
                            threat_template["impact"],
                            threat_template["likelihood"],
                            threat_template.get("mitigations")
                        )


def get_custom_threats(threat_model):
    """
    Generates a list of threats based on the components in the threat model
    using a rule-based engine.
    """
    generator = RuleBasedThreatGenerator(threat_model)
    return generator.generate_threats()