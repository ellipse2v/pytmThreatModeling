
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

def _create_threat_dict(component_name, description, stride_category, severity):
    """Creates a threat dictionary with a placeholder for the ID."""
    return {
        "component": component_name,
        "description": description,
        "stride_category": stride_category,
        "severity": severity,
    }

class ThreatGenerator:
    """
    A class to generate threats for a given threat model.
    """
    def __init__(self, threat_model):
        self.threat_model = threat_model
        self.threats = []
        self.id_counter = 1

    def _add_threat(self, component_name, description, stride_category, severity):
        """Adds a new threat to the list with a unique ID."""
        threat = _create_threat_dict(component_name, description, stride_category, severity)
        threat["id"] = self.id_counter
        self.threats.append(threat)
        self.id_counter += 1

    def generate_threats(self):
        """
        Generates all threats for the threat model.
        """
        self._generate_server_threats()
        self._generate_dataflow_threats()
        self._generate_actor_threats()
        return self.threats

    def _generate_server_threats(self):
        """Generates threats for all servers in the model."""
        for server_info in self.threat_model.servers:
            server_name = server_info['name']
            self._generate_generic_server_threats(server_name)

            if "app server" in server_name.lower():
                self._generate_app_server_threats(server_name)
            if "database" in server_name.lower() or "db" in server_name.lower():
                self._generate_database_threats(server_name)
            if "firewall" in server_name.lower():
                self._generate_firewall_threats(server_name)
            if "load balancer" in server_name.lower() or "gateway" in server_name.lower():
                self._generate_load_balancer_threats(server_name)
            if "central server" in server_name.lower():
                self._generate_central_server_threats(server_name)
            if "switch" in server_name.lower():
                self._generate_switch_threats(server_name)

            if any(keyword in server_name.lower() for keyword in ["atm", "flight", "radar", "control"]):
                self._generate_atm_specific_threats(server_name)

    def _generate_dataflow_threats(self):
        """Generates threats for all dataflows in the model."""
        for flow in self.threat_model.dataflows:
            if not flow.is_encrypted:
                self._add_threat(
                    f"Flow from {flow.source.name} to {flow.sink.name}",
                    "Data interception on an unencrypted channel (Man-in-the-Middle)",
                    "Information Disclosure",
                    "High"
                )

    def _generate_actor_threats(self):
        """Generates threats for all actors in the model."""
        for actor_info in self.threat_model.actors:
            actor_name = actor_info['name']
            self._add_threat(
                actor_name,
                f"Identity spoofing of the actor {actor_name} via phishing or credential theft",
                "Spoofing",
                "Medium"
            )
            self._add_threat(
                actor_name,
                f"Repudiation of critical actions performed by {actor_name}",
                "Repudiation",
                "Medium"
            )

    def _generate_generic_server_threats(self, server_name):
        self._add_threat(server_name, f"Unpatched OS or software vulnerabilities on {server_name}", "Tampering", "High")
        self._add_threat(server_name, f"Insecure security configuration or hardening on {server_name}", "Information Disclosure", "Medium")
        self._add_threat(server_name, f"Unauthorized privilege escalation on {server_name}", "Elevation of Privilege", "High")
        self._add_threat(server_name, f"Lack of monitoring or logging on {server_name}, preventing detection of malicious activities", "Repudiation", "Medium")

    def _generate_app_server_threats(self, server_name):
        self._add_threat(server_name, f"SQL or NoSQL injection vulnerability in the application on {server_name}", "Tampering", "Critical")
        self._add_threat(server_name, f"Cross-Site Scripting (XSS) vulnerability allowing script injection on {server_name}", "Tampering", "Medium")
        self._add_threat(server_name, f"Insecure Direct Object References (IDOR) leading to unauthorized data access on {server_name}", "Information Disclosure", "High")

    def _generate_database_threats(self, db_name):
        self._add_threat(db_name, f"Unauthorized access to sensitive data stored in {db_name}", "Information Disclosure", "High")
        self._add_threat(db_name, f"Data exfiltration or leakage from {db_name}", "Information Disclosure", "High")
        self._add_threat(db_name, f"Data corruption or tampering in {db_name} via unauthorized write access", "Tampering", "High")
        self._add_threat(db_name, f"Denial of Service against {db_name} through resource-intensive queries", "Denial of Service", "Medium")

    def _generate_firewall_threats(self, fw_name):
        self._add_threat(fw_name, f"Firewall rule misconfiguration allowing unintended traffic to bypass {fw_name}", "Spoofing", "High")
        self._add_threat(fw_name, f"Denial of Service (DoS) attack targeting {fw_name} to exhaust its resources", "Denial of Service", "High")
        self._add_threat(fw_name, f"Vulnerability in the management interface of {fw_name}", "Elevation of Privilege", "Critical")
        self._add_threat(fw_name, f"Firewall bypass through fragmented packets or other evasion techniques against {fw_name}", "Spoofing", "High")

    def _generate_load_balancer_threats(self, lb_name):
        self._add_threat(lb_name, f"Session hijacking or fixation attack against the {lb_name}", "Spoofing", "Medium")
        self._add_threat(lb_name, f"Weak SSL/TLS configuration or ciphers used by {lb_name}", "Information Disclosure", "Medium")

    def _generate_switch_threats(self, switch_name):
        self._add_threat(switch_name, f"VLAN hopping attack to gain access to unauthorized network segments through {switch_name}", "Elevation of Privilege", "High")
        self._add_threat(switch_name, f"MAC flooding attack on {switch_name} to force it into a hub-like state, enabling sniffing", "Information Disclosure", "Medium")

    def _generate_central_server_threats(self, server_name):
        self._add_threat(server_name, f"Compromise of the management interface of {server_name}", "Elevation of Privilege", "Critical")
        self._add_threat(server_name, f"Lateral movement from {server_name} to other systems in the network", "Elevation of Privilege", "High")

    def _generate_atm_specific_threats(self, component_name):
        self._add_threat(component_name, f"Injection of false surveillance data (e.g., ghost aircraft) into {component_name}", "Tampering", "Critical")
        self._add_threat(component_name, f"Denial of Service on {component_name} to disrupt air traffic control", "Denial of Service", "Critical")
        self._add_threat(component_name, f"Unauthorized access to or modification of flight plans in {component_name}", "Tampering", "Critical")
        self._add_threat(component_name, f"Spoofing of ADS-B signals to provide false aircraft position data to {component_name}", "Spoofing", "High")
        self._add_threat(component_name, f"Interference with Controller-Pilot Data Link Communications (CPDLC) via {component_name}", "Information Disclosure", "High")

def get_custom_threats(threat_model):
    """
    Generates a list of threats based on the components in the threat model.
    """
    generator = ThreatGenerator(threat_model)
    return generator.generate_threats()
