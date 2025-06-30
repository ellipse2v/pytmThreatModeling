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

def get_custom_threats(threat_model):
    """
    Generates a list of threats based on the components in the threat model.
    This function analyzes servers, actors, and dataflows to create
    both generic and role-specific threats.
    """
    threats = []
    id_counter = 1

    # --- Role-Based Threat Generation for Servers ---
    for server_info in threat_model.servers:
        server_name = server_info['name']
        
        # Add generic threats for all servers
        threats.extend(_generate_generic_server_threats(server_name, id_counter))
        id_counter += len(threats) # Increment counter

        # Add role-specific threats
        if "app server" in server_name.lower():
            threats.extend(_generate_app_server_threats(server_name, id_counter))
        elif "database" in server_name.lower():
            threats.extend(_generate_database_threats(server_name, id_counter))
        elif "firewall" in server_name.lower():
            threats.extend(_generate_firewall_threats(server_name, id_counter))
        elif "load balancer" in server_name.lower() or "gateway" in server_name.lower():
            threats.extend(_generate_load_balancer_threats(server_name, id_counter))
        elif "central server" in server_name.lower():
            threats.extend(_generate_central_server_threats(server_name, id_counter))
        elif "switch" in server_name.lower():
            threats.extend(_generate_switch_threats(server_name, id_counter))
        
        # Add ATM-specific threats if relevant keywords are found
        if any(keyword in server_name.lower() for keyword in ["atm", "flight", "radar", "control"]):
            threats.extend(_generate_atm_specific_threats(server_name, id_counter))

        id_counter = len(threats) + 1


    # --- Threats for Data Flows ---
    for flow in threat_model.dataflows:
        if not flow.is_encrypted:
            threats.append({
                "id": id_counter,
                "component": f"Flow from {flow.source.name} to {flow.sink.name}",
                "description": "Data interception on an unencrypted channel (Man-in-the-Middle)",
                "stride_category": "Information Disclosure",
                "severity": "High"
            })
            id_counter += 1

    # --- Threats for Actors ---
    for actor_info in threat_model.actors:
        actor_name = actor_info['name']
        threats.extend(_generate_actor_threats(actor_name, id_counter))
        id_counter = len(threats) + 1
            
    return threats

# --- Helper functions for generating threats for specific component types ---

def _generate_generic_server_threats(server_name, start_id):
    return [
        {
            "id": start_id,
            "component": server_name,
            "description": f"Unpatched OS or software vulnerabilities on {server_name}",
            "stride_category": "Tampering",
            "severity": "High"
        },
        {
            "id": start_id + 1,
            "component": server_name,
            "description": f"Insecure security configuration or hardening on {server_name}",
            "stride_category": "Information Disclosure",
            "severity": "Medium"
        },
        {
            "id": start_id + 2,
            "component": server_name,
            "description": f"Unauthorized privilege escalation on {server_name}",
            "stride_category": "Elevation of Privilege",
            "severity": "High"
        },
        {
            "id": start_id + 3,
            "component": server_name,
            "description": f"Lack of monitoring or logging on {server_name}, preventing detection of malicious activities",
            "stride_category": "Repudiation",
            "severity": "Medium"
        }
    ]

def _generate_app_server_threats(server_name, start_id):
    return [
        {
            "id": start_id,
            "component": server_name,
            "description": f"SQL or NoSQL injection vulnerability in the application on {server_name}",
            "stride_category": "Tampering",
            "severity": "Critical"
        },
        {
            "id": start_id + 1,
            "component": server_name,
            "description": f"Cross-Site Scripting (XSS) vulnerability allowing script injection on {server_name}",
            "stride_category": "Tampering",
            "severity": "Medium"
        },
        {
            "id": start_id + 2,
            "component": server_name,
            "description": f"Insecure Direct Object References (IDOR) leading to unauthorized data access on {server_name}",
            "stride_category": "Information Disclosure",
            "severity": "High"
        }
    ]

def _generate_database_threats(db_name, start_id):
    return [
        {
            "id": start_id,
            "component": db_name,
            "description": f"Unauthorized access to sensitive data stored in {db_name}",
            "stride_category": "Information Disclosure",
            "severity": "High"
        },
        {
            "id": start_id + 1,
            "component": db_name,
            "description": f"Data exfiltration or leakage from {db_name}",
            "stride_category": "Information Disclosure",
            "severity": "High"
        },
        {
            "id": start_id + 2,
            "component": db_name,
            "description": f"Data corruption or tampering in {db_name} via unauthorized write access",
            "stride_category": "Tampering",
            "severity": "High"
        },
        {
            "id": start_id + 3,
            "component": db_name,
            "description": f"Denial of Service against {db_name} through resource-intensive queries",
            "stride_category": "Denial of Service",
            "severity": "Medium"
        }
    ]

def _generate_firewall_threats(fw_name, start_id):
    return [
        {
            "id": start_id,
            "component": fw_name,
            "description": f"Firewall rule misconfiguration allowing unintended traffic to bypass {fw_name}",
            "stride_category": "Spoofing",
            "severity": "High"
        },
        {
            "id": start_id + 1,
            "component": fw_name,
            "description": f"Denial of Service (DoS) attack targeting {fw_name} to exhaust its resources",
            "stride_category": "Denial of Service",
            "severity": "High"
        },
        {
            "id": start_id + 2,
            "component": fw_name,
            "description": f"Vulnerability in the management interface of {fw_name}",
            "stride_category": "Elevation of Privilege",
            "severity": "Critical"
        },
        {
            "id": start_id + 3,
            "component": fw_name,
            "description": f"Firewall bypass through fragmented packets or other evasion techniques against {fw_name}",
            "stride_category": "Spoofing",
            "severity": "High"
        }
    ]

def _generate_load_balancer_threats(lb_name, start_id):
    return [
        {
            "id": start_id,
            "component": lb_name,
            "description": f"Session hijacking or fixation attack against the {lb_name}",
            "stride_category": "Spoofing",
            "severity": "Medium"
        },
        {
            "id": start_id + 1,
            "component": lb_name,
            "description": f"Weak SSL/TLS configuration or ciphers used by {lb_name}",
            "stride_category": "Information Disclosure",
            "severity": "Medium"
        }
    ]

def _generate_switch_threats(switch_name, start_id):
    return [
        {
            "id": start_id,
            "component": switch_name,
            "description": f"VLAN hopping attack to gain access to unauthorized network segments through {switch_name}",
            "stride_category": "Elevation of Privilege",
            "severity": "High"
        },
        {
            "id": start_id + 1,
            "component": switch_name,
            "description": f"MAC flooding attack on {switch_name} to force it into a hub-like state, enabling sniffing",
            "stride_category": "Information Disclosure",
            "severity": "Medium"
        }
    ]

def _generate_central_server_threats(server_name, start_id):
    return [
        {
            "id": start_id,
            "component": server_name,
            "description": f"Compromise of the management interface of {server_name}",
            "stride_category": "Elevation of Privilege",
            "severity": "Critical"
        },
        {
            "id": start_id + 1,
            "component": server_name,
            "description": f"Lateral movement from {server_name} to other systems in the network",
            "stride_category": "Elevation of Privilege",
            "severity": "High"
        }
    ]

def _generate_atm_specific_threats(component_name, start_id):
    """Generates threats specific to Air Traffic Management (ATM) systems."""
    return [
        {
            "id": start_id,
            "component": component_name,
            "description": f"Injection of false surveillance data (e.g., ghost aircraft) into {component_name}",
            "stride_category": "Tampering",
            "severity": "Critical"
        },
        {
            "id": start_id + 1,
            "component": component_name,
            "description": f"Denial of Service on {component_name} to disrupt air traffic control",
            "stride_category": "Denial of Service",
            "severity": "Critical"
        },
        {
            "id": start_id + 2,
            "component": component_name,
            "description": f"Unauthorized access to or modification of flight plans in {component_name}",
            "stride_category": "Tampering",
            "severity": "Critical"
        },
        {
            "id": start_id + 3,
            "component": component_name,
            "description": f"Spoofing of ADS-B signals to provide false aircraft position data to {component_name}",
            "stride_category": "Spoofing",
            "severity": "High"
        },
        {
            "id": start_id + 4,
            "component": component_name,
            "description": f"Interference with Controller-Pilot Data Link Communications (CPDLC) via {component_name}",
            "stride_category": "Information Disclosure",
            "severity": "High"
        }
    ]

def _generate_actor_threats(actor_name, start_id):
    return [
        {
            "id": start_id,
            "component": actor_name,
            "description": f"Identity spoofing of the actor {actor_name} via phishing or credential theft",
            "stride_category": "Spoofing",
            "severity": "Medium"
        },
        {
            "id": start_id + 1,
            "component": actor_name,
            "description": f"Repudiation of critical actions performed by {actor_name}",
            "stride_category": "Repudiation",
            "severity": "Medium"
        }
    ]