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

import pytest
from unittest.mock import MagicMock
from threat_analysis.custom_threats import _create_threat_dict, ThreatGenerator, get_custom_threats

def test_create_threat_dict():
    """Test the _create_threat_dict helper function."""
    threat = _create_threat_dict("ComponentA", "DescriptionA", "Spoofing", "High")
    assert threat == {
        "component": "ComponentA",
        "description": "DescriptionA",
        "stride_category": "Spoofing",
        "severity": "High",
    }

def test_threat_generator_init_and_add_threat():
    """Test ThreatGenerator initialization and _add_threat method."""
    mock_threat_model = MagicMock()
    generator = ThreatGenerator(mock_threat_model)
    assert generator.threat_model == mock_threat_model
    assert generator.threats == []
    assert generator.id_counter == 1

    generator._add_threat("ComponentB", "DescriptionB", "Tampering", "Medium")
    assert len(generator.threats) == 1
    assert generator.threats[0]["id"] == 1
    assert generator.threats[0]["component"] == "ComponentB"
    assert generator.id_counter == 2

def test_generate_threats_empty_model():
    """Test generate_threats with an empty threat model."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert threats == []

def test_generate_threats_with_actors():
    """Test generate_threats with actors."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []
    mock_threat_model.actors = [{"name": "UserA"}, {"name": "UserB"}]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) == 4 # 2 threats per actor
    assert any(t["component"] == "UserA" for t in threats)
    assert any(t["component"] == "UserB" for t in threats)

def test_generate_threats_with_unencrypted_dataflow():
    """Test generate_threats with an unencrypted dataflow."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.actors = []

    mock_dataflow = MagicMock()
    mock_dataflow.is_encrypted = False
    mock_dataflow.source.name = "SourceA"
    mock_dataflow.sink.name = "SinkA"
    mock_threat_model.dataflows = [mock_dataflow]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) == 1
    assert threats[0]["description"] == "Data interception on an unencrypted channel (Man-in-the-Middle)"

def test_generate_threats_with_encrypted_dataflow():
    """Test generate_threats with an encrypted dataflow (should not generate threat)."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.actors = []

    mock_dataflow = MagicMock()
    mock_dataflow.is_encrypted = True
    mock_dataflow.source.name = "SourceA"
    mock_dataflow.sink.name = "SinkA"
    mock_threat_model.dataflows = [mock_dataflow]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) == 0

def test_generate_threats_with_generic_server():
    """Test generate_threats with a generic server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "GenericServer"}]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) == 4 # 4 generic threats
    assert all(t["component"] == "GenericServer" for t in threats)

def test_generate_threats_with_app_server():
    """Test generate_threats with an app server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "My App Server"}]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    # 4 generic + 3 app server specific
    assert len(threats) == 7
    assert any("SQL or NoSQL injection" in t["description"] for t in threats)

def test_generate_threats_with_database():
    """Test generate_threats with a database server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "UserDB"}]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    # 4 generic + 4 database specific
    assert len(threats) == 8
    assert any("Unauthorized access to sensitive data" in t["description"] for t in threats)

def test_generate_threats_with_firewall():
    """Test generate_threats with a firewall server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "Perimeter Firewall"}]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    # 4 generic + 4 firewall specific
    assert len(threats) == 8
    assert any("Firewall rule misconfiguration" in t["description"] for t in threats)

def test_generate_threats_with_load_balancer():
    """Test generate_threats with a load balancer server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "LB Gateway"}]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    # 4 generic + 2 load balancer specific
    assert len(threats) == 6
    assert any("Session hijacking" in t["description"] for t in threats)

def test_generate_threats_with_central_server():
    """Test generate_threats with a central server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "Central Server"}]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    # 4 generic + 2 central server specific
    assert len(threats) == 6
    assert any("Compromise of the management interface" in t["description"] for t in threats)

def test_generate_threats_with_switch():
    """Test generate_threats with a switch server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "Network Switch"}]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    # 4 generic + 2 switch specific
    assert len(threats) == 6
    assert any("VLAN hopping attack" in t["description"] for t in threats)

def test_generate_threats_with_atm_specific_server():
    """Test generate_threats with an ATM specific server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "ATM Control System"}]

    generator = ThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    # 4 generic + 5 ATM specific
    assert len(threats) == 9
    assert any("Injection of false surveillance data" in t["description"] for t in threats)

def test_generate_server_threats_with_database_direct():
    """Test _generate_server_threats with a database server directly."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = [{"name": "MyDatabase"}]
    generator = ThreatGenerator(mock_threat_model)
    generator._generate_server_threats()
    # Expect 4 generic threats + 4 database specific threats = 8
    assert len(generator.threats) == 8
    assert any("Unauthorized access to sensitive data" in t["description"] for t in generator.threats)

def test_get_custom_threats():
    """Test the get_custom_threats function."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []
    mock_threat_model.actors = [{"name": "TestActor"}]

    threats = get_custom_threats(mock_threat_model)
    assert len(threats) == 2 # 2 threats from TestActor
    assert any(t["component"] == "TestActor" for t in threats)
