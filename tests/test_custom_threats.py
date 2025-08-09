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

from unittest.mock import MagicMock
from threat_analysis.custom_threats import (_create_threat_dict,
                                           RuleBasedThreatGenerator,
                                           get_custom_threats)


def test_create_threat_dict():
    """Test the _create_threat_dict helper function."""
    threat = _create_threat_dict("ComponentA", "DescriptionA", "Spoofing", 4, 3, ["MitigationA"])
    assert threat == {
        "component": "ComponentA",
        "description": "DescriptionA",
        "stride_category": "Spoofing",
        "impact": 4,
        "likelihood": 3,
        "mitigations": ["MitigationA"],
    }

    # Test with no mitigations
    threat_no_mitigations = _create_threat_dict("ComponentB", "DescriptionB", "Tampering", 5, 4)
    assert threat_no_mitigations["mitigations"] == []


def test_threat_generator_init_and_add_threat():
    """Test RuleBasedThreatGenerator initialization and _add_threat method."""
    mock_threat_model = MagicMock()
    generator = RuleBasedThreatGenerator(mock_threat_model)
    assert generator.threat_model == mock_threat_model
    assert generator.threats == []
    assert generator.id_counter == 1

    generator._add_threat("ComponentB", "DescriptionB", "Tampering", 5, 4)
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

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert threats == []


def test_generate_threats_with_actors():
    """Test generate_threats with actors."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []
    mock_threat_model.actors = [{"name": "UserA"}, {"name": "UserB"}]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) == 4  # 2 threats per actor
    assert any(t["component"] == "UserA" for t in threats)
    assert any(t["component"] == "UserB" for t in threats)


def test_generate_threats_with_unencrypted_dataflow():
    """Test generate_threats with an unencrypted dataflow."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.actors = []

    mock_dataflow = MagicMock()
    mock_dataflow.is_encrypted = False
    mock_dataflow.is_authenticated = True
    mock_dataflow.source.name = "SourceA"
    mock_dataflow.sink.name = "SinkA"
    mock_dataflow.data = []
    mock_threat_model.dataflows = [mock_dataflow]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any("Data interception on an unencrypted channel" in t["description"] for t in threats)


def test_generate_threats_with_unauthenticated_dataflow():
    """Test generate_threats with an unauthenticated dataflow."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.actors = []

    mock_dataflow = MagicMock()
    mock_dataflow.is_encrypted = True
    mock_dataflow.is_authenticated = False
    mock_dataflow.source.name = "SourceA"
    mock_dataflow.sink.name = "SinkA"
    mock_dataflow.data = []
    mock_threat_model.dataflows = [mock_dataflow]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any("Spoofing of data" in t["description"] for t in threats)


def test_generate_threats_with_database_server():
    """Test generate_threats with a database server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "UserDB", "type": "database"}]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any("Unauthorized access to sensitive data" in t["description"] for t in threats)


def test_generate_threats_with_app_server():
    """Test generate_threats with an app server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "WebApp", "type": "app-server"}]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any("SQL or NoSQL injection" in t["description"] for t in threats)


def test_generate_threats_with_public_server():
    """Test generate_threats with a public-facing server."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "PublicAPI", "is_public": True}]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any("Denial of Service (DoS) attack" in t["description"] for t in threats)


def test_generate_threats_with_management_interface():
    """Test generate_threats with a server having a management interface."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [{"name": "ManagedSwitch", "has_management_interface": True}]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any("Compromise of the management interface" in t["description"] for t in threats)


def test_generate_threats_with_network_components():
    """Test generate_threats with various network components."""
    mock_threat_model = MagicMock()
    mock_threat_model.dataflows = []
    mock_threat_model.actors = []
    mock_threat_model.servers = [
        {"name": "FW1", "type": "firewall"},
        {"name": "LB1", "type": "load-balancer"},
        {"name": "SW1", "type": "switch"},
    ]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any("Firewall rule misconfiguration" in t["description"] for t in threats)
    assert any("Session hijacking" in t["description"] for t in threats)
    assert any("VLAN hopping attack" in t["description"] for t in threats)


def test_generate_threats_with_sensitive_data():
    """Test generate_threats with a dataflow containing sensitive data."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.actors = []

    mock_data = MagicMock()
    mock_data.classification = "pii"

    mock_dataflow = MagicMock()
    mock_dataflow.is_encrypted = False
    mock_dataflow.is_authenticated = True
    mock_dataflow.source.name = "SourceA"
    mock_dataflow.sink.name = "SinkA"
    mock_dataflow.data = [mock_data]
    mock_threat_model.dataflows = [mock_dataflow]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any("Sensitive data (PII) transmitted in cleartext" in t["description"] for t in threats)


def test_generate_threats_with_trust_boundary_crossing():
    """Test generate_threats with a dataflow crossing a trust boundary."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.actors = []

    mock_untrusted_boundary = MagicMock()
    mock_untrusted_boundary.name = "untrusted"

    mock_trusted_boundary = MagicMock()
    mock_trusted_boundary.name = "trusted"

    mock_source = MagicMock()
    mock_source.name = "SourceA"
    mock_source.inBoundary = mock_untrusted_boundary

    mock_sink = MagicMock()
    mock_sink.name = "SinkA"
    mock_sink.inBoundary = mock_trusted_boundary

    mock_dataflow = MagicMock()
    mock_dataflow.is_encrypted = True
    mock_dataflow.is_authenticated = False
    mock_dataflow.source = mock_source
    mock_dataflow.sink = mock_sink
    mock_dataflow.data = []
    mock_threat_model.dataflows = [mock_dataflow]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any("Potential for spoofing attacks on data crossing trust boundaries" in t["description"] for t in threats)


def test_get_custom_threats():
    """Test the get_custom_threats function."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []
    mock_threat_model.actors = [{"name": "TestActor"}]

    threats = get_custom_threats(mock_threat_model)
    assert len(threats) == 2  # 2 threats from TestActor
    assert any(t["component"] == "TestActor" for t in threats)


def test_stride_coverage():
    """Test that all STRIDE categories are covered by the generated threats."""
    mock_threat_model = MagicMock()

    mock_threat_model.servers = [
        {"name": "GenericServer"},
        {"name": "DBServer", "type": "database"},
        {"name": "PivotServer", "can_pivot": True},
    ]

    mock_dataflow = MagicMock()
    mock_dataflow.is_encrypted = False
    mock_dataflow.is_authenticated = False
    mock_dataflow.source.name = "SourceA"
    mock_dataflow.sink.name = "SinkA"
    mock_dataflow.data = []
    mock_threat_model.dataflows = [mock_dataflow]

    mock_threat_model.actors = [{"name": "User"}]

    threats = get_custom_threats(mock_threat_model)

    stride_categories = {t["stride_category"] for t in threats}

    assert "Spoofing" in stride_categories
    assert "Tampering" in stride_categories
    assert "Repudiation" in stride_categories
    assert "Information Disclosure" in stride_categories
    assert "Denial of Service" in stride_categories
    assert "Elevation of Privilege" in stride_categories


def test_generate_threats_with_dmz_to_internal_flow():
    """Test generate_threats with a dataflow from DMZ to internal."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.actors = []

    mock_dmz_boundary = MagicMock()
    mock_dmz_boundary.name = "DMZ"

    mock_internal_boundary = MagicMock()
    mock_internal_boundary.name = "Internal"

    mock_source = MagicMock()
    mock_source.name = "WebServer"
    mock_source.inBoundary = mock_dmz_boundary

    mock_sink = MagicMock()
    mock_sink.name = "AppServer"
    mock_sink.inBoundary = mock_internal_boundary

    mock_dataflow = MagicMock()
    mock_dataflow.is_encrypted = True
    mock_dataflow.is_authenticated = True
    mock_dataflow.source = mock_source
    mock_dataflow.sink = mock_sink
    mock_dataflow.data = []
    mock_threat_model.dataflows = [mock_dataflow]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any("Insufficient traffic filtering between DMZ and internal network" in t["description"] for t in threats)


def test_generate_threats_with_internet_to_dmz_flow():
    """Test generate_threats with a dataflow from the internet to DMZ."""
    mock_threat_model = MagicMock()
    mock_threat_model.servers = []
    mock_threat_model.actors = []

    mock_dmz_boundary = MagicMock()
    mock_dmz_boundary.name = "DMZ"

    mock_source = MagicMock()
    mock_source.name = "User"
    mock_source.inBoundary = None  # Represents internet

    mock_sink = MagicMock()
    mock_sink.name = "WebServer"
    mock_sink.inBoundary = mock_dmz_boundary

    mock_dataflow = MagicMock()
    mock_dataflow.is_encrypted = True
    mock_dataflow.is_authenticated = True
    mock_dataflow.source = mock_source
    mock_dataflow.sink = mock_sink
    mock_dataflow.data = []
    mock_threat_model.dataflows = [mock_dataflow]

    generator = RuleBasedThreatGenerator(mock_threat_model)
    threats = generator.generate_threats()
    assert len(threats) > 0
    assert any(
        "Insufficient inspection of inbound traffic from the internet to the DMZ"
        in t["description"] for t in threats
    )
