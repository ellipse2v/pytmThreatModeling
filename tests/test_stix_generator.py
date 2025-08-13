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
import json
from threat_analysis.generation.stix_generator import StixGenerator

@pytest.fixture
def stix_generator():
    """Fixture for creating a StixGenerator instance with mocked data."""
    threat_model = MagicMock()
    threat_model.tm.name = "Test Threat Model"

    detailed_threats = [
        {
            "type": "Spoofing",
            "description": "User identity theft",
            "target": "User",
            "severity": {"score": 8.5, "level": "HIGH"},
            "mitre_techniques": [{"id": "T1566", "name": "Phishing"}],
            "stride_category": "Spoofing",
        },
        {
            "type": "Tampering",
            "description": "Data manipulation in transit",
            "target": "Data Flow",
            "severity": {"score": 7.0, "level": "HIGH"},
            "mitre_techniques": [{"id": "T1071", "name": "Application Layer Protocol"}],
            "stride_category": "Tampering",
        }
    ]

    return StixGenerator(threat_model, detailed_threats)

def test_generate_stix_bundle(stix_generator):
    """Test the generation of a STIX bundle."""
    bundle = stix_generator.generate_stix_bundle()

    # Basic bundle validation
    assert isinstance(bundle, dict)
    assert bundle.get("type") == "bundle"
    assert "id" in bundle and bundle["id"].startswith("bundle--")
    assert "spec_version" in bundle and bundle["spec_version"] == "2.1"
    assert "objects" in bundle and isinstance(bundle["objects"], list)

    # Validate the contents of the bundle
    objects = bundle["objects"]

    # Extract object types for easier validation
    object_types = [obj.get("type") for obj in objects]

    # Check for required STIX and Attack Flow objects
    assert "extension-definition" in object_types
    assert "identity" in object_types
    assert "attack-flow" in object_types

    # Check for the correct number of attack actions and assets
    assert object_types.count("attack-action") == 2
    assert object_types.count("attack-asset") == 2
    assert object_types.count("relationship") == 2

    # Detailed inspection of one object
    attack_action = next((obj for obj in objects if obj.get("type") == "attack-action" and obj.get("name") == "User identity theft"), None)
    assert attack_action is not None
    assert attack_action.get("technique_id") == "T1566"

    # Validate JSON serializability
    try:
        json.dumps(bundle)
    except TypeError as e:
        pytest.fail(f"STIX bundle is not JSON serializable: {e}")
