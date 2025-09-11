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
from threat_analysis.mitigation_suggestions import MitigationStixMapper

@pytest.fixture(scope="module")
def mitigation_mapper():
    """Fixture to initialize the MitigationStixMapper once per module."""
    return MitigationStixMapper()

def test_mapper_initialization(mitigation_mapper):
    """Test that the MitigationStixMapper initializes and loads data."""
    assert mitigation_mapper is not None
    assert isinstance(mitigation_mapper.attack_to_mitigations_map, dict)
    # Check that the map is not empty, assuming the data file is present
    assert len(mitigation_mapper.attack_to_mitigations_map) > 0

def test_mapping_for_known_technique(mitigation_mapper):
    """Test retrieving mitigations for a known ATT&CK technique."""
    # T1566 is Phishing, which should have M1017 (User Training) as a mitigation.
    technique_id = "T1566"
    assert technique_id in mitigation_mapper.attack_to_mitigations_map
    
    suggestions = mitigation_mapper.attack_to_mitigations_map[technique_id]
    assert isinstance(suggestions, list)
    assert len(suggestions) > 0

    # Check if one of the expected mitigations is present
    mitigation_ids = [mit['id'] for mit in suggestions]
    assert "M1017" in mitigation_ids

def test_mapping_for_unknown_technique(mitigation_mapper):
    """Test that an unknown technique ID has no mapping."""
    technique_id = "T9999"
    assert technique_id not in mitigation_mapper.attack_to_mitigations_map