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
# 

import pytest
import os
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from threat_analysis.core.mitre_mapping_module import MitreMapping

@pytest.fixture
def mitre_mapping():
    with patch('threat_analysis.core.data_loader.pd.read_csv') as mock_read_csv:
        mock_read_csv.return_value = MagicMock()
        with patch('threat_analysis.core.mitre_mapping_module.get_custom_threats') as mock_get_custom_threats:
            mock_get_custom_threats.return_value = {}
            with patch('builtins.open', new_callable=mock_open, read_data='{}') as mock_file:
                with patch('threat_analysis.core.mitre_mapping_module.attack_d3fend_mapping', {'M1015': ['D3-ANCI Test']}):
                    with patch('threat_analysis.core.data_loader.load_d3fend_mapping', return_value={'D3-ANCI': {'name': 'Test', 'description': 'Test'}}):
                        yield MitreMapping(threat_model=MagicMock())

def test_mitre_mapping_initialization(mitre_mapping):
    assert mitre_mapping is not None

def test_map_threat_to_mitre(mitre_mapping):
    threat_description = "A phishing attack was performed."
    mapping_results = mitre_mapping.map_threat_to_mitre(threat_description, "Spoofing")
    mitre_techniques = mapping_results.get('techniques', [])
    assert len(mitre_techniques) > 0
    assert mitre_techniques[0]['id'] == 'T1566'

def test_classify_pytm_threat(mitre_mapping):
    threat = MagicMock()
    threat.description = "A spoofing attack was performed."
    threat.stride_category = "Spoofing"
    stride_category = mitre_mapping.classify_pytm_threat(threat)
    assert stride_category == 'Spoofing'

def test_initialize_d3fend_mapping_file_not_found(caplog):
    # This is a more robust way to test this specific scenario
    with patch('pathlib.Path.exists', return_value=False):
        with caplog.at_level(logging.WARNING):
            mitre_mapping = MitreMapping(threat_model=MagicMock())
            assert mitre_mapping.d3fend_details == {}
            # Now the assertion will match the log in ALL environments
            assert "D3FEND CSV file not found" in caplog.text

def test_load_custom_mitre_mappings_from_markdown_file_not_found(caplog):
    with patch('builtins.open', side_effect=FileNotFoundError):
        with patch('os.path.exists', return_value=False): # Ensure os.path.exists returns False
            with patch('os.path.join', return_value='/fake/path/threatModel_Template/threat_model.md'):
                with caplog.at_level(1):
                    mitre_mapping = MitreMapping(threat_model=MagicMock(), threat_model_path='/fake/path/threatModel_Template/threat_model.md')
                    assert mitre_mapping.custom_mitre_mappings == []
                    assert "Warning: Custom MITRE mapping file not found" not in caplog.text # No warning expected

def test_load_custom_mitre_mappings_from_markdown_success():
    mock_markdown_content = '''
## Custom Mitre Mapping
- **Test Attack**: {"tactics": ["Test Tactic"], "techniques": [{"id": "T9999", "name": "Test Technique"}]}
'''
    with patch('builtins.open', mock_open(read_data=mock_markdown_content)) as mock_file:
        with patch('os.path.exists', return_value=True): # Simulate file found
            # Mock os.path.join to return the expected absolute path for the open call
            with patch('os.path.join', return_value='/fake/path/threatModel_Template/threat_model.md'):
                mitre_mapping = MitreMapping(threat_model=MagicMock(), threat_model_path='threatModel_Template/threat_model.md')
                assert len(mitre_mapping.custom_mitre_mappings) == 1
                assert mitre_mapping.custom_mitre_mappings[0]['threat_name'] == 'Test Attack'
                assert mitre_mapping.custom_mitre_mappings[0]['tactics'] == ['Test Tactic']
                assert mitre_mapping.custom_mitre_mappings[0]['techniques'] == [{'id': 'T9999', 'name': 'Test Technique'}]

def test_technique_urls_are_present(mitre_mapping):
    """Test that all techniques in the mapping have a URL."""
    for category in mitre_mapping.mapping.values():
        for technique in category.get("techniques", []):
            assert "url" in technique
            assert technique["url"].startswith("https://attack.mitre.org/techniques/")

def test_new_technique_mapping(mitre_mapping):
    """Test the mapping of a newly added technique."""
    threat_description = "A trusted relationship was abused."
    mapping_results = mitre_mapping.map_threat_to_mitre(threat_description, "Spoofing")
    mitre_techniques = mapping_results.get('techniques', [])
    assert len(mitre_techniques) > 0
    assert any(t['id'] == 'T1199' for t in mitre_techniques)

def test_get_d3fend_mitigations_for_mitre_id(mitre_mapping):
    """Test _get_d3fend_mitigations_for_mitre_id."""
    mitigations = mitre_mapping._get_d3fend_mitigations_for_mitre_id("M1015")
    assert isinstance(mitigations, list)
    assert len(mitigations) > 0
    assert "Test" in mitigations[0]["name"]

def test_get_stride_categories(mitre_mapping):
    """Test get_stride_categories."""
    categories = mitre_mapping.get_stride_categories()
    assert isinstance(categories, list)
    assert "Spoofing" in categories