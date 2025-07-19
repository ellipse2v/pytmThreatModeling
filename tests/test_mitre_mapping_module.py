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
from unittest.mock import MagicMock, patch, mock_open
from threat_analysis.core.mitre_mapping_module import MitreMapping

@pytest.fixture
def mitre_mapping():
    with patch('threat_analysis.core.mitre_mapping_module.pd.read_csv') as mock_read_csv:
        mock_read_csv.return_value = MagicMock()
        with patch('threat_analysis.core.mitre_mapping_module.get_custom_threats') as mock_get_custom_threats:
            mock_get_custom_threats.return_value = {}
            with patch('builtins.open', new_callable=MagicMock) as mock_open:
                mock_open.return_value.read.return_value = ""
                yield MitreMapping(threat_model=MagicMock())

def test_mitre_mapping_initialization(mitre_mapping):
    assert mitre_mapping is not None

def test_map_threat_to_mitre(mitre_mapping):
    threat_description = "A phishing attack was performed."
    mitre_techniques = mitre_mapping.map_threat_to_mitre(threat_description)
    assert len(mitre_techniques) > 0
    assert mitre_techniques[0]['id'] == 'T1566'

def test_classify_pytm_threat(mitre_mapping):
    threat = MagicMock()
    threat.description = "A spoofing attack was performed."
    threat.stride_category = "Spoofing"
    stride_category = mitre_mapping.classify_pytm_threat(threat)
    assert stride_category == 'Spoofing'

def test_initialize_d3fend_mapping_file_not_found(caplog):
    with patch('threat_analysis.core.mitre_mapping_module.pd.read_csv', side_effect=FileNotFoundError):
        with patch('os.path.join', return_value='/fake/path/d3fend.csv'):
            with caplog.at_level(1):
                mitre_mapping = MitreMapping(threat_model=MagicMock())
                assert mitre_mapping.d3fend_details == {}
                assert "Error: d3fend.csv not found" in caplog.text

def test_load_custom_mitre_mappings_from_markdown_file_not_found(caplog):
    with patch('builtins.open', side_effect=FileNotFoundError):
        with patch('os.path.exists', return_value=False): # Ensure os.path.exists returns False
            with patch('os.path.join', return_value='/fake/path/threatModel_Template/threat_model.md'):
                with caplog.at_level(1):
                    mitre_mapping = MitreMapping(threat_model=MagicMock(), threat_model_path='/fake/path/threatModel_Template/threat_model.md')
                    assert mitre_mapping.custom_mitre_mappings == []
                    assert "Warning: Custom MITRE mapping file not found" not in caplog.text # No warning expected

def test_load_custom_mitre_mappings_from_markdown_success():
    mock_markdown_content = """
## Custom Mitre Mapping
- **Test Attack**: {"tactics": ["Test Tactic"], "techniques": [{"id": "T9999", "name": "Test Technique"}]}
"""
    with patch('builtins.open', mock_open(read_data=mock_markdown_content)) as mock_file:
        with patch('os.path.exists', return_value=True): # Simulate file found
            # Mock os.path.join to return the expected absolute path for the open call
            with patch('os.path.join', return_value='/fake/path/threatModel_Template/threat_model.md'):
                mitre_mapping = MitreMapping(threat_model=MagicMock(), threat_model_path='threatModel_Template/threat_model.md')
                assert len(mitre_mapping.custom_mitre_mappings) == 1
                assert mitre_mapping.custom_mitre_mappings[0]['threat_name'] == 'Test Attack'
                assert mitre_mapping.custom_mitre_mappings[0]['tactics'] == ['Test Tactic']
                assert mitre_mapping.custom_mitre_mappings[0]['techniques'] == [{'id': 'T9999', 'name': 'Test Technique'}]
