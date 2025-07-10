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
from unittest.mock import MagicMock, patch
from threat_analysis.mitre_mapping_module import MitreMapping

@pytest.fixture
def mitre_mapping():
    with patch('threat_analysis.mitre_mapping_module.pd.read_csv') as mock_read_csv:
        mock_read_csv.return_value = MagicMock()
        with patch('threat_analysis.mitre_mapping_module.get_custom_threats') as mock_get_custom_threats:
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
