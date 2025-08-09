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

from unittest.mock import MagicMock, mock_open, patch
import pytest
from threat_analysis.generation.report_generator import ReportGenerator

@pytest.fixture
def report_generator():
    severity_calculator = MagicMock()
    mitre_mapping = MagicMock()
    return ReportGenerator(severity_calculator, mitre_mapping)

def test_generate_html_report(report_generator):
    threat_model = MagicMock()
    threat_model.mitre_analysis_results = {
        'total_threats': 1,
        'mitre_techniques_count': 1,
        'stride_distribution': {'S': 1}
    }
    threat_model.tm.name = "Test Architecture"

    threat_mock = MagicMock(description="Test Threat", stride_category='S', target=MagicMock(data=MagicMock(classification=MagicMock(name='Public'))))
    threat_mock.mitigations = []

    grouped_threats = {
        'Spoofing': [
            (threat_mock, MagicMock(name="Test Target"))
        ]
    }

    report_generator.severity_calculator.get_severity_info.return_value = {
        'level': 'High',
        'score': 8.0
    }
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = [
        {
            'id': 'T1588.002',
            'name': 'Tool',
            'defend_mitigations': [
                {
                    'id': 'D3-SCA',
                    'description': 'Software Component Analysis',
                    'url_friendly_name_source': 'D3-SCA Software Component Analysis'
                }
            ],
            'mitre_mitigations': [
                {
                    'id': 'M1051',
                    'name': 'Update Software'
                }
            ]
        }
    ]

    output_file = "test_report.html"
    with patch.object(report_generator.env, 'get_template') as mock_get_template:
        mock_template = MagicMock()
        mock_get_template.return_value = mock_template
        with patch("builtins.open", mock_open()) as mock_file:
            result = report_generator.generate_html_report(threat_model, grouped_threats, output_file)
            mock_file.assert_called_once_with(output_file, "w", encoding="utf-8")

    assert result == output_file

def test_generate_json_export(report_generator):
    threat_model = MagicMock()
    threat_model.tm.name = "Test Architecture"

    threat_mock = MagicMock(description="Test Threat", stride_category='S', target=MagicMock(data=MagicMock(classification=MagicMock(name='Public'))))
    threat_mock.mitigations = []

    grouped_threats = {
        'Spoofing': [
            (threat_mock, MagicMock(name="Test Target"))
        ]
    }

    report_generator.severity_calculator.get_severity_info.return_value = {
        'level': 'High',
        'score': 8.0
    }
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = []
    report_generator.mitre_mapping.mapping = {}

    output_file = "test_export.json"
    with patch("builtins.open", mock_open()) as mock_file:
        result = report_generator.generate_json_export(threat_model, grouped_threats, output_file)
        mock_file.assert_called_once_with(output_file, "w", encoding="utf-8")

    assert result == output_file

def test_get_all_threats_with_mitre_info_handles_missing_url_friendly_name_source(report_generator):
    threat_model = MagicMock()
    threat_model.mitre_analysis_results = {
        'total_threats': 1,
        'mitre_techniques_count': 1,
        'stride_distribution': {'S': 1}
    }
    threat_model.tm.name = "Test Architecture"

    grouped_threats = {
        'Spoofing': [
            (MagicMock(description="Test Threat", stride_category='S', target=MagicMock(data=MagicMock(classification=MagicMock(name='Public')))), MagicMock(name="Test Target"))
        ]
    }

    report_generator.severity_calculator.get_severity_info.return_value = {
        'level': 'High',
        'score': 8.0
    }
    # Simulate a scenario where 'url_friendly_name_source' is missing
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = [
        {
            'id': 'T1588.002',
            'name': 'Tool',
            'defend_mitigations': [
                {
                    'id': 'D3-SCA',
                    'description': 'Software Component Analysis',
                    # 'url_friendly_name_source' is intentionally missing here
                }
            ],
            'mitre_mitigations': [
                {
                    'id': 'M1051',
                    'name': 'Update Software'
                }
            ]
        }
    ]

    # Call the internal method directly to test its robustness
    all_detailed_threats = report_generator._get_all_threats_with_mitre_info(grouped_threats)

    # Assert that no KeyError occurred and the data is processed as expected
    assert len(all_detailed_threats) == 1
    assert 'mitre_techniques' in all_detailed_threats[0]
    assert len(all_detailed_threats[0]['mitre_techniques']) == 1
    assert 'defend_mitigations' in all_detailed_threats[0]['mitre_techniques'][0]
    assert len(all_detailed_threats[0]['mitre_techniques'][0]['defend_mitigations']) == 1
    # Check that url_friendly_name was still generated, even if from an empty string
    assert 'url_friendly_name' in all_detailed_threats[0]['mitre_techniques'][0]['defend_mitigations'][0]
    assert all_detailed_threats[0]['mitre_techniques'][0]['defend_mitigations'][0]['url_friendly_name'] == ''