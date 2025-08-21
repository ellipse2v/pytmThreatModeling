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

@patch('threat_analysis.generation.report_generator.get_mitigation_suggestions')
def test_generate_html_report(mock_get_mitigations, report_generator):
    threat_model = MagicMock()
    threat_model.mitre_analysis_results = {
        'total_threats': 1,
        'mitre_techniques_count': 1,
        'stride_distribution': {'S': 1}
    }
    threat_model.tm.name = "Test Architecture"

    # Note: threat_mock no longer has a 'mitigations' attribute
    threat_mock = MagicMock(description="Test Threat", stride_category='S', target=MagicMock(data=MagicMock(classification=MagicMock(name='Public'))))
    # Remove the mitigations attribute since it's no longer used
    if hasattr(threat_mock, 'mitigations'):
        del threat_mock.mitigations


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
            'id': 'T1190',
            'name': 'SQL Injection',
            'defend_mitigations': [],
            'mitre_mitigations': []
        }
    ]

    # Mock the return value of the new mitigation suggestion function
    mock_get_mitigations.return_value = [
        {'framework': 'OWASP ASVS', 'name': 'OWASP Mitigation 1', 'url': 'http://owasp.org'},
        {'framework': 'NIST', 'name': 'NIST Mitigation 1', 'url': 'http://nist.gov'},
        {'framework': 'CIS', 'name': 'CIS Mitigation 1', 'url': 'http://cisecurity.org'},
        {'framework': 'OWASP ASVS', 'name': 'OWASP Mitigation 2', 'url': 'http://owasp.org'},
    ]


    output_file = "test_report.html"
    with patch.object(report_generator.env, 'get_template') as mock_get_template:
        mock_template = MagicMock()
        mock_get_template.return_value = mock_template
        with patch("builtins.open", mock_open()) as mock_file:
            result = report_generator.generate_html_report(threat_model, grouped_threats, output_file)
            mock_file.assert_called_once_with(output_file, "w", encoding="utf-8")

    assert result == output_file

    # Capture the context passed to the template
    render_context = mock_template.render.call_args[1]
    rendered_threats = render_context['all_threats']

    # Assertions
    assert len(rendered_threats) == 1
    threat_details = rendered_threats[0]

    # Verify that custom_mitigations is gone
    assert 'custom_mitigations' not in threat_details

    # Verify the framework-based mitigations are present and correct
    assert 'owasp_mitigations' in threat_details
    assert len(threat_details['owasp_mitigations']) == 2
    assert threat_details['owasp_mitigations'][0]['name'] == 'OWASP Mitigation 1'

    assert 'nist_mitigations' in threat_details
    assert len(threat_details['nist_mitigations']) == 1
    assert threat_details['nist_mitigations'][0]['name'] == 'NIST Mitigation 1'

    assert 'cis_mitigations' in threat_details
    assert len(threat_details['cis_mitigations']) == 1
    assert threat_details['cis_mitigations'][0]['name'] == 'CIS Mitigation 1'

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
    report_generator.mitre_mapping.map_threat_to_capec.return_value = []

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

def test_d3fend_mitigations_have_descriptions(report_generator):
    """
    Tests that D3FEND mitigations processed for the report include their
    descriptions.
    """
    threat_mock = MagicMock(description="Test Threat", stride_category='S', target=MagicMock(data=MagicMock(classification=MagicMock(name='Public'))))
    grouped_threats = {'Spoofing': [(threat_mock, MagicMock(name="Test Target"))]}

    report_generator.severity_calculator.get_severity_info.return_value = {'level': 'Low', 'score': 1.0}

    # Mock the MITRE mapping to return a technique with a D3FEND mitigation that has a description
    report_generator.mitre_mapping.map_threat_to_mitre.return_value = [
        {
            'id': 'T1078',
            'name': 'Valid Accounts',
            'defend_mitigations': [
                {
                    'id': 'D3-DO',
                    'name': 'Decoy Object',
                    'description': 'A Decoy Object is created and deployed for the purposes of deceiving attackers.',
                    'url_friendly_name_source': 'D3-DO Decoy Object'
                }
            ],
            'mitre_mitigations': []
        }
    ]

    # Call the internal method that processes the threats
    all_detailed_threats = report_generator._get_all_threats_with_mitre_info(grouped_threats)

    # Assert that the description is present
    assert len(all_detailed_threats) == 1
    mitre_techniques = all_detailed_threats[0]['mitre_techniques']
    assert len(mitre_techniques) == 1
    d3fend_mitigations = mitre_techniques[0]['defend_mitigations']
    assert len(d3fend_mitigations) == 1
    assert 'description' in d3fend_mitigations[0]
    assert d3fend_mitigations[0]['description'] == 'A Decoy Object is created and deployed for the purposes of deceiving attackers.'