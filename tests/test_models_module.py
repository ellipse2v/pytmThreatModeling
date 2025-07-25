import pytest
from unittest.mock import MagicMock, patch
from threat_analysis.core.models_module import ThreatModel, CustomThreat
from threat_analysis.core.mitre_mapping_module import MitreMapping
from pytm import TM, Boundary, Actor, Server, Dataflow, Data, Classification, Lifetime

class MockPyTMThreat:
    def __init__(self, name, target, stride_category="Spoofing"):
        self.name = name
        self.target = target
        self.stride_category = stride_category
        self.__dict__ = {"name": name, "target": target, "stride_category": stride_category}

@pytest.fixture
def threat_model_instance():
    with patch('threat_analysis.core.models_module.MitreMapping') as MockMitreMapping:
        with patch('threat_analysis.core.models_module.TM') as MockTM:
            tm = ThreatModel(name="Test Model", description="A model for testing")
            tm.add_boundary("Internet", isTrusted=False)
            tm.add_boundary("Internal Network", isTrusted=True)
            tm.add_actor("User", boundary_name="Internet", isHuman=True)
            tm.add_server("WebServer", boundary_name="Internal Network", stereotype="Server")
            tm.add_data("Credentials", classification=Classification.RESTRICTED, lifetime=Lifetime.LONG)
            tm.add_dataflow(
                tm.get_element_by_name("User"),
                tm.get_element_by_name("WebServer"),
                "Login Flow",
                "HTTPS",
                data_name="credentials",
                is_authenticated=True,
                is_encrypted=True
            )
            yield tm

def test_process_threats_full_flow(threat_model_instance):
    # Configure mocks
    mock_tm_instance = threat_model_instance.tm

    # Define the threats that PyTM's process() method would generate
    # These will be assigned to mock_tm_instance._threats
    pytm_generated_threats = [
        MockPyTMThreat(name="PyTM Spoofing Threat", target=threat_model_instance.get_element_by_name("User"), stride_category="Spoofing"),
        MockPyTMThreat(name="PyTM Tampering Threat", target=threat_model_instance.get_element_by_name("WebServer"), stride_category="Tampering"),
        MockPyTMThreat(name="PyTM Server Class Threat", target=Server, stride_category="Elevation of Privilege")
    ]

    # Mock the process method of the TM instance to set _threats
    def mock_process():
        mock_tm_instance._threats = pytm_generated_threats
    mock_tm_instance.process.side_effect = mock_process

    mock_mitre_mapper_instance = threat_model_instance.mitre_mapper
    mock_mitre_mapper_instance.analyze_pytm_threats_list.return_value = {
        "processed_threats": [
            # Threats from PyTM (after expansion)
            {"threat_name": "PyTM Spoofing Threat", "stride_category": "Spoofing", "mitre_tactics": ["Initial Access"], "mitre_techniques": [{"id": "T1566", "name": "Phishing"}], "target": threat_model_instance.get_element_by_name("User")},
            {"threat_name": "PyTM Tampering Threat", "stride_category": "Tampering", "mitre_tactics": ["Defense Evasion"], "mitre_techniques": [{"id": "T1055", "name": "Process Injection"}], "target": threat_model_instance.get_element_by_name("WebServer")},
            {"threat_name": "PyTM Server Class Threat", "stride_category": "Elevation of Privilege", "mitre_tactics": ["Privilege Escalation"], "mitre_techniques": [{"id": "T1068", "name": "Exploitation for Privilege Escalation"}], "target": threat_model_instance.get_element_by_name("WebServer")}
        ]
    }

    # Add a custom threat that will be expanded
    # This will now use the mocked mitre_mapper
    # threat_model_instance.mitre_mapper.custom_threats = {
    #     "servers": [
    #         {"name": "Custom Server Threat", "description": "Custom threat for server", "stride_category": "T", "mitre_technique_id": "T1000"}
    #     ]
    # }

    with patch('threat_analysis.custom_threats.get_custom_threats') as mock_get_custom_threats:
        mock_get_custom_threats.return_value = [
            {"component": "WebServer", "description": "Custom threat for server", "stride_category": "T", "severity": "High"}
        ]

        # Call the method under test
        import sys
        original_argv = sys.argv
        sys.argv = [original_argv[0]] # Reset sys.argv to avoid pytest arguments interfering with pytm
        try:
            grouped_threats = threat_model_instance.process_threats()
        finally:
            sys.argv = original_argv # Restore sys.argv

    # Assertions
    mock_tm_instance.process.assert_called_once() # Check if pytm.TM.process was called
    mock_mitre_mapper_instance.analyze_pytm_threats_list.assert_called_once() # Check if MITRE analysis was called

    assert "Spoofing" in grouped_threats
    assert len(grouped_threats["Spoofing"]) == 1
    assert grouped_threats["Spoofing"][0][0].name == "PyTM Spoofing Threat"

    assert "Tampering" in grouped_threats
    assert len(grouped_threats["Tampering"]) == 1
    assert grouped_threats["Tampering"][0][0].name == "PyTM Tampering Threat"

    assert "Elevation of Privilege" in grouped_threats
    assert len(grouped_threats["Elevation of Privilege"]) == 1
    assert grouped_threats["Elevation of Privilege"][0][0].name == "PyTM Server Class Threat"

    # Check custom threats are processed and expanded
    assert "T" in grouped_threats # Assuming 'T' is the category for custom server threats
    assert len(grouped_threats["T"]) == 1 # Should be one custom threat for WebServer
    assert grouped_threats["T"][0][0].name == "Custom threat for server"
    assert grouped_threats["T"][0][1].name == "WebServer"

    # Test _perform_mitre_analysis
    assert "PyTM Spoofing Threat_User" in threat_model_instance.threat_mitre_mapping
    assert threat_model_instance.mitre_analysis_results is not None

    # Test get_statistics
    stats = threat_model_instance.get_statistics()
    assert stats["total_threats"] == 4 # PyTM Spoofing + PyTM Tampering + PyTM Server Class Threat (expanded) + Custom Server Threat
    assert stats["threat_types"] == 4 # Spoofing, Tampering, Elevation of Privilege, T
    assert stats["actors"] == 1
    assert stats["servers"] == 1
    assert stats["dataflows"] == 1
    assert stats["boundaries"] == 2
    assert stats["protocol_styles"] == 0 # No protocol styles added in this test
    assert stats["mitre_techniques_count"] == 0 # Mocked, so 0

def test_group_threats_with_unresolved_targets(threat_model_instance):
    threat_model_instance.threats_raw.append((MagicMock(stride_category="Unresolved"), None))
    grouped_threats_unresolved = threat_model_instance._group_threats()
    assert "Unresolved" not in grouped_threats_unresolved