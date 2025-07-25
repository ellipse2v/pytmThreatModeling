
import pytest
from threat_analysis.iac_plugins.ansible_plugin import AnsiblePlugin

@pytest.fixture
def ansible_plugin():
    """Fixture for the AnsiblePlugin."""
    return AnsiblePlugin()

def test_generate_threat_model_components(ansible_plugin):
    """Tests the generation of Markdown components from parsed data."""
    iac_data = {
        "threat_model_metadata": {
            "zones": [
                {"name": "Public", "type": "External", "isTrusted": False},
                {"name": "DMZ", "type": "DMZ", "isTrusted": True}
            ],
            "actors": [
                {"name": "User", "isHuman": True, "boundary": "Public"}
            ],
            "components": [
                {"name": "WebApp", "stereotype": "Server", "boundary": "DMZ"}
            ],
            "data_flows": [
                {
                    "name": "User to WebApp",
                    "source": "actor:User",
                    "destination": "component:WebApp",
                    "protocol": "HTTPS",
                    "data": "Web Traffic"
                }
            ]
        }
    }

    generated_markdown = ansible_plugin.generate_threat_model_components(iac_data)

    assert "## Boundaries" in generated_markdown
    assert "- **Public**: type=External, isTrusted=False" in generated_markdown
    assert "## Actors" in generated_markdown
    assert "- **User**: isHuman=True, boundary=Public" in generated_markdown
    assert "## Servers" in generated_markdown
    assert "- **WebApp**: stereotype=Server, boundary=DMZ" in generated_markdown
    assert "## Dataflows" in generated_markdown
    assert 'from="actor:User", to="component:WebApp", protocol="HTTPS", data="Web Traffic"' in generated_markdown
