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
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
import yaml

from threat_analysis.iac_plugins.ansible_plugin import AnsiblePlugin

# Path to the sample Ansible playbook for testing
SAMPLE_ANSIBLE_PLAYBOOK = Path(__file__).parent / "ansible_playbooks" / "simple_web_server.yml"

@pytest.fixture
def ansible_plugin():
    return AnsiblePlugin()

def test_ansible_plugin_name_and_description(ansible_plugin):
    assert ansible_plugin.name == "ansible"
    assert "Ansible playbooks" in ansible_plugin.description

def test_parse_iac_config_success(ansible_plugin):
    # Mock yaml.safe_load to return a predefined playbook structure
    mock_playbook_content = [
        {
            'name': 'Setup a simple web server',
            'hosts': 'webservers',
            'become': True,
            'tasks': [
                {'name': 'Install Nginx', 'ansible.builtin.apt': {'name': 'nginx', 'state': 'present'}},
                {'name': 'Allow HTTP traffic on port 80', 'ansible.builtin.ufw': {'rule': 'allow', 'port': '80', 'proto': 'tcp'}},
                {'name': 'Allow HTTPS traffic on port 443', 'ansible.builtin.ufw': {'rule': 'allow', 'port': '443', 'proto': 'tcp'}},
            ]
        }
    ]

    # Create a mock Path object
    mock_path_instance = MagicMock()
    mock_path_instance.exists.return_value = True
    mock_path_instance.is_file.return_value = True
    mock_path_instance.suffix = '.yml'

    with patch('builtins.open', mock_open(read_data=yaml.dump(mock_playbook_content))):
        with patch('pathlib.Path', return_value=mock_path_instance) as mock_path_class:
            # Ensure that Path(config_path) returns our mock_path_instance
            mock_path_class.return_value = mock_path_instance
            parsed_data = ansible_plugin.parse_iac_config(str(SAMPLE_ANSIBLE_PLAYBOOK))

            assert "hosts" in parsed_data
            assert "packages" in parsed_data
            assert "ports" in parsed_data

            assert "webservers" in parsed_data["hosts"]
            assert "nginx" in parsed_data["packages"]
            assert "80" in parsed_data["ports"]
            assert "443" in parsed_data["ports"]

def test_generate_threat_model_components(ansible_plugin):
    iac_data = {
        "hosts": ["webservers"],
        "packages": ["nginx"],
        "ports": ["80", "443"]
    }
    generated_markdown = ansible_plugin.generate_threat_model_components(iac_data)

    expected_markdown_parts = [
        "## Servers",
        "- **webservers**: description=Server managed by Ansible, IaC_Source=Ansible",
        "## Dataflows",
        "- **ExternalClientTowebserversPort80**: from=\"External Client 1\", to=\"webservers\", protocol=\"HTTP\", data=\"Traffic_on_port_80\"",
        "- **ExternalClientTowebserversPort443**: from=\"External Client 1\", to=\"webservers\", protocol=\"HTTPS\", data=\"Traffic_on_port_443\"",
        "## Data",
        "- **nginxData**: description=\"nginx related data\", classification=\"PUBLIC\"",
        "- **Traffic_on_port_80**: description=\"Network traffic on port 80\", classification=\"PUBLIC\"",
        "- **Traffic_on_port_443**: description=\"Network traffic on port 443\", classification=\"PUBLIC\"",
    ]

    for part in expected_markdown_parts:
        assert part in generated_markdown

def test_parse_iac_config_file_not_found(ansible_plugin):
    mock_path_instance = MagicMock()
    mock_path_instance.exists.return_value = False # Simulate file not found

    with patch('pathlib.Path', return_value=mock_path_instance) as mock_path_class:
        mock_path_class.return_value = mock_path_instance
        with pytest.raises(FileNotFoundError, match="Ansible config path not found"):
            ansible_plugin.parse_iac_config("/non/existent/path/playbook.yml")

def test_parse_iac_config_unsupported_file_type(ansible_plugin):
    mock_path_instance = MagicMock()
    mock_path_instance.exists.return_value = True
    mock_path_instance.is_file.return_value = True
    mock_path_instance.suffix = '.txt' # Simulate unsupported file type

    with patch('pathlib.Path', return_value=mock_path_instance) as mock_path_class:
        mock_path_class.return_value = mock_path_instance
        with pytest.raises(ValueError, match="Unsupported Ansible config path"):
            ansible_plugin.parse_iac_config("/fake/path/config.txt")
