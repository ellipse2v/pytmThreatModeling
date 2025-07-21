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
import yaml

from threat_analysis.iac_plugins.ansible_plugin import AnsiblePlugin

# Sample inventory content for tests
SAMPLE_INVENTORY_CONTENT = """
[webservers]
web-01 ansible_host=192.168.1.10

[dbservers]
db-01 ansible_host=192.168.1.20
"""

# Sample playbook content for tests
SAMPLE_PLAYBOOK_CONTENT = """
- name: Configure web server
  hosts: webservers
  tasks:
    - name: Install nginx
      ansible.builtin.apt:
        name: nginx
        state: present
"""

@pytest.fixture
def ansible_plugin():
    """Fixture for the AnsiblePlugin."""
    return AnsiblePlugin()

@pytest.fixture
def ansible_test_env(tmp_path):
    """Creates a temporary ansible environment with a playbook and inventory."""
    playbook_path = tmp_path / "playbook.yml"
    inventory_path = tmp_path / "hosts.ini"

    playbook_path.write_text(SAMPLE_PLAYBOOK_CONTENT)
    inventory_path.write_text(SAMPLE_INVENTORY_CONTENT)
    
    return playbook_path

def test_plugin_name_and_description(ansible_plugin):
    """Tests the plugin's name and description."""
    assert ansible_plugin.name == "ansible"
    assert "Ansible playbooks and inventories" in ansible_plugin.description

def test_parse_iac_config_success(ansible_plugin, ansible_test_env):
    """Tests successful parsing of a playbook and its inventory."""
    parsed_data = ansible_plugin.parse_iac_config(str(ansible_test_env))

    assert "inventory" in parsed_data
    assert "playbook" in parsed_data

    # Check inventory parsing
    inventory = parsed_data["inventory"]
    assert "webservers" in inventory["groups"]
    assert "dbservers" in inventory["groups"]
    assert "web-01" in inventory["groups"]["webservers"]
    assert "db-01" in inventory["hosts"]
    assert inventory["hosts"]["db-01"]["group"] == "dbservers"

    # Check playbook parsing
    playbook = parsed_data["playbook"]
    assert playbook[0]["name"] == "Configure web server"

def test_parse_iac_config_inventory_not_found(ansible_plugin, tmp_path):
    """Tests that parsing fails if the inventory file is missing."""
    playbook_path = tmp_path / "playbook.yml"
    playbook_path.write_text(SAMPLE_PLAYBOOK_CONTENT)
    
    with pytest.raises(FileNotFoundError, match="Inventory file not found"):
        ansible_plugin.parse_iac_config(str(playbook_path))

def test_parse_iac_config_unsupported_file_type(ansible_plugin, tmp_path):
    """Tests that parsing fails for unsupported playbook file types."""
    unsupported_file = tmp_path / "playbook.txt"
    unsupported_file.write_text("This is not a playbook.")

    with pytest.raises(ValueError, match="Unsupported Ansible config path"):
        ansible_plugin.parse_iac_config(str(unsupported_file))

def test_generate_threat_model_components(ansible_plugin):
    """Tests the generation of Markdown components from parsed data."""
    iac_data = {
        "inventory": {
            "groups": {
                "webservers": ["web-01"],
                "dbservers": ["db-01"],
                "dmz": ["rev-proxy-01"]
            },
            "hosts": {
                "web-01": {"group": "webservers"},
                "db-01": {"group": "dbservers"},
                "rev-proxy-01": {"group": "dmz"}
            }
        }
    }
    
    generated_markdown = ansible_plugin.generate_threat_model_components(iac_data)

    # Check for boundaries
    assert "- **dmz**: color=khaki" in generated_markdown
    assert "- **webservers**: color=lightgrey" in generated_markdown
    
    # Check for actors
    assert "- **Admin**: boundary=Internet" in generated_markdown

    # Check for servers
    assert "- **rev-proxy-01**: boundary=dmz, stereotype=Server" in generated_markdown
    assert "- **web-01**: boundary=webservers, stereotype=Server" in generated_markdown

    # Check for dataflows
    assert '- **Admin_to_web-01**: from="Admin", to="web-01", protocol="SSH", data="SSH_Admin"' in generated_markdown