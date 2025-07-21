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

import yaml
import configparser
from pathlib import Path
from typing import Dict, Any, List, Set

from threat_analysis.iac_plugins import IaCPlugin

class AnsiblePlugin(IaCPlugin):
    """
    IaC Plugin for Ansible configurations that understands inventories.
    """

    @property
    def name(self) -> str:
        return "ansible"

    @property
    def description(self) -> str:
        return "Integrates with Ansible playbooks and inventories to generate threat model components."

    def _parse_inventory(self, inventory_path: Path) -> Dict[str, Any]:
        """Parses an Ansible inventory file (.ini format)."""
        if not inventory_path.exists():
            raise FileNotFoundError(f"Inventory file not found: {inventory_path}")

        parser = configparser.ConfigParser(allow_no_value=True, delimiters=(' ', '='))
        parser.read(inventory_path)

        inventory_data = {"groups": {}, "hosts": {}}
        
        for section in parser.sections():
            if section.endswith(':children'):
                group_name = section.split(':')[0]
                inventory_data["groups"][group_name] = parser.options(section)
            else:
                hosts = []
                for host, _ in parser.items(section):
                    # Remove ansible vars from host string
                    clean_host = host.split(' ')[0]
                    hosts.append(clean_host)
                    inventory_data["hosts"][clean_host] = {"group": section}
                inventory_data["groups"][section] = hosts
        
        return inventory_data

    def parse_iac_config(self, config_path: str) -> Dict[str, Any]:
        """
        Parses an Ansible playbook and its corresponding inventory.
        Assumes inventory is named 'hosts.ini' and located in the same directory.
        """
        playbook_path = Path(config_path)
        inventory_path = playbook_path.parent / 'hosts.ini'

        if not playbook_path.is_file() or playbook_path.suffix not in ['.yml', '.yaml']:
            raise ValueError(f"Unsupported Ansible config path: {playbook_path}. Must be a .yml or .yaml file.")

        inventory = self._parse_inventory(inventory_path)
        
        with open(playbook_path, 'r') as f:
            playbook_content = yaml.safe_load(f)

        # For simplicity, we're focusing on the inventory structure.
        # A more advanced implementation would map tasks from the playbook to hosts.
        
        return {
            "inventory": inventory,
            "playbook": playbook_content
        }

    def generate_threat_model_components(self, iac_data: Dict[str, Any]) -> str:
        """Generates Markdown threat model components from parsed Ansible data."""
        inventory = iac_data.get("inventory", {})
        hosts_info = inventory.get("hosts", {})
        groups = inventory.get("groups", {})

        markdown = []

        # 1. Define Boundaries from top-level groups
        markdown.append("## Boundaries")
        boundary_colors = {"dmz": "khaki", "internal_network": "lightgreen", "billing": "lightblue", "network_infra": "lightgray"}
        
        # Define boundaries for groups that contain hosts, not just other groups
        host_groups = {details['group'] for details in hosts_info.values()}
        for group in host_groups:
            color = boundary_colors.get(group, "lightgrey")
            markdown.append(f"- **{group}**: color={color}")
        markdown.append("- **Internet**: color=lightcoral")
        markdown.append("")

        # 2. Define Actors
        markdown.append("## Actors")
        markdown.append("- **External_Client**: boundary=Internet, description=Represents external users.")
        markdown.append("- **Admin**: boundary=Internet, description=System administrators managing the infrastructure.")
        markdown.append("")

        # 3. Define Servers and Network Gear from inventory hosts
        markdown.append("## Servers")
        for host, details in hosts_info.items():
            group = details.get("group", "default")
            stereotype = "Network" if group in ["switches", "routers"] else "Server"
            markdown.append(f"- **{host}**: boundary={group}, stereotype={stereotype}")
        markdown.append("")

        # 4. Define Data and Protocols
        markdown.append("## Data")
        markdown.append("- **Web_Traffic**: classification=public")
        markdown.append("- **App_Data**: classification=restricted")
        markdown.append("- **DB_Data**: classification=secret")
        markdown.append("- **SSH_Admin**: classification=secret")
        markdown.append("")

        # 5. Define logical Dataflows
        markdown.append("## Dataflows")
        # External client to DMZ
        markdown.append('- **Client_to_DMZ**: from="External_Client", to="rev-proxy-01", protocol="HTTPS", data="Web_Traffic"')
        
        # DMZ to internal web
        if 'dmz' in groups and 'internal_web' in groups:
            for proxy in groups['dmz']:
                for web_server in groups['internal_web']:
                     markdown.append(f'- **DMZ_to_WebApp_{proxy}_{web_server}**: from="{proxy}", to="{web_server}", protocol="HTTP", data="App_Data"')

        # Internal web to DB
        if 'internal_web' in groups and 'internal_db' in groups:
            for web_server in groups['internal_web']:
                for db_server in groups['internal_db']:
                    markdown.append(f'- **WebApp_to_DB_{web_server}_{db_server}**: from="{web_server}", to="{db_server}", protocol="SQL", data="DB_Data"')

        # Admin access
        for host in hosts_info:
            markdown.append(f'- **Admin_to_{host}**: from="Admin", to="{host}", protocol="SSH", data="SSH_Admin"')
            
        # Billing to Internet (conceptual)
        markdown.append('- **Billing_to_Internet**: from="billing-server-01", to="External_Client", protocol="HTTPS", data="Web_Traffic", description="Represents billing communication with external payment gateways or users."')
        
        return "\n".join(markdown)