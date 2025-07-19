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

from typing import Dict, Any
from threat_analysis.iac_plugins import IaCPlugin

class AnsiblePlugin(IaCPlugin):
    """IaC Plugin for Ansible configurations.

    This plugin will parse Ansible playbooks and inventories
    to extract information relevant for threat modeling.
    """

    @property
    def name(self) -> str:
        return "ansible"

    @property
    def description(self) -> str:
        return "Integrates with Ansible playbooks and inventories to generate threat model components."

    def parse_iac_config(self, config_path: str) -> Dict[str, Any]:
        """Parses Ansible playbooks and inventories.

        Args:
            config_path: Path to the Ansible project root (e.g., directory containing playbooks).

        Returns:
            A dictionary containing parsed Ansible data.
        """
        # TODO: Implement actual Ansible parsing logic here.
        # This will involve reading YAML files, understanding roles, tasks, etc.
        import yaml
        from pathlib import Path

        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Ansible config path not found: {config_path}")

        hosts = set()
        packages = set()
        ports = set()

        if config_path.is_file() and config_path.suffix in ['.yml', '.yaml']:
            with open(config_path, 'r') as f:
                playbook_content = yaml.safe_load(f)

            if isinstance(playbook_content, list):
                for play in playbook_content:
                    if 'hosts' in play:
                        hosts.add(play['hosts'])
                    if 'tasks' in play:
                        for task in play['tasks']:
                            if 'ansible.builtin.apt' in task or 'apt' in task:
                                if 'name' in task['ansible.builtin.apt']:
                                    packages.add(task['ansible.builtin.apt']['name'])
                            elif 'ansible.builtin.ufw' in task or 'ufw' in task:
                                if task['ansible.builtin.ufw'].get('rule') == 'allow' and 'port' in task['ansible.builtin.ufw']:
                                    ports.add(task['ansible.builtin.ufw']['port'])
        else:
            raise ValueError(f"Unsupported Ansible config path: {config_path}. Must be a .yml or .yaml file.")

        return {
            "hosts": list(hosts),
            "packages": list(packages),
            "ports": list(ports)
        }

    def generate_threat_model_components(self, iac_data: Dict[str, Any]) -> str:
        """Generates Markdown threat model components from parsed Ansible data.

        Args:
            iac_data: The data extracted by parse_iac_config.

        Returns:
            A string containing Markdown content for threat model elements.
        """
        # TODO: Implement logic to convert parsed Ansible data into Markdown DSL.
        # This will involve creating Servers, Dataflows, etc., based on Ansible constructs.
        markdown_output = []

        # Add Servers based on hosts
        if iac_data.get("hosts"):
            markdown_output.append("## Servers")
            for host in iac_data["hosts"]:
                markdown_output.append(f"- **{host.replace(' ', '_ ')}**: description=Server managed by Ansible, IaC_Source=Ansible")

        # Add Dataflows based on ports
        if iac_data.get("ports") and iac_data.get("hosts"):
            markdown_output.append("\n## Dataflows")
            for host in iac_data["hosts"]:
                for port in iac_data["ports"]:
                    # Assuming external access for simplicity
                    protocol = "TCP" # Default, could be refined
                    if str(port) == "80":
                        protocol = "HTTP"
                    elif str(port) == "443":
                        protocol = "HTTPS"
                    elif str(port) == "22":
                        protocol = "SSH"

                    markdown_output.append(
                        f"- **ExternalClientTo{host.replace(' ', '_ ')}Port{port}**: from=\"External Client 1\", to=\"{host.replace(' ', '_ ')}\", protocol=\"{protocol}\", data=\"Traffic_on_port_{port}\""
                    )

        # Add Data based on packages and ports (simplified, could be more detailed)
        if iac_data.get("packages") or iac_data.get("ports"):
            markdown_output.append("\n## Data")
            for package in iac_data["packages"]:
                markdown_output.append(f"- **{package.replace(' ', '_ ')}Data**: description=\"{package} related data\", classification=\"PUBLIC\"")
            for port in iac_data["ports"]:
                markdown_output.append(f"- **Traffic_on_port_{port}**: description=\"Network traffic on port {port}\", classification=\"PUBLIC\"")

        return "\n".join(markdown_output)
