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
# # In threat_analysis/model_parser.py

import re
import logging
from typing import List, Dict, Any, Callable, Optional, Tuple, Set
from .models_module import ThreatModel, CustomThreat
from .mitre_mapping_module import MitreMapping
from pytm import Classification, Lifetime


class ModelParser:
    """
    Parses a threat model defined in Markdown and constructs a ThreatModel object.
    """
    def __init__(self, threat_model: ThreatModel, mitre_mapping: MitreMapping):
        self.threat_model = threat_model
        self.mitre_mapping = mitre_mapping
        self.current_section = None
        self.section_parsers: Dict[str, Callable[[str], None]] = {
            "## Boundaries": self._parse_boundary,
            "## Actors": self._parse_actor,
            "## Servers": self._parse_server,
            "## Data": self._parse_data,             
            "## Dataflows": self._parse_dataflow,
            "## Protocol Styles": self._parse_protocol_style,
            "## Severity Multipliers": self._parse_severity_multiplier,
            "## Custom Mitre Mapping": self._parse_custom_mitre
        }
                # Mappings of string literals to PyTM enums
        self.classification_map = {
            "UNKNOWN": Classification.UNKNOWN,
            "PUBLIC": Classification.PUBLIC,
            "SECRET": Classification.SECRET,
            "TOP_SECRET": Classification.TOP_SECRET,
            "RESTRICTED": Classification.RESTRICTED,
        }

        self.lifetime_map = {
            "NONE": Lifetime.NONE,
            "UNKNOWN": Lifetime.UNKNOWN,
            "SHORT": Lifetime.SHORT,
            "LONG": Lifetime.LONG,
            "AUTO": Lifetime.AUTO,
            "MANUAL": Lifetime.MANUAL,
            "HARDCODED": Lifetime.HARDCODED,
        }

    def parse_markdown(self, markdown_content: str):
        """
        Parses Markdown content line by line.
        """
        lines = markdown_content.splitlines()
        for line in lines:
            stripped_line = line.strip()
            if not stripped_line:
                continue

            # Check if it's a section header (## or ###)
            if stripped_line.startswith("## ") or stripped_line.startswith("### "):
                # Normalize the section title for matching
                section_title = stripped_line
                if section_title in self.section_parsers:
                    self.current_section = section_title
                    logging.info(f"⏳ Loading section: {self.current_section}")
                else:
                    # Unrecognized section, ignore it but set current_section to None
                    self.current_section = None
                    logging.info(f"ℹ️ Section ignored: {section_title}")
                continue

            # If we are in a recognized section, call the appropriate parser
            if self.current_section and self.current_section in self.section_parsers:
                self.section_parsers[self.current_section](stripped_line)
            elif self.current_section:
                # Ignore lines in explicitly unhandled sections
                pass

    def _parse_boundary(self, line: str):
        """Parses a boundary line with format: - **name**: color=value, isTrusted=bool, isFilled=bool"""
        # Updated regex to capture name and all parameters
        match = re.match(r'^- \*\*([^\*:]+)\*\*:\s*(.*)', line)
        if match:
            name = match.group(1).strip()
            params_str = match.group(2).strip()
            
            # Parse all key=value parameters
            boundary_kwargs = self._parse_key_value_params(params_str)
            
            # Set default color if not specified
            if 'color' not in boundary_kwargs:
                boundary_kwargs['color'] = 'lightgray'
            
            self.threat_model.add_boundary(name, **boundary_kwargs)
            
            # Create a nice log message
            params_display = []
            for key, value in boundary_kwargs.items():
                params_display.append(f"{key.capitalize()}: {value}")
            
            logging.info(f"   - Added Boundary: {name} ({', '.join(params_display)})")
        else:
            logging.warning(f"⚠️ Warning: Malformed boundary line: {line}")

    def _parse_actor(self, line: str):
        """Parses an actor line with flexible key=value attributes."""
        match = re.match(r'^- \*\*([^\*]+)\*\*:\s*(.*)', line)
        if match:
            actor_name = match.group(1).strip()
            params_str = match.group(2).strip()
            actor_kwargs = self._parse_key_value_params(params_str)
            boundary_name = actor_kwargs.pop('boundary', "")
            color = actor_kwargs.pop('color', None)
            is_filled = actor_kwargs.pop('isFilled', None)
            self.threat_model.add_actor(
                actor_name,
                boundary_name,
                color=color,
                is_filled=is_filled
            )
        else:
            logging.warning(f"⚠️ Warning: Malformed actor line: {line}")

    def _parse_server(self, line: str):
        """Parses a server line with format: - **name**: boundary=value, color=value, isFilled=bool"""
        # Match server name and all parameters after colon
        match = re.match(r'^- \*\*([^\*:]+)\*\*:\s*(.*)', line)
        if match:
            name = match.group(1).strip()
            params_str = match.group(2).strip()
            # Parse all key=value parameters
            server_kwargs = self._parse_key_value_params(params_str)
            boundary_name = server_kwargs.pop('boundary', "")
            color = server_kwargs.pop('color', None)
            is_filled = server_kwargs.pop('isFilled', None)
            # Call add_server with extracted parameters
            self.threat_model.add_server(
                name,
                boundary_name,
                color=color,
                is_filled=is_filled
            )
            logging.info(f"   - Added Server: {name} (Boundary: {boundary_name}, Color: {color}, Filled: {is_filled})")
        else:
            logging.warning(f"⚠️ Warning: Malformed server line: {line}")
            
    def _parse_key_value_params(self, params_str: str) -> Dict[str, Any]:
        """
        Parses a key=value parameter string and returns a dictionary.
        Handles quoted strings, booleans, numbers, hex colors, and unquoted strings.
        """
        params = {}
        # This regex matches key=value pairs, where value can be quoted or unquoted (including hex colors)
        param_pattern = re.compile(
            r'(\w+)\s*=\s*'                # key=
            r'(?:'                         # non-capturing group for value
                r'"([^"]*)"'               #   "quoted string"
                r'|'
                r'(#?\w+)'                 #   unquoted value (including #hex)
            r')'
        )
        for m in param_pattern.finditer(params_str):
            key = m.group(1)
            value_quoted = m.group(2)
            value_unquoted = m.group(3)
            if value_quoted is not None:
                value = value_quoted
            elif value_unquoted is not None:
                # Handle booleans
                if value_unquoted.lower() == 'true':
                    value = True
                elif value_unquoted.lower() == 'false':
                    value = False
                else:
                    try:
                        value = float(value_unquoted)
                    except ValueError:
                        value = value_unquoted
            else:
                continue
            params[key] = value
        return params

    def _parse_data(self, line: str):
        """Parses a line to define a Data object, extracting all properties."""
        # The regex captures the name between ** and the rest of the line as a parameter string
        match = re.match(r'^- \*\*([^\*]+)\*\*:\s*(.*)', line)
        if match:
            name = match.group(1).strip()
            params_str = match.group(2).strip()
            data_kwargs = self._parse_key_value_params(params_str) # Extract key=value

            # Convert strings to PyTM enum objects
            if "classification" in data_kwargs:
                enum_str = data_kwargs["classification"].upper()
                data_kwargs["classification"] = self.classification_map.get(enum_str, Classification.UNKNOWN)
                if enum_str not in self.classification_map:
                    logging.warning(f"⚠️ Warning: Classification '{enum_str}' not recognized for Data '{name}'. Set to UNKNOWN.")

            if "credentialsLife" in data_kwargs:
                enum_str = data_kwargs["credentialsLife"].upper()
                data_kwargs["credentialsLife"] = self.lifetime_map.get(enum_str, Lifetime.UNKNOWN)
                if enum_str not in self.lifetime_map:
                    logging.warning(f"⚠️ Warning: Lifetime '{enum_str}' not recognized for Data '{name}'. Set to UNKNOWN.")
            
            # Call add_data by unpacking the properties dictionary
            self.threat_model.add_data(name, **data_kwargs)
            
            # Create a nice log message
            params_display = []
            for key, value in data_kwargs.items():
                if hasattr(value, 'name'):  # For enum objects
                    params_display.append(f"{key}: {value.name}")
                else:
                    params_display.append(f"{key}: {value}")
            
            logging.info(f"   - Added Data: {name} ({', '.join(params_display)})")
        else:
            logging.warning(f"⚠️ Warning: Malformed data line: {line}")

    def _parse_dataflow(self, line: str):
        """Parses a dataflow line with flexible named arguments."""
        # First, extract the dataflow name
        name_match = re.match(r'^- \*\*([^\*]+)\*\*:\s*(.*)', line)
        if not name_match:
            logging.warning(f"⚠️ Warning: Malformed dataflow line (missing name): {line}")
            return

        name = name_match.group(1).strip()
        params_str = name_match.group(2).strip()

        # Parse key="value" or key=True/False pairs
        params = {}
        # Regex to find key="value" (groups 1,2) OR key=True/False (groups 3,4)
        param_pattern = re.compile(r'(\w+)="([^"]*)"|\s*(\w+)=(True|False)')
        for m in param_pattern.finditer(params_str):
            if m.group(1):  # Matches key="value"
                key = m.group(1)
                value = m.group(2)
            else:  # Matches key=True/False
                key = m.group(3)
                value = (m.group(4) == 'True')  # Convert to actual boolean

            params[key] = value

        from_name = params.get("from")
        to_name = params.get("to")
        protocol = params.get("protocol")
        data_name = params.get("data")  # Extract the data argument
        is_authenticated = params.get("is_authenticated", False)
        is_encrypted = params.get("is_encrypted", False)

        if not all([from_name, to_name, protocol]):
            logging.warning(f"⚠️ Warning: Dataflow '{name}' is missing mandatory parameters (from, to, protocol).")
            return

        from_elem = self.threat_model.get_element_by_name(from_name)
        to_elem = self.threat_model.get_element_by_name(to_name)

        if from_elem and to_elem:
            self.threat_model.add_dataflow(
                from_elem, to_elem, name, protocol,
                data_name=data_name,  # Pass data_name
                is_authenticated=is_authenticated,
                is_encrypted=is_encrypted
            )
            logging.info(f"   - Added Dataflow: {name} ({from_name} -> {to_name}, Proto: {protocol}" +
                      (f", Data: {data_name}" if data_name else "") +
                      (f", Authenticated: {is_authenticated}" if is_authenticated else "") +
                      (f", Encrypted: {is_encrypted}" if is_encrypted else "") + ")")
        else:
            logging.warning(f"⚠️ Warning: Elements '{from_name}' or '{to_name}' not found for dataflow '{name}'.")
            
    def _parse_protocol_style(self, line: str):
        """Parses a protocol style line with format: - **protocol**: color=value, line_style=value"""
        match = re.match(r'^- \*\*([^\*:]+)\*\*:\s*(.*)', line)
        if match:
            protocol_name = match.group(1).strip()
            params_str = match.group(2).strip()
            
            # Parse all key=value parameters
            style_kwargs = self._parse_key_value_params(params_str)
            
            # Call add_protocol_style method if it exists
            if hasattr(self.threat_model, 'add_protocol_style'):
                self.threat_model.add_protocol_style(protocol_name, **style_kwargs)
                
                # Create a nice log message
                params_display = []
                for key, value in style_kwargs.items():
                    params_display.append(f"{key}: {value}")
                
                logging.info(f"   - Added Protocol Style: {protocol_name} ({', '.join(params_display)})")
            else:
                logging.info(f"ℹ️ Protocol Style ignored (method not implemented): {protocol_name}")
        else:
            logging.warning(f"⚠️ Warning: Malformed protocol style line: {line}")

    def _parse_severity_multiplier(self, line: str):
        """Parses a severity multiplier line."""
        match = re.match(r'^- \*\*([^\*]+)\*\*:\s*([0-9.]+)', line)
        if match:
            element_name = match.group(1).strip()
            multiplier = float(match.group(2).strip())
            # Assume there is an add_severity_multiplier method
            if hasattr(self.threat_model, 'add_severity_multiplier'):
                self.threat_model.add_severity_multiplier(element_name, multiplier)
                logging.info(f"   - Added Severity Multiplier: {element_name} = {multiplier}")
            else:
                logging.info(f"ℹ️ Severity Multiplier ignored (method not implemented): {element_name} = {multiplier}")
        else:
            logging.warning(f"⚠️ Warning: Malformed severity multiplier line: {line}")

    def _parse_custom_mitre(self, line: str):
        """Parses a custom MITRE mapping line."""
        # Expected format: - **Attack Name**: tactics=["tactic1", "tactic2"], techniques=[{"id": "T1234", "name": "Attack Name"}]
        match = re.match(r'^- \*\*([^\*]+)\*\*:\s*(.*)', line)
        if match:
            attack_name = match.group(1).strip()
            params_str = match.group(2).strip()
            
            # Parse tactics and techniques arrays (this is a simplified version)
            tactics = []
            techniques = []
            
            # Extract tactics array
            tactics_match = re.search(r'tactics=\[(.*?)\]', params_str)
            if tactics_match:
                tactics_str = tactics_match.group(1)
                # Extract quoted strings from the array
                tactics = [t.strip('"') for t in re.findall(r'"([^"]*)"', tactics_str)]
            
            # Extract techniques array (simplified - just extract IDs and names)
            techniques_match = re.search(r'techniques=\[(.*?)\]', params_str)
            if techniques_match:
                techniques_str = techniques_match.group(1)
                # Find all technique objects
                technique_objects = re.findall(r'\{[^}]*\}', techniques_str)
                for tech_obj in technique_objects:
                    id_match = re.search(r'"id":\s*"([^"]*)"', tech_obj)
                    name_match = re.search(r'"name":\s*"([^"]*)"', tech_obj)
                    if id_match and name_match:
                        techniques.append({
                            "id": id_match.group(1),
                            "name": name_match.group(1)
                        })
            
            # Call add_custom_mitre_mapping method if it exists
            if hasattr(self.threat_model, 'add_custom_mitre_mapping'):
                self.threat_model.add_custom_mitre_mapping(attack_name, tactics, techniques)
                logging.info(f"   - Added Custom MITRE Mapping: {attack_name} (Tactics: {len(tactics)}, Techniques: {len(techniques)})")
            else:
                logging.warning(f"⚠️ Warning: Malformed custom MITRE mapping line: {line}")
        else:
            logging.warning(f"⚠️ Warning: Malformed custom MITRE mapping line: {line}")
            

    def _apply_custom_threats(self) -> Tuple[List[Tuple[CustomThreat, Any]], Set[Any]]:
        """
        Applies custom threats to the threat model and returns them along with the elements they cover.
        """
        
        custom_threat_definitions = self.mitre_mapping.get_custom_threats()
        
        generated_custom_threats = []
        elements_with_custom_threats = set()

        # Apply threats to servers
        for server_info in self.threat_model.servers:
            server = server_info['object']
            for threat_template in custom_threat_definitions.get("servers", []):
                threat_name = threat_template["name"].format(server_name=server.name)
                
                custom_threat = CustomThreat(
                    name=threat_name,
                    description=threat_template["description"],
                    stride_category=threat_template["stride_category"],
                    mitre_technique_id=threat_template["mitre_technique_id"],
                    target=server # The target is the actual PyTM object
                )
                
                generated_custom_threats.append((custom_threat, server))
                elements_with_custom_threats.add(server)
                

        # Apply threats to dataflows
        for dataflow in self.threat_model.dataflows:
            for threat_template in custom_threat_definitions.get("dataflows", []):
                threat_name = threat_template["name"].format(dataflow_name=dataflow.name)
                
                custom_threat = CustomThreat(
                    name=threat_name,
                    description=threat_template["description"],
                    stride_category=threat_template["stride_category"],
                    mitre_technique_id=threat_template["mitre_technique_id"],
                    target=dataflow # The target is the actual PyTM object
                )
                
                generated_custom_threats.append((custom_threat, dataflow))
                elements_with_custom_threats.add(dataflow)
                
        
        return generated_custom_threats, elements_with_custom_threats