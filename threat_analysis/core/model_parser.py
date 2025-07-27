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
import ast


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
        Parses Markdown content in two passes: first for elements, then for relationships.
        """
        lines = markdown_content.splitlines()
        
        # First Pass: Parse Boundaries, Actors, Servers, and Data
        element_sections = {
            "## Boundaries": self._parse_boundary,
            "## Actors": self._parse_actor,
            "## Servers": self._parse_server,
            "## Data": self._parse_data,
        }
        self._process_sections(lines, element_sections)

        # Second Pass: Parse Dataflows, Protocol Styles, Severity Multipliers, Custom Mitre Mapping
        # These sections rely on elements defined in the first pass.
        relationship_sections = {
            "## Dataflows": self._parse_dataflow,
            "## Protocol Styles": self._parse_protocol_style,
            "## Severity Multipliers": self._parse_severity_multiplier,
            "## Custom Mitre Mapping": self._parse_custom_mitre,
        }
        self._process_sections(lines, relationship_sections)

    def _process_sections(self, lines: List[str], parsers: Dict[str, Callable[[str, int], None]]):
        """
        Helper method to process specific sections of the Markdown content.
        """
        current_section = None
        # Stack to keep track of parent boundaries for nested structures
        boundary_stack: List[Tuple[str, int]] = [] # (boundary_name, indentation_level)

        for line in lines:
            stripped_line = line.strip()
            if not stripped_line:
                continue

            indentation = len(line) - len(line.lstrip())

            if stripped_line.startswith("## ") or stripped_line.startswith("### "):
                section_title = stripped_line
                if section_title in parsers:
                    current_section = section_title
                    logging.info(f"⏳ Loading section: {current_section}")
                    # Reset boundary stack when a new section starts
                    boundary_stack = []
                else:
                    current_section = None
                    # Only log ignored sections once per section type
                    if section_title not in self.section_parsers: # Avoid re-logging already handled sections
                        logging.info(f"ℹ️ Section ignored: {section_title}")
                continue

            if current_section and current_section in parsers:
                if current_section == "## Boundaries":
                    self._parse_boundary(line, indentation, boundary_stack)
                else:
                    # For other sections, just pass the stripped line
                    parsers[current_section](stripped_line)

    def _parse_boundary(self, line: str, indentation: int, boundary_stack: List[Tuple[str, int]]):
        """Parses a boundary line with format: - **name**: color=value, isTrusted=bool, isFilled=bool"""
        match = re.match(r'^- \*\*([^\*:]+)\*\*:\s*(.*)', line.strip())
        if match:
            name = match.group(1).strip()
            params_str = match.group(2).strip()
            boundary_kwargs = self._parse_key_value_params(params_str)
            if 'color' not in boundary_kwargs:
                boundary_kwargs['color'] = 'lightgray'
            parent_obj = None
            while boundary_stack and boundary_stack[-1][1] >= indentation:
                boundary_stack.pop()
            if boundary_stack:
                parent_name = boundary_stack[-1][0]
                parent_obj = self.threat_model.boundaries.get(parent_name, {}).get('boundary')
            self.threat_model.add_boundary(name, parent_boundary_obj=parent_obj, **boundary_kwargs)
            boundary_stack.append((name, indentation))

    def _parse_actor(self, line: str):
        """Parses an actor line with flexible key=value attributes."""
        match = re.match(r'^- \*\*([^\*]+)\*\*:\s*(.*)', line)
        if match:
            actor_name = match.group(1).strip()
            params_str = match.group(2).strip()
            actor_kwargs = self._parse_key_value_params(params_str)
            boundary_name = actor_kwargs.pop('boundary', None)
            self.threat_model.add_actor(actor_name, boundary_name=boundary_name, **actor_kwargs)
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
            boundary_name = server_kwargs.pop('boundary', None)
            self.threat_model.add_server(name, boundary_name=boundary_name, **server_kwargs)
            logging.info(f"   - Added Server: {name} (Boundary: {boundary_name}, Props: {server_kwargs})")
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
                r'([^,]+)'                  #   unquoted value (anything until comma or end of string)
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
        if not match:
            logging.warning(f"⚠️ Warning: Malformed data line: {line}")
            return

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

    def _parse_dataflow(self, line: str):
        """Parses a dataflow line with flexible named arguments."""
        name_match = re.match(r'^- \*\*([^\*]+)\*\*:\s*(.*)', line)
        if not name_match:
            logging.warning(f"⚠️ Warning: Malformed dataflow line (missing name): {line}")
            return

        name = name_match.group(1).strip()
        params_str = name_match.group(2).strip()
        params = self._parse_key_value_params(params_str)

        from_name = params.get("from").lower().replace("actor:", "").replace("component:", "").replace("zone:", "")
        to_name = params.get("to").lower().replace("actor:", "").replace("component:", "").replace("zone:", "")
        protocol = params.get("protocol")
        data_name = params.get("data")
        is_authenticated = params.get("is_authenticated", False)
        is_encrypted = params.get("is_encrypted", False)

        if not all([from_name, to_name, protocol]):
            logging.warning(f"⚠️ Warning: Dataflow '{name}' is missing mandatory parameters (from, to, protocol).")
            return

        from_elem = self.threat_model.get_element_by_name(from_name) or self.threat_model.boundaries.get(from_name, {}).get('boundary')
        to_elem = self.threat_model.get_element_by_name(to_name) or self.threat_model.boundaries.get(to_name, {}).get('boundary')

        if from_elem and to_elem:
            self.threat_model.add_dataflow(
                from_elem, to_elem, name, protocol,
                data_name=data_name.lower(),
                is_authenticated=is_authenticated,
                is_encrypted=is_encrypted
            )
            logging.info(f"   - Added Dataflow: {name} ({from_name} -> {to_name}, Proto: {protocol}, Data: {data_name})")
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
        if not match:
            logging.warning(f"⚠️ Warning: Malformed custom MITRE mapping line: {line}")
            return

        attack_name = match.group(1).strip()
        params_str = match.group(2).strip()
        
        # Parse tactics and techniques arrays using ast.literal_eval
        try:
            parsed_mapping = ast.literal_eval(params_str)
            tactics = parsed_mapping.get('tactics', [])
            techniques = parsed_mapping.get('techniques', [])
        except (SyntaxError, ValueError) as e:
            logging.error(f"Error evaluating custom MITRE mapping for '{attack_name}': {e}")
            tactics = []
            techniques = []
        
        # Call add_custom_mitre_mapping method if it exists
        if hasattr(self.threat_model, 'add_custom_mitre_mapping'):
            self.threat_model.add_custom_mitre_mapping(attack_name, tactics, techniques)
            logging.info(f"   - Added Custom MITRE Mapping: {attack_name} (Tactics: {len(tactics)}, Techniques: {len(techniques)})")
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
                threat_name = threat_template["description"].format(name=server.name)
                
                custom_threat = CustomThreat(
                    name=threat_name,
                    description=threat_template["description"],
                    stride_category=threat_template["stride_category"],
                    impact=threat_template["impact"],
                    likelihood=threat_template["likelihood"],
                    target=server # The target is the actual PyTM object
                )
                
                generated_custom_threats.append((custom_threat, server))
                elements_with_custom_threats.add(server)
                

        # Apply threats to dataflows
        for dataflow in self.threat_model.dataflows:
            for threat_template in custom_threat_definitions.get("dataflows", []):
                threat_name = threat_template["description"].format(source=dataflow.source, sink=dataflow.sink)
                
                custom_threat = CustomThreat(
                    name=threat_name,
                    description=threat_template["description"],
                    stride_category=threat_template["stride_category"],
                    impact=threat_template["impact"],
                    likelihood=threat_template["likelihood"],
                    target=dataflow # The target is the actual PyTM object
                )
                
                generated_custom_threats.append((custom_threat, dataflow))
                elements_with_custom_threats.add(dataflow)
                
        # Apply threats to actors
        for actor_info in self.threat_model.actors:
            actor = actor_info['object']
            for threat_template in custom_threat_definitions.get("actors", []):
                threat_name = threat_template["description"].format(name=actor.name)

                custom_threat = CustomThreat(
                    name=threat_name,
                    description=threat_template["description"],
                    stride_category=threat_template["stride_category"],
                    impact=threat_template["impact"],
                    likelihood=threat_template["likelihood"],
                    target=actor # The target is the actual PyTM object
                )

                generated_custom_threats.append((custom_threat, actor))
                elements_with_custom_threats.add(actor)
        
        return generated_custom_threats, elements_with_custom_threats