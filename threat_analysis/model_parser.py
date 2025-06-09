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
from typing import List, Dict, Any, Callable, Optional
from .models_module import ThreatModel
from pytm import Classification, Lifetime


class ModelParser:
    """
    Parses a threat model defined in Markdown and constructs a ThreatModel object.
    """
    def __init__(self, threat_model: ThreatModel):
        self.threat_model = threat_model
        self.current_section = None
        self.section_parsers: Dict[str, Callable[[str], None]] = {
            "## Boundaries": self._parse_boundary,
            "## Actors": self._parse_actor,
            "## Servers": self._parse_server,
            "## Data": self._parse_data,             
            "## Dataflows": self._parse_dataflow,
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
                    print(f"⏳ Loading section: {self.current_section}")
                else:
                    # Unrecognized section, ignore it but set current_section to None
                    self.current_section = None
                    print(f"ℹ️ Section ignored: {section_title}")
                continue

            # If we are in a recognized section, call the appropriate parser
            if self.current_section and self.current_section in self.section_parsers:
                self.section_parsers[self.current_section](stripped_line)
            elif self.current_section:
                # Ignore lines in explicitly unhandled sections
                pass

    def _parse_boundary(self, line: str):
        """Parses a boundary line with format: - **name**: color=value"""
        # Support for both possible formats
        match = re.match(r'^- \*\*([^\*:]+)\*\*(?:\s*:\s*color=([^\s,]+))?', line)
        if match:
            name = match.group(1).strip()
            color = match.group(2).strip() if match.group(2) else "lightgray"
            self.threat_model.add_boundary(name, color)
            print(f"   - Added Boundary: {name} (Color: {color})")
        else:
            print(f"⚠️ Warning: Malformed boundary line: {line}")

    def _parse_actor(self, line: str):
        """Parses an actor line with format: - **name**: boundary=value"""
        match = re.match(r'^- \*\*([^\*:]+)\*\*(?:\s*:\s*boundary=([^\s,]+))?', line)
        if match:
            name = match.group(1).strip()
            boundary_name = match.group(2).strip() if match.group(2) else ""
            if boundary_name:
                self.threat_model.add_actor(name, boundary_name)
                print(f"   - Added Actor: {name} (Boundary: {boundary_name})")
            else:
                print(f"⚠️ Warning: Actor '{name}' has no boundary specified.")
        else:
            print(f"⚠️ Warning: Malformed actor line: {line}")

    def _parse_server(self, line: str):
        """Parses a server line with format: - **name**: boundary=value"""
        match = re.match(r'^- \*\*([^\*:]+)\*\*(?:\s*:\s*boundary=([^\s,]+))?', line)
        if match:
            name = match.group(1).strip()
            boundary_name = match.group(2).strip() if match.group(2) else ""
            if boundary_name:
                self.threat_model.add_server(name, boundary_name)
                print(f"   - Added Server: {name} (Boundary: {boundary_name})")
            else:
                print(f"⚠️ Warning: Server '{name}' has no boundary specified.")
        else:
            print(f"⚠️ Warning: Malformed server line: {line}")

    def _parse_key_value_params(self, params_str: str) -> Dict[str, Any]:
        """Parses a key=value parameter string and returns a dictionary."""
        params = {}
        # Regex to find key="value" or key=True/False or key=Number or key=STRING_ENUM
        param_pattern = re.compile(r'(\w+)=(?:\"([^\"]*)\"|(\w+|[0-9.]+))')
        
        for m in param_pattern.finditer(params_str):
            key = m.group(1)
            value_quoted = m.group(2)
            value_unquoted = m.group(3)

            if value_quoted is not None:
                value = value_quoted
            elif value_unquoted is not None:
                if value_unquoted.lower() == 'true':
                    value = True
                elif value_unquoted.lower() == 'false':
                    value = False
                elif value_unquoted.replace('.', '', 1).isdigit(): # Check if it's a number (int or float)
                    try:
                        value = int(value_unquoted)
                    except ValueError:
                        value = float(value_unquoted)
                else:
                    value = value_unquoted # Remains a string (for enums)
            else:
                continue # Should not happen with this regex

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
                    print(f"⚠️ Warning: Classification '{enum_str}' not recognized for Data '{name}'. Set to UNKNOWN.")

            if "credentialsLife" in data_kwargs:
                enum_str = data_kwargs["credentialsLife"].upper()
                data_kwargs["credentialsLife"] = self.lifetime_map.get(enum_str, Lifetime.UNKNOWN)
                if enum_str not in self.lifetime_map:
                    print(f"⚠️ Warning: Lifetime '{enum_str}' not recognized for Data '{name}'. Set to UNKNOWN.")
            
            # Call add_data by unpacking the properties dictionary
            self.threat_model.add_data(name, **data_kwargs)
        else:
            print(f"⚠️ Warning: Malformed data line: {line}")

    def _parse_dataflow(self, line: str):
        """Parses a dataflow line with flexible named arguments."""
        # First, extract the dataflow name
        name_match = re.match(r'^- \*\*([^\*]+)\*\*:\s*(.*)', line)
        if not name_match:
            print(f"⚠️ Warning: Malformed dataflow line (missing name): {line}")
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
            print(f"⚠️ Warning: Dataflow '{name}' is missing mandatory parameters (from, to, protocol).")
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
            print(f"   - Added Dataflow: {name} ({from_name} -> {to_name}, Proto: {protocol}" +
                      (f", Data: {data_name}" if data_name else "") +
                      (f", Authenticated: {is_authenticated}" if is_authenticated else "") +
                      (f", Encrypted: {is_encrypted}" if is_encrypted else "") + ")")
        else:
            print(f"⚠️ Warning: Elements '{from_name}' or '{to_name}' not found for dataflow '{name}'.")

    def _parse_severity_multiplier(self, line: str):
        """Parses a severity multiplier line."""
        match = re.match(r'^- \*\*([^\*]+)\*\*:\s*([0-9.]+)', line)
        if match:
            element_name = match.group(1).strip()
            multiplier = float(match.group(2).strip())
            # Assume there is an add_severity_multiplier method
            if hasattr(self.threat_model, 'add_severity_multiplier'):
                self.threat_model.add_severity_multiplier(element_name, multiplier)
                print(f"   - Added Severity Multiplier: {element_name} = {multiplier}")
            else:
                print(f"ℹ️ Severity Multiplier ignored (method not implemented): {element_name} = {multiplier}")
        else:
            print(f"⚠️ Warning: Malformed severity multiplier line: {line}")

    def _parse_custom_mitre(self, line: str):
        """Parses a custom MITRE mapping line."""
        # Expected format: - **Attack Name**: tactics=["tactic1", "tactic2"], techniques=[{"id": "T1234", "name": "Attack Name"}]
        match = re.match(r'^- \*\*([^\*]+)\*\*:\s*(.*)', line)
        if match:
            attack_name = match.group(1).strip()
            params_str = match.group(2).strip()
            
            # For now, just log that we found a custom mapping
            if hasattr(self.threat_model, 'add_custom_mitre_mapping'):
                # Here, you would implement more sophisticated parsing of tactics and techniques
                print(f"   - Added Custom MITRE Mapping: {attack_name}")
                # self.threat_model.add_custom_mitre_mapping(attack_name, tactics, techniques)
            else:
                print(f"ℹ️ Custom MITRE Mapping ignored (method not implemented): {attack_name}")
        else:
            print(f"⚠️ Warning: Malformed custom MITRE mapping line: {line}")