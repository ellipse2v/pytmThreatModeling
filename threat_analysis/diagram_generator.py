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

"""
Diagram generation module
"""
import subprocess
import os
import re
from typing import Dict, List, Any, Optional
from pytm import TM, Boundary, Actor, Server, Dataflow, Data  # Import for pytm types

class DiagramGenerator:
    """Class for threat model diagram generation"""
    
    def __init__(self):
        self.dot_executable = "dot"
        self.supported_formats = ["svg", "png", "pdf", "ps"]
        
    def generate_diagram_from_model(self, threat_model, output_file: str = "tm_diagram", 
                                  format: str = "svg") -> Optional[str]:
        """
        Generates a diagram (e.g., SVG, PNG) from a threat model.
        This method handles DOT extraction and final diagram generation.
        """
        try:
            dot_code = self._extract_dot_from_model(threat_model)
            if not dot_code:
                dot_code = self._generate_manual_dot(threat_model)
            
            if dot_code:
                return self.generate_diagram_from_dot(dot_code, output_file, format)
            else:
                print("❌ Unable to obtain DOT code for diagram generation.")
                return None
            
        except Exception as e:
            print(f"❌ Error during diagram generation: {e}")
            return None
    
    def generate_dot_file_from_model(self, threat_model, output_file: str) -> Optional[str]:
        """Generates a .dot file from the threat model and saves it."""
        try:
            dot_code = self._extract_dot_from_model(threat_model)
            if not dot_code: # If pytm.to_dot() returns empty/None
                dot_code = self._generate_manual_dot(threat_model) # Fallback to manual generation
            
            if not dot_code or not dot_code.strip(): # Check if DOT code is empty or only whitespace
                print("❌ Unable to generate DOT code from model. DOT code is empty. Check model content.")
                return None

            # Clean the DOT code
            cleaned_dot = self._clean_dot_code(dot_code)

            # Ensure output directory exists
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)

            with open(output_file, "w", encoding="utf-8", newline='\n') as f:
                f.write(cleaned_dot)
            print(f"✅ DOT file generated: {output_file}")
            return output_file
        except Exception as e:
            print(f"❌ Error during DOT file generation: {e}")
            return None

    def generate_diagram_from_dot(self, dot_code: str, output_file: str, format: str = "svg") -> Optional[str]:
        """Generates a diagram from DOT code using Graphviz."""
        if format not in self.supported_formats:
            print(f"❌ Unsupported format: {format}. Supported formats: {self.supported_formats}")
            return None
            
        if not self.check_graphviz_installation():
            print("❌ Graphviz not found!")
            print(self.get_installation_instructions())
            return None
            
        try:
            output_path = f"{output_file}.{format}"
            
            # Clean the DOT code before processing
            cleaned_dot = self._clean_dot_code(dot_code)
            
            # Run dot command to generate diagram
            process = subprocess.run(
                [self.dot_executable, f"-T{format}", "-o", output_path],
                input=cleaned_dot,
                text=True,
                encoding='utf-8',
                capture_output=True,
                check=True
            )
            
            if os.path.exists(output_path):
                print(f"✅ Diagram generated: {output_path}")
                return output_path
            else:
                print("❌ Output file was not created")
                return None
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Graphviz error: {e.stderr}")
            print(f"DOT code preview: {cleaned_dot[:200]}...")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return None

    def _extract_dot_from_model(self, threat_model) -> Optional[str]:
        """Attempts to extract DOT code from a PyTM model if available."""
        try:
            if hasattr(threat_model, 'tm') and hasattr(threat_model.tm, 'to_dot'):
                # Returns DOT generated by pytm.TM
                return threat_model.tm.to_dot()
            elif hasattr(threat_model, 'to_dot'): # If threat_model is directly a TM instance
                return threat_model.to_dot()
        except Exception as e:
            print(f"⚠️ Error extracting DOT from model: {e}")
        return None

    def _generate_manual_dot(self, threat_model) -> str:
        """Generates manual DOT code from ThreatModel components."""
        dot_code = [
            "digraph ThreatModel {",
            "  rankdir=LR;",
            "  node [shape=box, style=filled, fillcolor=lightblue];",
            "  edge [fontsize=10];",
            "  charset=\"UTF-8\";"
        ]

        # Generate boundaries as subgraphs
        if hasattr(threat_model, 'boundaries') and threat_model.boundaries:
            for name, info in threat_model.boundaries.items():
                safe_name = self._sanitize_name(name)
                color = info.get("color", "lightgray")
                escaped_name = self._escape_label(name)
                dot_code.append(f"  subgraph cluster_{safe_name} {{")
                dot_code.append(f"    label=\"{escaped_name}\";")
                dot_code.append(f"    style=filled;")
                dot_code.append(f"    fillcolor=\"{color}\";")
                dot_code.append(f"    color=black;")
                
                # Add actors in this boundary
                if hasattr(threat_model, 'actors'):
                    for actor in threat_model.actors:
                        if (hasattr(actor, 'inBoundary') and actor.inBoundary and 
                            hasattr(actor.inBoundary, 'name') and actor.inBoundary.name == name):
                            escaped_actor_name = self._escape_label(actor.name)
                            node_attrs = self._get_node_attributes(actor.name, 'actor')
                            dot_code.append(f"    \"{escaped_actor_name}\" {node_attrs};")
                
                # Add servers in this boundary
                if hasattr(threat_model, 'servers'):
                    for server in threat_model.servers:
                        if (hasattr(server, 'inBoundary') and server.inBoundary and 
                            hasattr(server.inBoundary, 'name') and server.inBoundary.name == name):
                            escaped_server_name = self._escape_label(server.name)
                            node_attrs = self._get_node_attributes(server.name, 'server')
                            dot_code.append(f"    \"{escaped_server_name}\" {node_attrs};")
                
                dot_code.append("  }")
        
        # Add actors not in boundaries
        if hasattr(threat_model, 'actors'):
            for actor in threat_model.actors:
                if not hasattr(actor, 'inBoundary') or not actor.inBoundary:
                    escaped_actor_name = self._escape_label(actor.name)
                    node_attrs = self._get_node_attributes(actor.name, 'actor')
                    dot_code.append(f"  \"{escaped_actor_name}\" {node_attrs};")
        
        # Add servers not in boundaries
        if hasattr(threat_model, 'servers'):
            for server in threat_model.servers:
                if not hasattr(server, 'inBoundary') or not server.inBoundary:
                    escaped_server_name = self._escape_label(server.name)
                    node_attrs = self._get_node_attributes(server.name, 'server')
                    dot_code.append(f"  \"{escaped_server_name}\" {node_attrs};")

        # Add dataflows
        if hasattr(threat_model, 'dataflows'):
            for df in threat_model.dataflows:
                try:
                    # Get source and destination names safely
                    source_name = self._get_element_name(df.source)
                    dest_name = self._get_element_name(df.sink)
                    
                    if not source_name or not dest_name:
                        print(f"⚠️ Skipping dataflow with missing source or destination")
                        continue
                    
                    # Escape names for DOT
                    escaped_source = self._escape_label(source_name)
                    escaped_dest = self._escape_label(dest_name)
                    
                    # Build label parts
                    label_parts = []
                    
                    # Add dataflow name
                    if hasattr(df, 'name') and df.name:
                        label_parts.append(self._escape_label(df.name))
                    
                    # Add protocol
                    if hasattr(df, 'protocol') and df.protocol:
                        label_parts.append(f"Protocol: {self._escape_label(df.protocol)}")
                    
                    # Add data information
                    data_info = self._extract_data_info(df)
                    if data_info:
                        label_parts.append(self._escape_label(data_info))
                    
                    # Add security attributes
                    if hasattr(df, 'isEncrypted') and df.isEncrypted:
                        label_parts.append("Encrypted")
                    if hasattr(df, 'authenticatedWith') and df.authenticatedWith:
                        label_parts.append("Authenticated")
                    
                    label = "\\n".join(label_parts) if label_parts else "Data Flow"
                    
                    dot_code.append(f"  \"{escaped_source}\" -> \"{escaped_dest}\" [label=\"{label}\"];")
                
                except Exception as e:
                    print(f"⚠️ Error processing dataflow: {e}")
                    continue

        dot_code.append("}")
        
        result = "\n".join(dot_code)
        print(f"📝 Generated DOT code ({len(result)} characters)")
        return result

    def _get_node_attributes(self, node_name: str, node_type: str) -> str:
        """
        Returns DOT node attributes based on node name and type.
        Adds specific icons for switches and firewalls.
        """
        node_name_lower = node_name.lower()
        
        # Check for switch
        if 'switch' in node_name_lower:
            return '[shape=diamond, style=filled, fillcolor=orange, label="🔀\\n' + self._escape_label(node_name) + '"]'
        
        # Check for firewall
        elif 'firewall' in node_name_lower:
            return '[shape=hexagon, style=filled, fillcolor=red, label="🔥\\n' + self._escape_label(node_name) + '"]'
        
        # Default attributes based on node type
        elif node_type == 'actor':
            return '[shape=oval, fillcolor=yellow]'
        elif node_type == 'server':
            return '[shape=box, fillcolor=lightgreen]'
        else:
            return '[shape=box, style=filled, fillcolor=lightblue]'
        

    def _get_element_name(self, element) -> Optional[str]:
        """Safely extracts the name from a model element."""
        if element is None:
            return None
        
        if hasattr(element, 'name'):
            return element.name
        
        # If it's a string, return it directly
        if isinstance(element, str):
            return element
        
        # Try to convert to string as last resort
        try:
            return str(element)
        except:
            return None

    def _extract_data_info(self, dataflow) -> Optional[str]:
        """Extracts data information from a dataflow."""
        if not hasattr(dataflow, 'data') or not dataflow.data:
            return None
        
        try:
            data = dataflow.data
            
            # If data has a 'value' attribute (varData wrapper)
            if hasattr(data, 'value'):
                data = data.value
            
            # Single Data object
            if hasattr(data, 'name'):
                return f"Data: {data.name}"
            
            # List of Data objects (DataSet)
            if isinstance(data, list):
                data_names = []
                for item in data:
                    if hasattr(item, 'name'):
                        data_names.append(item.name)
                    else:
                        data_names.append(str(item))
                
                if data_names:
                    return f"Data: {', '.join(data_names)}"
            
            # Fallback to string representation
            return f"Data: {str(data)}"
            
        except Exception as e:
            print(f"⚠️ Error extracting data info: {e}")
            return "Data: Unknown"

    def _sanitize_name(self, name: str) -> str:
        """Sanitizes a name for use as DOT identifier."""
        if not name:
            return "unnamed"
        
        # Replace problematic characters with underscores
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', str(name))
        
        # Ensure it starts with a letter or underscore
        if sanitized and sanitized[0].isdigit():
            sanitized = f"_{sanitized}"
        
        return sanitized or "unnamed"

    def _escape_label(self, text: str) -> str:
        """Escapes text for use in DOT labels."""
        if not text:
            return ""
        
        # Convert to string and handle encoding
        text = str(text)
        
        # Remove or replace problematic characters
        text = text.replace('"', '\\"')  # Escape quotes
        text = text.replace('\n', '\\n')  # Escape newlines
        text = text.replace('\r', '')     # Remove carriage returns
        text = text.replace('\t', ' ')    # Replace tabs with spaces
        
        # Remove non-printable characters except basic ones
        text = re.sub(r'[^\x20-\x7E\u00A0-\uFFFF]', '', text)
        
        # Limit length to prevent overly long labels
        if len(text) > 100:
            text = text[:97] + "..."
        
        return text

    def _clean_dot_code(self, dot_code: str) -> str:
        """Cleans DOT code to prevent encoding issues."""
        if not dot_code:
            return ""
        
        # Ensure proper encoding
        if isinstance(dot_code, bytes):
            dot_code = dot_code.decode('utf-8', errors='replace')
        
        # Remove any BOM characters
        dot_code = dot_code.lstrip('\ufeff')
        
        # Normalize line endings
        dot_code = dot_code.replace('\r\n', '\n').replace('\r', '\n')
        
        return dot_code
    
    def check_graphviz_installation(self) -> bool:
        """Checks if Graphviz is installed"""
        try:
            result = subprocess.run([self.dot_executable, "-V"], 
                                  capture_output=True, text=True, check=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except subprocess.CalledProcessError as e:
            print(f"❌ Error running Graphviz for verification: {e.stderr}")
            return False

    def get_installation_instructions(self) -> str:
        """Returns Graphviz installation instructions"""
        return """
🔧 Graphviz Installation:

Graphviz 'dot' command not found. Please install Graphviz to generate diagrams.

Windows:
- Download from https://graphviz.org/download/
- Or use Chocolatey: choco install graphviz

macOS:
- Use Homebrew: brew install graphviz
- Or MacPorts: sudo port install graphviz

Linux (Ubuntu/Debian):
- sudo apt-get install graphviz

Linux (CentOS/RHEL):
- sudo yum install graphviz
- or sudo dnf install graphviz

After installation, restart your terminal or IDE.
"""