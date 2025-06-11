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
Enhanced Diagram generation module with protocol styles and boundary attributes support
"""
import subprocess
import os
import re
from typing import Dict, List, Any, Optional
from pytm import TM, Boundary, Actor, Server, Dataflow, Data  # Import for pytm types

class DiagramGenerator:
    """Enhanced class for threat model diagram generation with protocol styles and boundary attributes"""
    
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
            #dot_code = self._extract_dot_from_model(threat_model)
            #if not dot_code:
            #    dot_code = self._generate_manual_dot(threat_model)
            
            #if dot_code:
                #return self.generate_diagram_from_dot(dot_code, output_file, format)
           return self.generate_enhanced_diagram_with_legend(threat_model, output_file, format)

        #    else:
         #       print("❌ Unable to obtain DOT code for diagram generation.")
          #      return None
            
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
                print(" Returns DOT generated by pytm.TM")
                return threat_model.tm.to_dot()
            elif hasattr(threat_model, 'to_dot'): # If threat_model is directly a TM instance
                print("If threat_model is directly a TM instance")
                return threat_model.to_dot()
        except Exception as e:
            print(f"⚠️ Error extracting DOT from model: {e}")
        return None

    def _get_edge_attributes_for_protocol(self, threat_model, protocol: Optional[str]) -> str:
        """
        Returns DOT edge attributes based on protocol styling defined in the threat model.
        
        Args:
            threat_model: The threat model containing protocol styles
            protocol: The protocol name to get styling for
            
        Returns:
            str: Additional DOT attributes for the edge
        """
        if not protocol or not hasattr(threat_model, 'get_protocol_style'):
            return ""
        
        protocol_style = threat_model.get_protocol_style(protocol)
        if not protocol_style:
            return ""
        
        attributes = []
        
        # Color attribute
        if 'color' in protocol_style:
            attributes.append(f"color=\"{protocol_style['color']}\"")
        
        # Line style attribute
        if 'line_style' in protocol_style:
            style = protocol_style['line_style']
            if style in ['solid', 'dashed', 'dotted', 'bold']:
                attributes.append(f"style=\"{style}\"")
        
        # Line width attribute
        if 'width' in protocol_style:
            try:
                width = float(protocol_style['width'])
                attributes.append(f"penwidth={width}")
            except (ValueError, TypeError):
                pass
        
        # Arrow style attribute
        if 'arrow_style' in protocol_style:
            arrow_style = protocol_style['arrow_style']
            if arrow_style in ['normal', 'box', 'diamond', 'dot', 'none']:
                attributes.append(f"arrowhead=\"{arrow_style}\"")
        
        # Arrow size
        if 'arrow_size' in protocol_style:
            try:
                arrow_size = float(protocol_style['arrow_size'])
                attributes.append(f"arrowsize={arrow_size}")
            except (ValueError, TypeError):
                pass
        
        # Font size for edge labels
        if 'font_size' in protocol_style:
            try:
                font_size = int(protocol_style['font_size'])
                attributes.append(f"fontsize={font_size}")
            except (ValueError, TypeError):
                pass
        
        # Font color for edge labels
        if 'font_color' in protocol_style:
            attributes.append(f"fontcolor=\"{protocol_style['font_color']}\"")
        
        # Additional custom attributes
        for key, value in protocol_style.items():
            if key not in ['color', 'line_style', 'width', 'arrow_style', 'arrow_size', 'font_size', 'font_color']:
                if isinstance(value, (str, int, float)):
                    # Sanitize attribute name for DOT
                    sanitized_key = re.sub(r'[^a-zA-Z0-9_]', '_', str(key))
                    attributes.append(f"{sanitized_key}=\"{value}\"")
        
        if attributes:
            return ", " + ", ".join(attributes)
        return ""
    
    def _get_node_attributes(self, element, node_type: str) -> str:
        """
        Returns DOT node attributes based on element properties and type.
        Takes into account custom attributes like color and is_filled.
        Handles both dict format and object format.
        """
        # Start with base attributes
        attributes = []
        
        # Get element name and custom attributes
        if isinstance(element, dict):
            # Handle dictionary format with 'object' key (your format)
            if 'object' in element:
                # Get name from the PyTM object
                pytm_object = element['object']
                node_name = getattr(pytm_object, 'name', element.get('name', 'Unnamed'))
                # Get custom attributes from the dict (not from PyTM object)
                color = element.get('color')
                is_filled = element.get('is_filled')
                fillcolor = element.get('fillcolor')
            else:
                # Handle simple dictionary format
                node_name = element.get('name', 'Unnamed')
                color = element.get('color')
                is_filled = element.get('is_filled')
                fillcolor = element.get('fillcolor')
        elif isinstance(element, str):
            # Handle string format
            node_name = element
            color = None
            is_filled = None
            fillcolor = None
        else:
            # Handle object format (old format)
            node_name = getattr(element, 'name', str(element))
            color = getattr(element, 'color', None)
            is_filled = getattr(element, 'is_filled', None)
            fillcolor = getattr(element, 'fillcolor', None)
        
        node_name_lower = node_name.lower()
        
        # Escape the label
        escaped_name = self._escape_label(node_name)
        
        # Check for special node types based on name
        if 'switch' in node_name_lower:
            attributes.append('shape=diamond')
            default_fillcolor = 'orange'
            icon = '🔀\\n'
        elif 'firewall' in node_name_lower:
            attributes.append('shape=hexagon')
            default_fillcolor = 'red'
            icon = '🔥\\n'
        else:
            # Default shapes based on node type
            if node_type == 'actor':
                attributes.append('shape=oval')
                default_fillcolor = 'yellow'
            elif node_type == 'server':
                attributes.append('shape=box')
                default_fillcolor = 'lightgreen'
            else:
                attributes.append('shape=box')
                default_fillcolor = 'lightblue'
            icon = ''
        
        # Handle fill style
        if is_filled is not None:
            if is_filled:
                attributes.append('style=filled')
            else:
                attributes.append('style=""')
        else:
            # Default to filled for most elements
            attributes.append('style=filled')
        
        # Handle colors - priority: fillcolor > color > default
        final_fillcolor = fillcolor or color or default_fillcolor
        if final_fillcolor:
            attributes.append(f'fillcolor="{final_fillcolor}"')
        
        # Handle border color (if different from fill color)
        if color and fillcolor and color != fillcolor:
            attributes.append(f'color="{color}"')
        elif color and not fillcolor:
            # If only color is specified, use it for border too
            attributes.append(f'color="{color}"')
        
        # Set label with icon if applicable
        if icon:
            attributes.append(f'label="{icon}{escaped_name}"')
        else:
            attributes.append(f'label="{escaped_name}"')
        
        return f'[{", ".join(attributes)}]'

    def _get_element_name(self, element) -> Optional[str]:
        """Safely extracts the name from a model element."""
        if element is None:
            return None
        
        # Handle new actor format (dict)
        if isinstance(element, dict) and 'name' in element:
            return element['name']
        
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
    
    def generate_enhanced_diagram_with_legend(self, threat_model, output_file: str = "tm_diagram_with_legend", 
                                            format: str = "svg") -> Optional[str]:
        """
        Generates a diagram with a legend showing protocol styles and boundary types.
        """
        try:
            print("🔍 DEBUG: Starting enhanced diagram generation...")
            
            # Generate main diagram DOT code
            print("🔍 DEBUG: Generating main DOT code...")
            main_dot = self._generate_manual_dot(threat_model)
            print(f"🔍 DEBUG: Main DOT generated: {len(main_dot)} characters")
            
            # Add legend subgraph
            print("🔍 DEBUG: Generating legend DOT code...")
            legend_dot = self._generate_legend_dot(threat_model)
            print(f"🔍 DEBUG: Legend DOT generated: {len(legend_dot)} characters")
            
            if legend_dot.strip():
                print("🔍 DEBUG: Legend content found, combining with main diagram...")
                # Insérer la légende avant la fermeture du graphe
                combined_dot = main_dot.rstrip('}\n') + '\n' + legend_dot + '\n}'
                print("🔍 DEBUG: Combined successfully")
            else:
                print("⚠️ DEBUG: No legend content generated, using main diagram only")
                combined_dot = main_dot
            
            print(f"📝 Generated diagram with legend ({len(combined_dot)} characters)")
            
            # Debug: Save combined DOT to file for inspection
            try:
                debug_dot_file = f"{output_file}_debug.dot"
                with open(debug_dot_file, 'w', encoding='utf-8') as f:
                    f.write(combined_dot)
                print(f"🔍 DEBUG: DOT code saved to {debug_dot_file} for inspection")
            except Exception as debug_e:
                print(f"⚠️ DEBUG: Could not save debug DOT file: {debug_e}")
            
            return self.generate_diagram_from_dot(combined_dot, output_file, format)
            
        except Exception as e:
            print(f"❌ Error generating enhanced diagram with legend: {e}")
            import traceback
            traceback.print_exc()
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
                
                # Extract boundary properties from your structure
                boundary_obj = info.get('boundary')
                color = info.get('color', 'lightgray')
                is_trusted = info.get('isTrusted', False)
                is_filled = info.get('isFilled', True)
                line_style = info.get('line_style', 'solid')  # solid, dashed, dotted
                
                # Get display name from boundary object or use key name
                if boundary_obj and hasattr(boundary_obj, 'name'):
                    display_name = boundary_obj.name
                else:
                    display_name = name
                
                escaped_name = self._escape_label(display_name)
                dot_code.append(f"  subgraph cluster_{safe_name} {{")
                dot_code.append(f"    label=\"{escaped_name}\";")
                
                # Adjust font size for untrusted boundaries (one level smaller)
                if not is_trusted:
                    dot_code.append(f"    fontsize=10;")  # Smaller font for untrusted boundaries
                
                # Build style attribute with rounded corners and fill
                style_parts = ["rounded"]  # Always add rounded corners
                
                if is_filled:
                    style_parts.append("filled")
                    dot_code.append(f"    fillcolor=\"{color}\";")
                
                dot_code.append(f"    style=\"{','.join(style_parts)}\";")
                
                # Different border style for trusted/untrusted boundaries
                if not is_trusted:
                    dot_code.append(f"    color=black;")
                else:
                    dot_code.append(f"    color=red;")
                    dot_code.append(f"    penwidth=3;") 
                
                # Apply line style (solid, dashed, dotted)
                if line_style and line_style != 'solid':
                    if line_style == 'dashed':
                        dot_code.append(f"    style=\"{','.join(style_parts)},dashed\";")
                    elif line_style == 'dotted':
                        dot_code.append(f"    style=\"{','.join(style_parts)},dotted\";")
                    # For other line styles, you can add more conditions here
                
                # Add actors in this boundary
                if hasattr(threat_model, 'actors'):
                    for actor_info in threat_model.actors:
                        # Handle new actor format (dict)
                        if isinstance(actor_info, dict):
                            actor_boundary = actor_info.get('boundary')
                            if (actor_boundary and hasattr(actor_boundary, 'name') and 
                                actor_boundary.name == name):
                                escaped_actor_name = self._escape_label(actor_info['name'])
                                # Pass the full actor_info dict to get custom attributes
                                node_attrs = self._get_node_attributes(actor_info, 'actor')
                                dot_code.append(f"    \"{escaped_actor_name}\" {node_attrs};")
                        # Handle old actor format (object with inBoundary)
                        elif (hasattr(actor_info, 'inBoundary') and actor_info.inBoundary and 
                            hasattr(actor_info.inBoundary, 'name') and actor_info.inBoundary.name == name):
                            escaped_actor_name = self._escape_label(actor_info.name)
                            # Pass the full actor object to get custom attributes
                            node_attrs = self._get_node_attributes(actor_info, 'actor')
                            dot_code.append(f"    \"{escaped_actor_name}\" {node_attrs};")
                
                # Add servers in this boundary
                if hasattr(threat_model, 'servers'):
                    for server in threat_model.servers:
                        if (hasattr(server, 'inBoundary') and server.inBoundary and 
                            hasattr(server.inBoundary, 'name') and server.inBoundary.name == name):
                            escaped_server_name = self._escape_label(server.name)
                            # Pass the full server object to get custom attributes
                            node_attrs = self._get_node_attributes(server, 'server')
                            dot_code.append(f"    \"{escaped_server_name}\" {node_attrs};")
                
                dot_code.append("  }")
        
        # Add actors not in boundaries
        if hasattr(threat_model, 'actors'):
            for actor_info in threat_model.actors:
                # Handle new actor format (dict)
                if isinstance(actor_info, dict):
                    if not actor_info.get('boundary'):
                        escaped_actor_name = self._escape_label(actor_info['name'])
                        # Pass the full actor_info dict to get custom attributes
                        node_attrs = self._get_node_attributes(actor_info, 'actor')
                        dot_code.append(f"  \"{escaped_actor_name}\" {node_attrs};")
                # Handle old actor format (object)
                elif not hasattr(actor_info, 'inBoundary') or not actor_info.inBoundary:
                    escaped_actor_name = self._escape_label(actor_info.name)
                    # Pass the full actor object to get custom attributes
                    node_attrs = self._get_node_attributes(actor_info, 'actor')
                    dot_code.append(f"  \"{escaped_actor_name}\" {node_attrs};")
        
        # Add servers not in boundaries
        if hasattr(threat_model, 'servers'):
            for server in threat_model.servers:
                if not hasattr(server, 'inBoundary') or not server.inBoundary:
                    escaped_server_name = self._escape_label(server.name)
                    # Pass the full server object to get custom attributes
                    node_attrs = self._get_node_attributes(server, 'server')
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
                    
                    # Dataflow text 30% smaller (fontsize 7 instead of 10)
                    dot_code.append(f"  \"{escaped_source}\" -> \"{escaped_dest}\" [label=\"{label}\", fontsize=7];")
                
                except Exception as e:
                    print(f"⚠️ Error processing dataflow: {e}")
                    continue

        dot_code.append("}")
        
        result = "\n".join(dot_code)
        print(f"📝 Generated DOT code ({len(result)} characters)")
        return result
    
    def _generate_legend_dot(self, threat_model) -> str:
        """
        Generates DOT code for a legend showing protocol styles and boundary types.
        """
        try:
            print("🔍 DEBUG: Starting legend generation...")
            
            legend_parts = []
            
            # Start legend subgraph
            legend_parts.append('  subgraph cluster_legend {')
            legend_parts.append('    label="Legend";')
            legend_parts.append('    style="rounded,filled";')
            legend_parts.append('    fillcolor="white";')
            legend_parts.append('    color="black";')
            legend_parts.append('    fontsize=12;')
            legend_parts.append('    fontname="Arial";')
            legend_parts.append('    margin=10;')
            legend_parts.append('    rank=sink;')  # Place legend at bottom
            
            # Protocol styles legend
            protocol_styles = self._get_protocol_styles_from_model(threat_model)
            if protocol_styles:
                print(f"🔍 DEBUG: Found {len(protocol_styles)} protocol styles")
                
                # Create invisible nodes for protocol legend
                legend_parts.append('    // Protocol Styles')
                legend_parts.append('    "protocol_header" [label="Protocol Styles:", shape=plaintext, fontsize=10, fontname="Arial Bold"];')
                
                for i, (protocol, style) in enumerate(protocol_styles.items()):
                    node_id = f"protocol_{i}"
                    legend_parts.append(f'    "{node_id}_src" [label="", shape=point, width=0.1, height=0.1];')
                    legend_parts.append(f'    "{node_id}_dst" [label="", shape=point, width=0.1, height=0.1];')
                    
                    # Build edge attributes
                    edge_attrs = self._build_legend_edge_attributes(style)
                    protocol_label = self._escape_label(protocol)
                    
                    legend_parts.append(f'    "{node_id}_src" -> "{node_id}_dst" [label="{protocol_label}"{edge_attrs}];')
            else:
                print("🔍 DEBUG: No protocol styles found")
            
            # Boundary types legend
            boundary_info = self._get_boundary_types_from_model(threat_model)
            if boundary_info:
                print(f"🔍 DEBUG: Found {len(boundary_info)} boundary types")
                
                legend_parts.append('    // Boundary Types')
                legend_parts.append('    "boundary_header" [label="Boundary Types:", shape=plaintext, fontsize=10, fontname="Arial Bold"];')
                
                for i, (boundary_name, boundary_props) in enumerate(boundary_info.items()):
                    node_id = f"boundary_{i}"
                    boundary_label = self._escape_label(boundary_name)
                    
                    # Create a small rectangular node to represent the boundary
                    is_trusted = boundary_props.get('isTrusted', True)
                    color = boundary_props.get('color', 'lightgray')
                    line_style = boundary_props.get('line_style', 'solid')
                    
                    # Build node attributes for boundary representation
                    node_attrs = ['shape=box', 'width=0.5', 'height=0.3']
                    node_attrs.append(f'label="{boundary_label}"')
                    node_attrs.append('fontsize=8')
                    
                    if boundary_props.get('isFilled', True):
                        node_attrs.append('style="filled,rounded"')
                        node_attrs.append(f'fillcolor="{color}"')
                    else:
                        node_attrs.append('style="rounded"')
                    
                    if not is_trusted:
                        node_attrs.append('color="red"')
                        node_attrs.append('penwidth=2')
                    else:
                        node_attrs.append('color="black"')
                    
                    if line_style == 'dashed':
                        current_style = node_attrs[-2].replace('style="', '').replace('"', '')
                        node_attrs[-2] = f'style="{current_style},dashed"'
                    elif line_style == 'dotted':
                        current_style = node_attrs[-2].replace('style="', '').replace('"', '')
                        node_attrs[-2] = f'style="{current_style},dotted"'
                    
                    legend_parts.append(f'    "{node_id}" [{", ".join(node_attrs)}];')
            else:
                print("🔍 DEBUG: No boundary types found")
            
            # Node types legend
            legend_parts.append('    // Node Types')
            legend_parts.append('    "node_header" [label="Node Types:", shape=plaintext, fontsize=10, fontname="Arial Bold"];')
            
            # Standard node types
            node_types = [
                ('Actor', 'oval', 'yellow'),
                ('Server', 'box', 'lightgreen'),
                ('Firewall', 'hexagon', 'red'),
                ('Switch', 'diamond', 'orange')
            ]
            
            for i, (node_type, shape, color) in enumerate(node_types):
                node_id = f"nodetype_{i}"
                legend_parts.append(f'    "{node_id}" [label="{node_type}", shape={shape}, style=filled, fillcolor="{color}", fontsize=8];')
            
            # Close legend subgraph
            legend_parts.append('  }')
            
            # Add invisible edges to control legend layout
            legend_parts.append('  // Legend layout constraints')
            if protocol_styles:
                legend_parts.append('  "protocol_header" -> "protocol_0_src" [style=invis];')
            if boundary_info:
                legend_parts.append('  "boundary_header" -> "boundary_0" [style=invis];')
            legend_parts.append('  "node_header" -> "nodetype_0" [style=invis];')
            
            result = '\n'.join(legend_parts)
            print(f"🔍 DEBUG: Legend DOT generated: {len(result)} characters")
            return result
            
        except Exception as e:
            print(f"❌ Error generating legend DOT: {e}")
            import traceback
            traceback.print_exc()
            return ""
    def _get_protocol_styles_from_model(self, threat_model) -> Dict[str, Dict]:
        """
        Extracts protocol styles from the threat model.
        """
        protocol_styles = {}
        
        try:
            # Check if threat model has protocol styles method
            if hasattr(threat_model, 'get_all_protocol_styles'):
                protocol_styles = threat_model.get_all_protocol_styles()
            elif hasattr(threat_model, 'protocol_styles'):
                protocol_styles = threat_model.protocol_styles
            else:
                # Extract protocols from dataflows and create default styles
                protocols = set()
                if hasattr(threat_model, 'dataflows'):
                    for df in threat_model.dataflows:
                        if hasattr(df, 'protocol') and df.protocol:
                            protocols.add(df.protocol)
                
                # Create default styles for found protocols
                colors = ['blue', 'green', 'purple', 'orange', 'brown']
                for i, protocol in enumerate(protocols):
                    protocol_styles[protocol] = {
                        'color': colors[i % len(colors)],
                        'line_style': 'solid'
                    }
            
            print(f"🔍 DEBUG: Extracted {len(protocol_styles)} protocol styles: {list(protocol_styles.keys())}")
            
        except Exception as e:
            print(f"⚠️ Error extracting protocol styles: {e}")
        
        return protocol_styles

    def _get_boundary_types_from_model(self, threat_model) -> Dict[str, Dict]:
        """
        Extracts boundary types and their properties from the threat model.
        """
        boundary_info = {}
        
        try:
            if hasattr(threat_model, 'boundaries') and threat_model.boundaries:
                for name, info in threat_model.boundaries.items():
                    boundary_props = {
                        'isTrusted': info.get('isTrusted', True),
                        'isFilled': info.get('isFilled', True),
                        'color': info.get('color', 'lightgray'),
                        'line_style': info.get('line_style', 'solid')
                    }
                    boundary_info[name] = boundary_props
            
            print(f"🔍 DEBUG: Extracted {len(boundary_info)} boundary types: {list(boundary_info.keys())}")
            
        except Exception as e:
            print(f"⚠️ Error extracting boundary info: {e}")
        
        return boundary_info

    def _build_legend_edge_attributes(self, style: Dict) -> str:
        """
        Builds DOT edge attributes string from protocol style dictionary.
        """
        attributes = []
        
        # Color
        if 'color' in style:
            attributes.append(f'color="{style["color"]}"')
        
        # Line style
        if 'line_style' in style:
            line_style = style['line_style']
            if line_style in ['solid', 'dashed', 'dotted', 'bold']:
                attributes.append(f'style="{line_style}"')
        
        # Line width
        if 'width' in style:
            try:
                width = float(style['width'])
                attributes.append(f'penwidth={width}')
            except (ValueError, TypeError):
                pass
        
        # Arrow style
        if 'arrow_style' in style:
            arrow_style = style['arrow_style']
            if arrow_style in ['normal', 'box', 'diamond', 'dot', 'none']:
                attributes.append(f'arrowhead="{arrow_style}"')
        
        # Font size
        if 'font_size' in style:
            try:
                font_size = int(style['font_size'])
                attributes.append(f'fontsize={font_size}')
            except (ValueError, TypeError):
                pass
        
        # Font color
        if 'font_color' in style:
            attributes.append(f'fontcolor="{style["font_color"]}"')
        
        if attributes:
            return ', ' + ', '.join(attributes)
        return ''

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

