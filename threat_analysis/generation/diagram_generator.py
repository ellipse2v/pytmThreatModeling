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
import re
import logging
from typing import Dict, List, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

class DiagramGenerator:
    """Enhanced class for threat model diagram generation with protocol styles and boundary attributes"""
    
    def __init__(self):
        self.dot_executable = "dot"
        self.supported_formats = ["svg", "png", "pdf", "ps"]
        self.template_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"))
    
    def generate_dot_file_from_model(self, threat_model, output_file: str) -> Optional[str]:
        """Generates a .dot file from the threat model and saves it."""
        try:
            dot_code = self._generate_manual_dot(threat_model) # Fallback to manual generation
            
            if not dot_code or not dot_code.strip(): # Check if DOT code is empty or only whitespace
                logging.error("❌ Unable to generate DOT code from model. DOT code is empty. Check model content.")
                return None

            # Clean the DOT code
            cleaned_dot = self._clean_dot_code(dot_code)

            # Convert output_file to Path object
            output_path_obj = Path(output_file)

            # Ensure output directory exists
            output_dir = output_path_obj.parent
            if not output_dir.exists():
                output_dir.mkdir(parents=True)

            with open(str(output_path_obj), "w", encoding="utf-8", newline='\n') as f:
                f.write(cleaned_dot)
            logging.info(f"✅ DOT file generated: {output_file}")
            return output_file
        except Exception as e:
            logging.error(f"❌ Error during DOT file generation: {e}")
            return None

    def generate_diagram_from_dot(self, dot_code: str, output_file: str, format: str = "svg") -> Optional[str]:
        """Generates a diagram from DOT code using Graphviz."""
        if format not in self.supported_formats:
            logging.error(f"❌ Unsupported format: {format}. Supported formats: {self.supported_formats}")
            return None
            
        if not self.check_graphviz_installation():
            logging.error("❌ Graphviz not found!")
            logging.warning(self.get_installation_instructions())
            return None
            
        try:
            # Convert output_file to Path object
            output_path_obj = Path(output_file)

            # Ensure the output directory exists
            output_dir = output_path_obj.parent
            if not output_dir.exists():
                output_dir.mkdir(parents=True)

            # Construct the output path, avoiding double extensions
            if output_path_obj.suffix == f'.{format}':
                output_path = str(output_path_obj)
            else:
                output_path = str(output_path_obj.with_suffix(f'.{format}'))
            
            # Clean the DOT code before processing
            cleaned_dot = self._clean_dot_code(dot_code)
            
            # Run dot command to generate diagram
            # process = subprocess.run(
            subprocess.run(
                [self.dot_executable, f"-T{format}", "-o", output_path],
                input=cleaned_dot,
                text=True,
                encoding='utf-8',
                capture_output=True,
                check=True
            )
            
            if output_path_obj.exists(): # Use output_path_obj for existence check
                
                return output_path
            else:
                logging.error("❌ Output file was not created")
                return None
                
        except subprocess.CalledProcessError as e:
            logging.error(f"❌ Graphviz error: {e.stderr}")
            logging.error(f"DOT code preview: {cleaned_dot[:200]}...")
            return None
        except Exception as e:
            logging.error(f"❌ Unexpected error: {e}")
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
        if 'router' in node_name_lower:
            attributes.append('shape=box') # Routers often represented as boxes
            default_fillcolor = '#FFD700' # Gold color for routers
            icon = '🌐 '
        elif 'switch' in node_name_lower:
            attributes.append('shape=diamond')
            default_fillcolor = 'orange'
            icon = '🔀 '
        elif 'firewall' in node_name_lower:
            attributes.append('shape=hexagon')
            default_fillcolor = 'red'
            icon = '🔥 '
                # Check for database
        elif 'database' in node_name_lower or 'db' in node_name_lower:
                attributes.append('shape=cylinder')
                icon = '🗄️ '
                default_fillcolor = 'lightblue'
        
        # Check for web server
        elif 'web' in node_name_lower and 'server' in node_name_lower:
            return '[shape=box, style=filled, fillcolor=lightgreen, label="🌐 ' + self._escape_label(node_name) + '"]'
        
        # Check for API
        elif 'api' in node_name_lower:
            return '[shape=box, style=filled, fillcolor=lightyellow, label="🔌 ' + self._escape_label(node_name) + '"]'
        else:
            # Default shapes based on node type
            if node_type == 'actor':
                attributes.append('shape=oval')
                icon = '👤 '
                default_fillcolor = 'yellow'
            elif node_type == 'server':
                attributes.append('shape=box')
                icon = '🖥️ '
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
            logging.warning(f"⚠️ Error extracting data info: {e}")
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

    def _generate_manual_dot(self, threat_model) -> str:
        """Generates DOT code from ThreatModel components using Jinja2 template."""
        template = self.template_env.get_template("threat_model.dot.j2")

        boundaries_data = self._prepare_boundaries_data(threat_model)
        actors_outside_boundaries_data = self._prepare_nodes_data(threat_model, "actor")
        servers_outside_boundaries_data = self._prepare_nodes_data(threat_model, "server")
        dataflows_data = self._prepare_dataflows_data(threat_model)

        context = {
            "boundaries": boundaries_data,
            "actors_outside_boundaries": actors_outside_boundaries_data,
            "servers_outside_boundaries": servers_outside_boundaries_data,
            "dataflows": dataflows_data,
        }
        return template.render(context)

    def _prepare_boundaries_data(self, threat_model) -> List[Dict]:
        """Prepares hierarchical boundary data for the Jinja2 template."""
        
        # Build a dictionary of all boundaries, keyed by their PyTM object
        all_boundaries_by_obj = {info['boundary']: {'name': name, 'info': info, 'children': []} 
                                 for name, info in threat_model.boundaries.items()}
        
        # Identify root boundaries and populate children
        root_boundaries = []
        for name, info in threat_model.boundaries.items():
            boundary_obj = info['boundary']
            parent_obj = getattr(boundary_obj, 'inBoundary', None)
            
            if parent_obj and parent_obj in all_boundaries_by_obj:
                all_boundaries_by_obj[parent_obj]['children'].append(all_boundaries_by_obj[boundary_obj])
            else:
                root_boundaries.append(all_boundaries_by_obj[boundary_obj])

        # Recursively prepare data for rendering
        boundaries_data = []
        for root_node in root_boundaries:
            boundaries_data.append(self._prepare_boundary_node(root_node, threat_model))
            
        return boundaries_data

    def _prepare_boundary_node(self, boundary_node, threat_model):
        name = boundary_node['name']
        info = boundary_node['info']
        boundary_obj = info.get('boundary')
        color = info.get('color', 'lightgray')
        is_trusted = info.get('isTrusted', False)
        is_filled = info.get('isFilled', True)
        line_style = info.get('line_style', 'solid')

        display_name = boundary_obj.name if boundary_obj and hasattr(boundary_obj, 'name') else name
        escaped_name = self._escape_label(display_name)
        safe_name = self._sanitize_name(name)

        style_parts = ["rounded"]
        if is_filled:
            style_parts.append("filled")
        
        style_attr = info.get('style') # Get the style attribute
        if style_attr: # Add custom styles like "invis"
            for s in style_attr.split(','):
                style_parts.append(s.strip())

        actors_in_boundary = []
        if hasattr(threat_model, 'actors'):
            for actor_info in threat_model.actors:
                actor_boundary_obj = None
                if isinstance(actor_info, dict):
                    actor_boundary_obj = actor_info.get('boundary')
                elif hasattr(actor_info, 'inBoundary'):
                    actor_boundary_obj = actor_info.inBoundary

                if actor_boundary_obj == boundary_obj:
                    actors_in_boundary.append({
                        "escaped_name": self._escape_label(self._get_element_name(actor_info)),
                        "node_attrs": self._get_node_attributes(actor_info, 'actor')
                    })

        servers_in_boundary = []
        if hasattr(threat_model, 'servers'):
            for server_info in threat_model.servers:
                server_boundary_obj = None
                if isinstance(server_info, dict):
                    server_boundary_obj = server_info.get('boundary')
                elif hasattr(server_info, 'inBoundary'):
                    server_boundary_obj = server_info.inBoundary

                if server_boundary_obj == boundary_obj:
                    servers_in_boundary.append({
                        "escaped_name": self._escape_label(self._get_element_name(server_info)),
                        "node_attrs": self._get_node_attributes(server_info, 'server')
                    })
        
        # Recursively prepare child boundaries
        child_boundaries_data = []
        for child_node in boundary_node['children']:
            logging.info(f"DEBUG: Calling _prepare_boundary_node for child_node: {child_node['name']}")
            child_boundaries_data.append(self._prepare_boundary_node(child_node, threat_model))

        return {
            "safe_name": safe_name,
            "escaped_name": escaped_name,
            "is_trusted": is_trusted,
            "is_filled": is_filled,
            "color": color,
            "line_style": line_style,
            "style_parts": style_parts,
            "actors": actors_in_boundary,
            "servers": servers_in_boundary,
            "children": child_boundaries_data # Add children here
        }

    def _prepare_nodes_data(self, threat_model, node_type: str) -> List[Dict]:
        """Prepares node data (actors/servers) not in boundaries for the Jinja2 template."""
        nodes_data = []
        elements = getattr(threat_model, f'{node_type}s', [])
        for element_info in elements:
            is_in_boundary = False
            if isinstance(element_info, dict):
                if element_info.get('boundary'):
                    is_in_boundary = True
            elif hasattr(element_info, 'inBoundary') and element_info.inBoundary:
                is_in_boundary = True

            if not is_in_boundary:
                nodes_data.append({
                    "escaped_name": self._escape_label(self._get_element_name(element_info)),
                    "node_attrs": self._get_node_attributes(element_info, node_type)
                })
        return nodes_data

    def _prepare_dataflows_data(self, threat_model) -> List[Dict]:
        dataflows_data = []
        dataflow_map = {}
        boundary_name_map = {name: info['boundary'] for name, info in threat_model.boundaries.items()}

        if hasattr(threat_model, 'dataflows'):
            for df in threat_model.dataflows:
                source_obj, dest_obj = df.source, df.sink
                source_name = self._get_element_name(source_obj)
                dest_name = self._get_element_name(dest_obj) # Initialize dest_name here

                try:
                    if not source_name or not dest_name:
                        logging.warning(f"⚠️ Skipping dataflow with missing source or destination")
                        continue

                    edge_attributes = self._get_edge_attributes_for_protocol(threat_model, getattr(df, 'protocol', None))
                    lhead = ltail = ''

                    # Handle source being a boundary
                    if hasattr(source_obj, 'isBoundary') and source_obj.isBoundary:
                        ltail = f'ltail=cluster_{self._sanitize_name(source_name)}'
                        source_node = next((s for s in threat_model.servers if getattr(s, 'inBoundary', None) == source_obj), None) or \
                                      next((a for a in threat_model.actors if getattr(a, 'inBoundary', None) == source_obj), None)
                        if not source_node:
                            logging.warning(f"⚠️ Dataflow from empty boundary '{source_name}' to '{dest_name}' will not be drawn to avoid a visual loop.")
                            continue
                        else:
                            source_name = self._get_element_name(source_node)

                    # Handle destination being a boundary
                    if hasattr(dest_obj, 'isBoundary') and dest_obj.isBoundary:
                        lhead = f'lhead=cluster_{self._sanitize_name(dest_name)}'
                        dest_node = next((s for s in threat_model.servers if getattr(s, 'inBoundary', None) == dest_obj), None) or \
                                    next((a for a in threat_model.actors if getattr(a, 'inBoundary', None) == dest_obj), None)
                        if dest_node:
                            dest_name = self._get_element_name(dest_node)

                    escaped_source = self._escape_label(source_name)
                    escaped_dest = self._escape_label(dest_name)
                    protocol = getattr(df, 'protocol', None)

                    label_parts = [self._escape_label(df.name)] if hasattr(df, 'name') and df.name else []
                    if protocol:
                        label_parts.append(f"Protocol: {self._escape_label(protocol)}")
                    data_info = self._extract_data_info(df)
                    if data_info:
                        label_parts.append(self._escape_label(data_info))
                    if getattr(df, 'isEncrypted', False) or getattr(df, 'is_encrypted', False):
                        label_parts.append("🔒 Encrypted")
                    if getattr(df, 'authenticatedWith', False) or getattr(df, 'is_authenticated', False):
                        label_parts.append("🔐 Authenticated")

                    label = "\n".join(label_parts) if label_parts else "Data Flow"
                    
                    if lhead:
                        edge_attributes += f", {lhead}"
                    if ltail:
                        edge_attributes += f", {ltail}"

                    protocol_class = self._sanitize_name(protocol) if protocol else ''
                    class_attribute = f'class="{protocol_class}"' if protocol_class else ''
                    key = (escaped_source, escaped_dest, protocol)
                    dataflow_map[key] = {
                        "label": label,
                        "edge_attributes": edge_attributes,
                        "class_attribute": class_attribute
                    }
                except Exception as e:
                    logging.warning(f"⚠️ Error processing dataflow: {e}")
                    continue

        processed = set()
        for (src, dst, proto), info in dataflow_map.items():
            direction = ""
            if ((dst, src, proto) in dataflow_map) and ((dst, src, proto) not in processed):
                label = f"{info['label']}\n↔️ Bidirectional"
                direction = "dir=\"both\", "
                processed.add((src, dst, proto))
                processed.add((dst, src, proto))
            elif (src, dst, proto) not in processed:
                label = info["label"]
                processed.add((src, dst, proto))
            else:
                continue

            dataflows_data.append({
                "escaped_source": src,
                "escaped_dest": dst,
                "label": label,
                "edge_attributes": info["edge_attributes"],
                "class_attribute": info["class_attribute"],
                "direction": direction
            })
        return dataflows_data

    def _generate_legend_html(self, threat_model) -> str:
        """Generates HTML legend content."""
        legend_items = []

        # Dynamically generate node types for the legend
        legend_node_types = {}

        # Process actors
        if hasattr(threat_model, 'actors'):
            for actor in threat_model.actors:
                color = actor.get('color') or '#FFFF99'
                if 'Acteur' not in legend_node_types:
                    legend_node_types['Acteur'] = ('👤 Acteur', color)

        # Process servers to find one of each type for the legend
        if hasattr(threat_model, 'servers'):
            server_types_seen = set()
            for server in threat_model.servers:
                name = server.get('name', '').lower()
                color = server.get('color')

                type_key = None
                display_name = None

                if 'firewall' in name and 'Firewall' not in server_types_seen:
                    type_key = 'Firewall'
                    display_name = '🔥 Firewall'
                    color = color or '#FF6B6B'
                elif ('database' in name or 'db' in name) and 'Database' not in server_types_seen:
                    type_key = 'Database'
                    display_name = '🗄️ Database'
                    color = color or '#ADD8D6'
                elif 'Serveur' not in server_types_seen: # Generic server as fallback
                    type_key = 'Serveur'
                    display_name = '🖥️ Serveur'
                    color = color or '#90EE90'

                if type_key and type_key not in legend_node_types:
                    legend_node_types[type_key] = (display_name, color)
                    server_types_seen.add(type_key)

        # Add any missing default types if they weren't found
        default_types = {
            'Acteur': ('👤 Acteur', '#FFFF99'),
            'Serveur': ('🖥️ Serveur', '#90EE90'),
            'Database': ('🗄️ Database', '#ADD8D6'),
            'Firewall': ('🔥 Firewall', '#FF6B6B'),
        }
        for key, value in default_types.items():
            if key not in legend_node_types:
                legend_node_types[key] = value

        # Generate HTML for node types
        for _, (label, color) in legend_node_types.items():
            legend_items.append(f"""
                <div style="display: flex; align-items: center; margin-bottom: 3px;">
                    <div style="width: 12px; height: 8px; background-color: {color};
                            border: 1px solid #999; margin-right: 8px; border-radius: 2px;"></div>
                    <span style="font-size: 9px;">{label}</span>
                </div>
            """)

        # Boundary types
        boundary_types = [
            ("Trust Boundaries", "#FF0000", "3px solid"),
            ("Untrust Boundaries", "#000000", "1px solid"),
        ]
        
        for label, color, border_style in boundary_types:
            legend_items.append(f"""
                <div style="display: flex; align-items: center; margin-bottom: 3px;">
                    <div style="width: 20px; height: 15px; border: {border_style} {color};
                            margin-right: 8px; border-radius: 2px;"></div>
                    <span style="font-size: 11px;">{label}</span>
                </div>
            """)
        
        # Protocol colors - extract from model
        protocol_styles = self._get_protocol_styles_from_model(threat_model)
        if protocol_styles:
            legend_items.append('<div style="margin-top: 5px; margin-bottom: 3px; font-weight: bold; font-size: 10px;">Protocoles:</div>')
            for protocol, style in protocol_styles.items():
                color = style.get('color', '#000000')
                sanitized_protocol = self._sanitize_name(protocol)
                legend_items.append(f"""
                    <div class="legend-item" data-protocol="{sanitized_protocol}">
                        <div style="width: 20px; height: 2px; background-color: {color};
                                margin-right: 8px;"></div>
                        <span style="font-size: 11px;">{protocol}</span>
                    </div>
                """)
        
        return ''.join(legend_items)
   
    def _generate_html_with_legend(self, svg_path: Path, html_output_path: Path, threat_model) -> Optional[Path]:
        """Generates HTML file with SVG and positioned legend."""
        try:
            # Read SVG content
            with open(svg_path, 'r', encoding='utf-8') as f:
                svg_content = f.read()
            
            # Generate legend HTML
            legend_html = self._generate_legend_html(threat_model)
            
            # Create complete HTML
            html_content = self._create_complete_html(svg_content, legend_html, threat_model)
            
            # Write HTML file
            with open(html_output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            
            return html_output_path
        
        except Exception as e:
            logging.error(f"❌ Error generating HTML with legend: {e}")
            return None   
 
    def _create_complete_html(self, svg_content: str, legend_html: str, threat_model) -> str:
            """Creates the complete HTML document with SVG and legend."""
            return f"""<!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Diagramme de Menaces - {threat_model.name if hasattr(threat_model, 'name') else 'Threat Model'}</title>
            <style>
                body {{
                    margin: 0;
                    padding: 0;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f5f5f5;
                    overflow: hidden;
                    user-select: none;
                }}
                .diagram-container {{
                    position: relative;
                    width: 100vw;
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }}
                .svg-container {{
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    background: white;
                    padding: 20px;
                    box-sizing: border-box;
                }}
                .svg-container svg {{
                    max-width: 100%;
                    max-height: 100%;
                    object-fit: contain;
                    drop-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                }}
                .legend {{
                    position: absolute;
                    top: 5px;
                    right: 40px;
                    background: rgba(255, 255, 255, 0.95);
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
                    backdrop-filter: blur(10px);
                    min-width: 90px;
                    max-width: 140px;
                    z-index: 1000;
                    transition: all 0.3s ease;
                    /* cursor: move; */ /* Désactivé pour empêcher le déplacement */
                    pointer-events: none; /* Permet au zoom de passer à travers */
                }}
                .legend:hover {{
                    background: rgba(255, 255, 255, 0.98);
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
                }}
                .legend.dragging {{
                    cursor: grabbing;
                    transform: scale(1.05);
                }}
                .legend-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 8px;
                    border-bottom: 1px solid #007acc;
                    background: rgba(0, 122, 204, 0.1);
                    border-radius: 6px 6px 0 0;
                }}
                .legend-title {{
                    font-weight: bold;
                    font-size: 10px;
                    color: #333;
                    display: flex;
                    align-items: center;
                    gap: 3px;
                    margin: 0;
                }}
                .legend-toggle {{
                    background: none;
                    border: none;
                    cursor: pointer;
                    font-size: 12px;
                    padding: 0;
                    width: 16px;
                    height: 16px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    border-radius: 2px;
                    transition: background-color 0.2s;
                    pointer-events: auto; /* Réactiver les événements pour ce bouton */
                }}
                .legend-toggle:hover {{
                    background-color: rgba(0, 122, 204, 0.2);
                }}
                .legend-content {{
                    padding: 8px;
                    line-height: 1.2;
                    transition: all 0.3s ease;
                }}
                .legend-content.hidden {{
                    display: none;
                }}
                .legend-item {{
                    display: flex;
                    align-items: center;
                    margin-bottom: 3px;
                    padding: 1px 0;
                    font-size: 9px;
                }}
                .legend-item:hover {{
                    background-color: rgba(0, 122, 204, 0.1);
                    border-radius: 2px;
                    padding: 1px 2px;
                }}
                .legend-collapsed {{
                    min-width: auto;
                    max-width: auto;
                }}
                /* Toggle button */
                .legend-toggle-btn {{
                    position: absolute;
                    top: 5px;
                    right: 5px;
                    background: rgba(255, 255, 255, 0.9);
                    border: 1px solid #ddd;
                    border-radius: 50%;
                    width: 24px;
                    height: 24px;
                    cursor: pointer;
                    font-size: 12px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 1001;
                    transition: all 0.2s ease;
                    pointer-events: auto; /* Assurez-vous que ce bouton reste cliquable */
                }}
                .legend-toggle-btn:hover {{
                    background: rgba(255, 255, 255, 1);
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
                }}
                .legend.hidden {{
                    display: none;
                }}
                #zoom-controls {{
                    position: absolute;
                    bottom: 15px;
                    right: 15px;
                    z-index: 1002;
                    display: flex;
                    flex-direction: column;
                    gap: 5px;
                }}
                #zoom-controls button {{
                    width: 30px;
                    height: 30px;
                    border: 1px solid #ccc;
                    background-color: #fff;
                    border-radius: 50%;
                    font-size: 16px;
                    font-weight: bold;
                    cursor: pointer;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    transition: background-color 0.2s, box-shadow 0.2s;
                    pointer-events: auto;
                }}
                #zoom-controls button:hover {{
                    background-color: #f0f0f0;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.15);
                }}
                /* Responsive adjustments */
                @media (max-width: 768px) {{
                    .legend {{
                        min-width: 80px;
                        max-width: 120px;
                        right: 35px;
                    }}
                    .legend-title {{
                        font-size: 9px;
                    }}
                    .legend-item {{
                        font-size: 8px;
                    }}
                    .svg-container {{
                        padding: 10px;
                    }}
                }}
                @media (max-width: 480px) {{
                    .legend {{
                        min-width: 70px;
                        max-width: 100px;
                        right: 30px;
                    }}
                    .legend-title {{
                        font-size: 8px;
                    }}
                    .legend-item {{
                        font-size: 7px;
                    }}
                }}
                /* Print styles */
                @media print {{
                    .legend {{
                        position: static;
                        float: left;
                        margin: 10px;
                        box-shadow: none;
                        border: 1px solid #333;
                    }}
                    .legend-toggle-btn {{
                        display: none;
                    }}
                    .diagram-container {{
                        height: auto;
                        page-break-inside: avoid;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="diagram-container">
                <div class="svg-container" id="svg-container">
                    {svg_content}
                </div>

                <div id="zoom-controls">
                    <button id="zoom-in-btn" title="Zoom avant">+</button>
                    <button id="zoom-out-btn" title="Zoom arrière">-</button>
                    <button id="reset-zoom-btn" title="Réinitialiser">&#8635;</button>
                </div>
                
                <!-- Toggle button for legend -->
                <button class="legend-toggle-btn" onclick="toggleLegend()" title="Masquer/Afficher la légende">
                    👁️
                </button>
                
                <div class="legend" id="legend">
                    <div class="legend-header">
                        <div class="legend-title">
                            🔍 Légende
                        </div>
                        <button class="legend-toggle" onclick="toggleLegendContent()" title="Réduire/Étendre">
                            <span id="toggle-icon">−</span>
                        </button>
                    </div>
                    <div class="legend-content" id="legend-content">
                        {legend_html}
                    </div>
                </div>
            </div>

            <script>
                // svg-pan-zoom v3.6.1
                // https://github.com/ariutta/svg-pan-zoom
                !function s(r,a,l){function u(e,t){if(!a[e]){if(!r[e]){var o="function"==typeof require&&require;if(!t&&o)return o(e,!0);if(h)return h(e,!0);var n=new Error("Cannot find module '"+e+"'");throw n.code="MODULE_NOT_FOUND",n}var i=a[e]={exports:{}};r[e][0].call(i.exports,function(t){return u(r[e][1][t]||t)},i,i.exports,s,r,a,l)}return a[e].exports}for(var h="function"==typeof require&&require,t=0;t<l.length;t++)u(l[t]);return u}({1:[function(t,e,o){var s=t("./svg-utilities");e.exports={enable:function(t){var e=t.svg.querySelector("defs");if(e||(e=document.createElementNS(s.svgNS,"defs"),t.svg.appendChild(e)),!e.querySelector("style#svg-pan-zoom-controls-styles")){var o=document.createElementNS(s.svgNS,"style");o.setAttribute("id","svg-pan-zoom-controls-styles"),o.setAttribute("type","text/css"),o.textContent=".svg-pan-zoom-control { cursor: pointer; fill: black; fill-opacity: 0.333; } .svg-pan-zoom-control:hover { fill-opacity: 0.8; } .svg-pan-zoom-control-background { fill: white; fill-opacity: 0.5; } .svg-pan-zoom-control-background { fill-opacity: 0.8; }",e.appendChild(o)}var n=document.createElementNS(s.svgNS,"g");n.setAttribute("id","svg-pan-zoom-controls"),n.setAttribute("transform","translate("+(t.width-70)+" "+(t.height-76)+") scale(0.75)"),n.setAttribute("class","svg-pan-zoom-control"),n.appendChild(this._createZoomIn(t)),n.appendChild(this._createZoomReset(t)),n.appendChild(this._createZoomOut(t)),t.svg.appendChild(n),t.controlIcons=n},_createZoomIn:function(t){var e=document.createElementNS(s.svgNS,"g");e.setAttribute("id","svg-pan-zoom-zoom-in"),e.setAttribute("transform","translate(30.5 5) scale(0.015)"),e.setAttribute("class","svg-pan-zoom-control"),e.addEventListener("click",function(){t.getPublicInstance().zoomIn()},!1),e.addEventListener("touchstart",function(){t.getPublicInstance().zoomIn()},!1);var o=document.createElementNS(s.svgNS,"rect");o.setAttribute("x","0"),o.setAttribute("y","0"),o.setAttribute("width","1500"),o.setAttribute("height","1400"),o.setAttribute("class","svg-pan-zoom-control-background"),e.appendChild(o);var n=document.createElementNS(s.svgNS,"path");return n.setAttribute("d","M1280 576v128q0 26 -19 45t-45 19h-320v320q0 26 -19 45t-45 19h-128q-26 0 -45 -19t-19 -45v-320h-320q-26 0 -45 -19t-19 -45v-128q0 -26 19 -45t45 -19h320v-320q0 -26 19 -45t45 -19h128q26 0 45 19t19 45v320h320q26 0 45 19t19 45zM1536 1120v-960 q0 -119 -84.5 -203.5t-203.5 -84.5h-960q-119 0 -203.5 84.5t-84.5 203.5v960q0 119 84.5 203.5t203.5 84.5h960q119 0 203.5 -84.5t84.5 -203.5z"),n.setAttribute("class","svg-pan-zoom-control-element"),e.appendChild(n),e},_createZoomReset:function(t){var e=document.createElementNS(s.svgNS,"g");e.setAttribute("id","svg-pan-zoom-reset-pan-zoom"),e.setAttribute("transform","translate(5 35) scale(0.4)"),e.setAttribute("class","svg-pan-zoom-control"),e.addEventListener("click",function(){t.getPublicInstance().reset()},!1),e.addEventListener("touchstart",function(){t.getPublicInstance().reset()},!1);var o=document.createElementNS(s.svgNS,"rect");o.setAttribute("x","2"),o.setAttribute("y","2"),o.setAttribute("width","182"),o.setAttribute("height","58"),o.setAttribute("class","svg-pan-zoom-control-background"),e.appendChild(o);var n=document.createElementNS(s.svgNS,"path");n.setAttribute("d","M33.051,20.632c-0.742-0.406-1.854-0.609-3.338-0.609h-7.969v9.281h7.769c1.543,0,2.701-0.188,3.473-0.562c1.365-0.656,2.048-1.953,2.048-3.891C35.032,22.757,34.372,21.351,33.051,20.632z"),n.setAttribute("class","svg-pan-zoom-control-element"),e.appendChild(n);var i=document.createElementNS(s.svgNS,"path");return i.setAttribute("d","M170.231,0.5H15.847C7.102,0.5,0.5,5.708,0.5,11.84v38.861C0.5,56.833,7.102,61.5,15.847,61.5h154.384c8.745,0,15.269-4.667,15.269-10.798V11.84C185.5,5.708,178.976,0.5,170.231,0.5z M42.837,48.569h-7.969c-0.219-0.766-0.375-1.383-0.469-1.852c-0.188-0.969-0.289-1.961-0.305-2.977l-0.047-3.211c-0.03-2.203-0.41-3.672-1.142-4.406c-0.732-0.734-2.103-1.102-4.113-1.102h-7.05v13.547h-7.055V14.022h16.524c2.361,0.047,4.178,0.344,5.45,0.891c1.272,0.547,2.351,1.352,3.234,2.414c0.731,0.875,1.31,1.844,1.737,2.906s0.64,2.273,0.64,3.633c0,1.641-0.414,3.254-1.242,4.84s-2.195,2.707-4.102,3.363c1.594,0.641,2.723,1.551,3.387,2.73s0.996,2.98,0.996,5.402v2.32c0,1.578,0.063,2.648,0.19,3.211c0.19,0.891,0.635,1.547,1.333,1.969V48.569z M75.579,48.569h-26.18V14.022h25.336v6.117H56.454v7.336h16.781v6H56.454v8.883h19.125V48.569z M104.497,46.331c-2.44,2.086-5.887,3.129-10.34,3.129c-4.548,0-8.125-1.027-10.731-3.082s-3.909-4.879-3.909-8.473h6.891c0.224,1.578,0.662,2.758,1.316,3.539c1.196,1.422,3.246,2.133,6.15,2.133c1.739,0,3.151-0.188,4.236-0.562c2.058-0.719,3.087-2.055,3.087-4.008c0-1.141-0.504-2.023-1.512-2.648c-1.008-0.609-2.607-1.148-4.796-1.617l-3.74-0.82c-3.676-0.812-6.201-1.695-7.576-2.648c-2.328-1.594-3.492-4.086-3.492-7.477c0-3.094,1.139-5.664,3.417-7.711s5.623-3.07,10.036-3.07c3.685,0,6.829,0.965,9.431,2.895c2.602,1.93,3.966,4.73,4.093,8.402h-6.938c-0.128-2.078-1.057-3.555-2.787-4.43c-1.154-0.578-2.587-0.867-4.301-0.867c-1.907,0-3.428,0.375-4.565,1.125c-1.138,0.75-1.706,1.797-1.706,3.141c0,1.234,0.561,2.156,1.682,2.766c0.721,0.406,2.25,0.883,4.589,1.43l6.063,1.43c2.657,0.625,4.648,1.461,5.975,2.508c2.059,1.625,3.089,3.977,3.089,7.055C108.157,41.624,106.937,44.245,104.497,46.331z M139.61,48.569h-26.18V14.022h25.336v6.117h-18.281v7.336h16.781v6h-16.781v8.883h19.125V48.569z M170.337,20.14h-10.336v28.43h-7.266V20.14h-10.383v-6.117h27.984V20.14z"),i.setAttribute("class","svg-pan-zoom-control-element"),e.appendChild(i),e},_createZoomOut:function(t){var e=document.createElementNS(s.svgNS,"g");e.setAttribute("id","svg-pan-zoom-zoom-out"),e.setAttribute("transform","translate(30.5 70) scale(0.015)"),e.setAttribute("class","svg-pan-zoom-control"),e.addEventListener("click",function(){t.getPublicInstance().zoomOut()},!1),e.addEventListener("touchstart",function(){t.getPublicInstance().zoomOut()},!1);var o=document.createElementNS(s.svgNS,"rect");o.setAttribute("x","0"),o.setAttribute("y","0"),o.setAttribute("width","1500"),o.setAttribute("height","1400"),o.setAttribute("class","svg-pan-zoom-control-background"),e.appendChild(o);var n=document.createElementNS(s.svgNS,"path");return n.setAttribute("d","M1280 576v128q0 26 -19 45t-45 19h-896q-26 0 -45 -19t-19 -45v-128q0 -26 19 -45t45 -19h896q26 0 45 19t19 45zM1536 1120v-960q0 -119 -84.5 -203.5t-203.5 -84.5h-960q-119 0 -203.5 84.5t-84.5 203.5v960q0 119 84.5 203.5t203.5 84.5h960q119 0 203.5 -84.5 t84.5 -203.5z"),n.setAttribute("class","svg-pan-zoom-control-element"),e.appendChild(n),e},disable:function(t){t.controlIcons&&(t.controlIcons.parentNode.removeChild(t.controlIcons),t.controlIcons=null)}}},{"./svg-utilities":5}],2:[function(t,e,o){function n(t,e){this.init(t,e)}var i=t("./svg-utilities"),r=t("./utilities");n.prototype.init=function(t,e){this.viewport=t,this.options=e,this.originalState={zoom:1,x:0,y:0},this.activeState={zoom:1,x:0,y:0},this.updateCTMCached=r.proxy(this.updateCTM,this),this.requestAnimationFrame=r.createRequestAnimationFrame(this.options.refreshRate),this.viewBox={x:0,y:0,width:0,height:0},this.cacheViewBox();var o=this.processCTM();this.setCTM(o),this.updateCTM()},n.prototype.cacheViewBox=function(){var t=this.options.svg.getAttribute("viewBox");if(t){var e=t.split(/[\s\,]/).filter(function(t){return t}).map(parseFloat);this.viewBox.x=e[0],this.viewBox.y=e[1],this.viewBox.width=e[2],this.viewBox.height=e[3];var o=Math.min(this.options.width/this.viewBox.width,this.options.height/this.viewBox.height);this.activeState.zoom=o,this.activeState.x=(this.options.width-this.viewBox.width*o)/2,this.activeState.y=(this.options.height-this.viewBox.height*o)/2,this.updateCTMOnNextFrame(),this.options.svg.removeAttribute("viewBox")}else this.simpleViewBoxCache()},n.prototype.simpleViewBoxCache=function(){var t=this.viewport.getBBox();this.viewBox.x=t.x,this.viewBox.y=t.y,this.viewBox.width=t.width,this.viewBox.height=t.height},n.prototype.getViewBox=function(){return r.extend({},this.viewBox)},n.prototype.processCTM=function(){var t,e=this.getCTM();(this.options.fit||this.options.contain)&&(t=this.options.fit?Math.min(this.options.width/this.viewBox.width,this.options.height/this.viewBox.height):Math.max(this.options.width/this.viewBox.width,this.options.height/this.viewBox.height),e.a=t,e.d=t,e.e=-this.viewBox.x*t,e.f=-this.viewBox.y*t);if(this.options.center){var o=.5*(this.options.width-(this.viewBox.width+2*this.viewBox.x)*e.a),n=.5*(this.options.height-(this.viewBox.height+2*this.viewBox.y)*e.a);e.e=o,e.f=n}return this.originalState.zoom=e.a,this.originalState.x=e.e,this.originalState.y=e.f,e},n.prototype.getOriginalState=function(){return r.extend({},this.originalState)},n.prototype.getState=function(){return r.extend({},this.activeState)},n.prototype.getZoom=function(){return this.activeState.zoom},n.prototype.getRelativeZoom=function(){return this.activeState.zoom/this.originalState.zoom},n.prototype.computeRelativeZoom=function(t){return t/this.originalState.zoom},n.prototype.getPan=function(){return{x:this.activeState.x,y:this.activeState.y}},n.prototype.getCTM=function(){var t=this.options.svg.createSVGMatrix();return t.a=this.activeState.zoom,t.b=0,t.c=0,t.d=this.activeState.zoom,t.e=this.activeState.x,t.f=this.activeState.y,t},n.prototype.setCTM=function(t){var e=this.isZoomDifferent(t),o=this.isPanDifferent(t);if(e||o){if(e&&(!1===this.options.beforeZoom(this.getRelativeZoom(),this.computeRelativeZoom(t.a))?(t.a=t.d=this.activeState.zoom,e=!1):(this.updateCache(t),this.options.onZoom(this.getRelativeZoom()))),o){var n=this.options.beforePan(this.getPan(),{x:t.e,y:t.f}),i=!1,s=!1;!1===n?(t.e=this.getPan().x,t.f=this.getPan().y,i=s=!0):r.isObject(n)&&(!1===n.x?(t.e=this.getPan().x,i=!0):r.isNumber(n.x)&&(t.e=n.x),!1===n.y?(t.f=this.getPan().y,s=!0):r.isNumber(n.y)&&(t.f=n.y)),i&&s||!this.isPanDifferent(t)?o=!1:(this.updateCache(t),this.options.onPan(this.getPan()))}(e||o)&&this.updateCTMOnNextFrame()}},n.prototype.isZoomDifferent=function(t){return this.activeState.zoom!==t.a},n.prototype.isPanDifferent=function(t){return this.activeState.x!==t.e||this.activeState.y!==t.f},n.prototype.updateCache=function(t){this.activeState.zoom=t.a,this.activeState.x=t.e,this.activeState.y=t.f},n.prototype.pendingUpdate=!1,n.prototype.updateCTMOnNextFrame=function(){this.pendingUpdate||(this.pendingUpdate=!0,this.requestAnimationFrame.call(window,this.updateCTMCached))},n.prototype.updateCTM=function(){var t=this.getCTM();i.setCTM(this.viewport,t,this.defs),this.pendingUpdate=!1,this.options.onUpdatedCTM&&this.options.onUpdatedCTM(t)},e.exports=function(t,e){return new n(t,e)}},{"./svg-utilities":5,"./utilities":7}],3:[function(t,e,o){var n,i=t("./svg-pan-zoom.js");n=window,document,"function"==typeof define&&define.amd?define("svg-pan-zoom",function(){return i}):void 0!==e&&e.exports&&(e.exports=i,n.svgPanZoom=i)},{"./svg-pan-zoom.js":4}],4:[function(t,e,o){function i(t,e){this.init(t,e)}var n=t("./uniwheel"),s=t("./control-icons"),r=t("./utilities"),a=t("./svg-utilities"),l=t("./shadow-viewport"),u={viewportSelector:".svg-pan-zoom_viewport",panEnabled:!0,controlIconsEnabled:!1,zoomEnabled:!0,dblClickZoomEnabled:!0,mouseWheelZoomEnabled:!0,preventMouseEventsDefault:!0,zoomScaleSensitivity:.1,minZoom:.5,maxZoom:10,fit:!0,contain:!1,center:!0,refreshRate:"auto",beforeZoom:null,onZoom:null,beforePan:null,onPan:null,customEventsHandler:null,eventsListenerElement:null,onUpdatedCTM:null},h={passive:!0};i.prototype.init=function(t,e){var o=this;this.svg=t,this.defs=t.querySelector("defs"),a.setupSvgAttributes(this.svg),this.options=r.extend(r.extend({},u),e),this.state="none";var n=a.getBoundingClientRectNormalized(t);this.width=n.width,this.height=n.height,this.viewport=l(a.getOrCreateViewport(this.svg,this.options.viewportSelector),{svg:this.svg,width:this.width,height:this.height,fit:this.options.fit,contain:this.options.contain,center:this.options.center,refreshRate:this.options.refreshRate,beforeZoom:function(t,e){if(o.viewport&&o.options.beforeZoom)return o.options.beforeZoom(t,e)},onZoom:function(t){if(o.viewport&&o.options.onZoom)return o.options.onZoom(t)},beforePan:function(t,e){if(o.viewport&&o.options.beforePan)return o.options.beforePan(t,e)},onPan:function(t){if(o.viewport&&o.options.onPan)return o.options.onPan(t)},onUpdatedCTM:function(t){if(o.viewport&&o.options.onUpdatedCTM)return o.options.onUpdatedCTM(t)}});var i=this.getPublicInstance();i.setBeforeZoom(this.options.beforeZoom),i.setOnZoom(this.options.onZoom),i.setBeforePan(this.options.beforePan),i.setOnPan(this.options.onPan),i.setOnUpdatedCTM(this.options.onUpdatedCTM),this.options.controlIconsEnabled&&s.enable(this),this.lastMouseWheelEventTime=Date.now(),this.setupHandlers()},i.prototype.setupHandlers=function(){var o=this,n=null;if(this.eventListeners={mousedown:function(t){var e=o.handleMouseDown(t,n);return n=t,e},touchstart:function(t){var e=o.handleMouseDown(t,n);return n=t,e},mouseup:function(t){return o.handleMouseUp(t)},touchend:function(t){return o.handleMouseUp(t)},mousemove:function(t){return o.handleMouseMove(t)},touchmove:function(t){return o.handleMouseMove(t)},mouseleave:function(t){return o.handleMouseUp(t)},touchleave:function(t){return o.handleMouseUp(t)},touchcancel:function(t){return o.handleMouseUp(t)}},null!=this.options.customEventsHandler){this.options.customEventsHandler.init({svgElement:this.svg,eventsListenerElement:this.options.eventsListenerElement,instance:this.getPublicInstance()});var t=this.options.customEventsHandler.haltEventListeners;if(t&&t.length)for(var e=t.length-1;0<=e;e--)this.eventListeners.hasOwnProperty(t[e])&&delete this.eventListeners[t[e]]}for(var i in this.eventListeners)(this.options.eventsListenerElement||this.svg).addEventListener(i,this.eventListeners[i],!this.options.preventMouseEventsDefault&&h);this.options.mouseWheelZoomEnabled&&(this.options.mouseWheelZoomEnabled=!1,this.enableMouseWheelZoom())},i.prototype.enableMouseWheelZoom=function(){if(!this.options.mouseWheelZoomEnabled){var e=this;this.wheelListener=function(t){return e.handleMouseWheel(t)};var t=!this.options.preventMouseEventsDefault;n.on(this.options.eventsListenerElement||this.svg,this.wheelListener,t),this.options.mouseWheelZoomEnabled=!0}},i.prototype.disableMouseWheelZoom=function(){if(this.options.mouseWheelZoomEnabled){var t=!this.options.preventMouseEventsDefault;n.off(this.options.eventsListenerElement||this.svg,this.wheelListener,t),this.options.mouseWheelZoomEnabled=!1}},i.prototype.handleMouseWheel=function(t){if(this.options.zoomEnabled&&"none"===this.state){this.options.preventMouseEventsDefault&&(t.preventDefault?t.preventDefault():t.returnValue=!1);var e=t.deltaY||1,o=Date.now()-this.lastMouseWheelEventTime,n=3+Math.max(0,30-o);this.lastMouseWheelEventTime=Date.now(),"deltaMode"in t&&0===t.deltaMode&&t.wheelDelta&&(e=0===t.deltaY?0:Math.abs(t.wheelDelta)/t.deltaY),e=-.3<e&&e<.3?e:(0<e?1:-1)*Math.log(Math.abs(e)+10)/n;var i=this.svg.getScreenCTM().inverse(),s=a.getEventPoint(t,this.svg).matrixTransform(i),r=Math.pow(1+this.options.zoomScaleSensitivity,-1*e);this.zoomAtPoint(r,s)}},i.prototype.zoomAtPoint=function(t,e,o){var n=this.viewport.getOriginalState();o?(t=Math.max(this.options.minZoom*n.zoom,Math.min(this.options.maxZoom*n.zoom,t)),t/=this.getZoom()):this.getZoom()*t<this.options.minZoom*n.zoom?t=this.options.minZoom*n.zoom/this.getZoom():this.getZoom()*t>this.options.maxZoom*n.zoom&&(t=this.options.maxZoom*n.zoom/this.getZoom());var i=this.viewport.getCTM(),s=e.matrixTransform(i.inverse()),r=this.svg.createSVGPoint().translate(s.x,s.y).scale(t).translate(-s.x,-s.y),a=i.multiply(r);a.a!==i.a&&this.viewport.setCTM(a)},i.prototype.zoom=function(t,e){this.zoomAtPoint(t,a.getSvgCenterPoint(this.svg,this.width,this.height),e)},i.prototype.publicZoom=function(t,e){e&&(t=this.computeFromRelativeZoom(t)),this.zoom(t,e)},i.prototype.publicZoomAtPoint=function(t,e,o){if(o&&(t=this.computeFromRelativeZoom(t)),"SVGPoint"!==r.getType(e)){if(!("x"in e&&"y"in e))throw new Error("Given point is invalid");e=a.createSVGPoint(this.svg,e.x,e.y)}this.zoomAtPoint(t,e,o)},i.prototype.getZoom=function(){return this.viewport.getZoom()},i.prototype.getRelativeZoom=function(){return this.viewport.getRelativeZoom()},i.prototype.computeFromRelativeZoom=function(t){return t*this.viewport.getOriginalState().zoom},i.prototype.resetZoom=function(){var t=this.viewport.getOriginalState();this.zoom(t.zoom,!0)},i.prototype.resetPan=function(){this.pan(this.viewport.getOriginalState())},i.prototype.reset=function(){this.resetZoom(),this.resetPan()},i.prototype.handleDblClick=function(t){var e;if((this.options.preventMouseEventsDefault&&(t.preventDefault?t.preventDefault():t.returnValue=!1),this.options.controlIconsEnabled)&&-1<(t.target.getAttribute("class")||"").indexOf("svg-pan-zoom-control"))return!1;e=t.shiftKey?1/(2*(1+this.options.zoomScaleSensitivity)):2*(1+this.options.zoomScaleSensitivity);var o=a.getEventPoint(t,this.svg).matrixTransform(this.svg.getScreenCTM().inverse());this.zoomAtPoint(e,o)},i.prototype.handleMouseDown=function(t,e){this.options.preventMouseEventsDefault&&(t.preventDefault?t.preventDefault():t.returnValue=!1),r.mouseAndTouchNormalize(t,this.svg),this.options.dblClickZoomEnabled&&r.isDblClick(t,e)?this.handleDblClick(t):(this.state="pan",this.firstEventCTM=this.viewport.getCTM(),this.stateOrigin=a.getEventPoint(t,this.svg).matrixTransform(this.firstEventCTM.inverse()))},i.prototype.handleMouseMove=function(t){if(this.options.preventMouseEventsDefault&&(t.preventDefault?t.preventDefault():t.returnValue=!1),"pan"===this.state&&this.options.panEnabled){var e=a.getEventPoint(t,this.svg).matrixTransform(this.firstEventCTM.inverse()),o=this.firstEventCTM.translate(e.x-this.stateOrigin.x,e.y-this.stateOrigin.y);this.viewport.setCTM(o)}},i.prototype.handleMouseUp=function(t){this.options.preventMouseEventsDefault&&(t.preventDefault?t.preventDefault():t.returnValue=!1),"pan"===this.state&&(this.state="none")},i.prototype.fit=function(){var t=this.viewport.getViewBox(),e=Math.min(this.width/t.width,this.height/t.height);this.zoom(e,!0)},i.prototype.contain=function(){var t=this.viewport.getViewBox(),e=Math.max(this.width/t.width,this.height/t.height);this.zoom(e,!0)},i.prototype.center=function(){var t=this.viewport.getViewBox(),e=.5*(this.width-(t.width+2*t.x)*this.getZoom()),o=.5*(this.height-(t.height+2*t.y)*this.getZoom());this.getPublicInstance().pan({x:e,y:o})},i.prototype.updateBBox=function(){this.viewport.simpleViewBoxCache()},i.prototype.pan=function(t){var e=this.viewport.getCTM();e.e=t.x,e.f=t.y,this.viewport.setCTM(e)},i.prototype.panBy=function(t){var e=this.viewport.getCTM();e.e+=t.x,e.f+=t.y,this.viewport.setCTM(e)},i.prototype.getPan=function(){var t=this.viewport.getState();return{x:t.x,y:t.y}},i.prototype.resize=function(){var t=a.getBoundingClientRectNormalized(this.svg);this.width=t.width,this.height=t.height;var e=this.viewport;e.options.width=this.width,e.options.height=this.height,e.processCTM(),this.options.controlIconsEnabled&&(this.getPublicInstance().disableControlIcons(),this.getPublicInstance().enableControlIcons())},i.prototype.destroy=function(){var e=this;for(var t in this.beforeZoom=null,this.onZoom=null,this.beforePan=null,this.onPan=null,(this.onUpdatedCTM=null)!=this.options.customEventsHandler&&this.options.customEventsHandler.destroy({svgElement:this.svg,eventsListenerElement:this.options.eventsListenerElement,instance:this.getPublicInstance()}),this.eventListeners)(this.options.eventsListenerElement||this.svg).removeEventListener(t,this.eventListeners[t],!this.options.preventMouseEventsDefault&&h);this.disableMouseWheelZoom(),this.getPublicInstance().disableControlIcons(),this.reset(),c=c.filter(function(t){return t.svg!==e.svg}),delete this.options,delete this.viewport,delete this.publicInstance,delete this.pi,this.getPublicInstance=function(){return null}},i.prototype.getPublicInstance=function(){var o=this;return this.publicInstance||(this.publicInstance=this.pi={enablePan:function(){return o.options.panEnabled=!0,o.pi},disablePan:function(){return o.options.panEnabled=!1,o.pi},isPanEnabled:function(){return!!o.options.panEnabled},pan:function(t){return o.pan(t),o.pi},panBy:function(t){return o.panBy(t),o.pi},getPan:function(){return o.getPan()},setBeforePan:function(t){return o.options.beforePan=null===t?null:r.proxy(t,o.publicInstance),o.pi},setOnPan:function(t){return o.options.onPan=null===t?null:r.proxy(t,o.publicInstance),o.pi},enableZoom:function(){return o.options.zoomEnabled=!0,o.pi},disableZoom:function(){return o.options.zoomEnabled=!1,o.pi},isZoomEnabled:function(){return!!o.options.zoomEnabled},enableControlIcons:function(){return o.options.controlIconsEnabled||(o.options.controlIconsEnabled=!0,s.enable(o)),o.pi},disableControlIcons:function(){return o.options.controlIconsEnabled&&(o.options.controlIconsEnabled=!1,s.disable(o)),o.pi},isControlIconsEnabled:function(){return!!o.options.controlIconsEnabled},enableDblClickZoom:function(){return o.options.dblClickZoomEnabled=!0,o.pi},disableDblClickZoom:function(){return o.options.dblClickZoomEnabled=!1,o.pi},isDblClickZoomEnabled:function(){return!!o.options.dblClickZoomEnabled},enableMouseWheelZoom:function(){return o.enableMouseWheelZoom(),o.pi},disableMouseWheelZoom:function(){return o.disableMouseWheelZoom(),o.pi},isMouseWheelZoomEnabled:function(){return!!o.options.mouseWheelZoomEnabled},setZoomScaleSensitivity:function(t){return o.options.zoomScaleSensitivity=t,o.pi},setMinZoom:function(t){return o.options.minZoom=t,o.pi},setMaxZoom:function(t){return o.options.maxZoom=t,o.pi},setBeforeZoom:function(t){return o.options.beforeZoom=null===t?null:r.proxy(t,o.publicInstance),o.pi},setOnZoom:function(t){return o.options.onZoom=null===t?null:r.proxy(t,o.publicInstance),o.pi},zoom:function(t){return o.publicZoom(t,!0),o.pi},zoomBy:function(t){return o.publicZoom(t,!1),o.pi},zoomAtPoint:function(t,e){return o.publicZoomAtPoint(t,e,!0),o.pi},zoomAtPointBy:function(t,e){return o.publicZoomAtPoint(t,e,!1),o.pi},zoomIn:function(){return this.zoomBy(1+o.options.zoomScaleSensitivity),o.pi},zoomOut:function(){return this.zoomBy(1/(1+o.options.zoomScaleSensitivity)),o.pi},getZoom:function(){return o.getRelativeZoom()},setOnUpdatedCTM:function(t){return o.options.onUpdatedCTM=null===t?null:r.proxy(t,o.publicInstance),o.pi},resetZoom:function(){return o.resetZoom(),o.pi},resetPan:function(){return o.resetPan(),o.pi},reset:function(){return o.reset(),o.pi},fit:function(){return o.fit(),o.pi},contain:function(){return o.contain(),o.pi},center:function(){return o.center(),o.pi},updateBBox:function(){return o.updateBBox(),o.pi},resize:function(){return o.resize(),o.pi},getSizes:function(){return{width:o.width,height:o.height,realZoom:o.getZoom(),viewBox:o.viewport.getViewBox()}},destroy:function(){return o.destroy(),o.pi}}),this.publicInstance};var c=[];e.exports=function(t,e){var o=r.getSvg(t);if(null===o)return null;for(var n=c.length-1;0<=n;n--)if(c[n].svg===o)return c[n].instance.getPublicInstance();return c.push({svg:o,instance:new i(o,e)}),c[c.length-1].instance.getPublicInstance()}},{"./control-icons":1,"./shadow-viewport":2,"./svg-utilities":5,"./uniwheel":6,"./utilities":7}],5:[function(t,e,o){var l=t("./utilities"),s="unknown";document.documentMode&&(s="ie"),e.exports={svgNS:"http://www.w3.org/2000/svg",xmlNS:"http://www.w3.org/XML/1998/namespace",xmlnsNS:"http://www.w3.org/2000/xmlns/",xlinkNS:"http://www.w3.org/1999/xlink",evNS:"http://www.w3.org/2001/xml-events",getBoundingClientRectNormalized:function(t){if(t.clientWidth&&t.clientHeight)return{width:t.clientWidth,height:t.clientHeight};if(t.getBoundingClientRect())return t.getBoundingClientRect();throw new Error("Cannot get BoundingClientRect for SVG.")},getOrCreateViewport:function(t,e){var o=null;if(!(o=l.isElement(e)?e:t.querySelector(e))){var n=Array.prototype.slice.call(t.childNodes||t.children).filter(function(t){return"defs"!==t.nodeName&&"#text"!==t.nodeName});1===n.length&&"g"===n[0].nodeName&&null===n[0].getAttribute("transform")&&(o=n[0])}if(!o){var i="viewport-"+(new Date).toISOString().replace(/\D/g,"");(o=document.createElementNS(this.svgNS,"g")).setAttribute("id",i);var s=t.childNodes||t.children;if(s&&0<s.length)for(var r=s.length;0<r;r--)"defs"!==s[s.length-r].nodeName&&o.appendChild(s[s.length-r]);t.appendChild(o)}var a=[];return o.getAttribute("class")&&(a=o.getAttribute("class").split(" ")),~a.indexOf("svg-pan-zoom_viewport")||(a.push("svg-pan-zoom_viewport"),o.setAttribute("class",a.join(" "))),o},setupSvgAttributes:function(t){if(t.setAttribute("xmlns",this.svgNS),t.setAttributeNS(this.xmlnsNS,"xmlns:xlink",this.xlinkNS),t.setAttributeNS(this.xmlnsNS,"xmlns:ev",this.evNS),null!==t.parentNode){var e=t.getAttribute("style")||"";-1===e.toLowerCase().indexOf("overflow")&&t.setAttribute("style","overflow: hidden; "+e)}},internetExplorerRedisplayInterval:300,refreshDefsGlobal:l.throttle(function(){for(var t=document.querySelectorAll("defs"),e=t.length,o=0;o<e;o++){var n=t[o];n.parentNode.insertBefore(n,n)}},this?this.internetExplorerRedisplayInterval:null),setCTM:function(t,e,o){var n=this,i="matrix("+e.a+","+e.b+","+e.c+","+e.d+","+e.e+","+e.f+")";t.setAttributeNS(null,"transform",i),"transform"in t.style?t.style.transform=i:"-ms-transform"in t.style?t.style["-ms-transform"]=i:"-webkit-transform"in t.style&&(t.style["-webkit-transform"]=i),"ie"===s&&o&&(o.parentNode.insertBefore(o,o),window.setTimeout(function(){n.refreshDefsGlobal()},n.internetExplorerRedisplayInterval))},getEventPoint:function(t,e){var o=e.createSVGPoint();return l.mouseAndTouchNormalize(t,e),o.x=t.clientX,o.y=t.clientY,o},getSvgCenterPoint:function(t,e,o){return this.createSVGPoint(t,e/2,o/2)},createSVGPoint:function(t,e,o){var n=t.createSVGPoint();return n.x=e,n.y=o,n}}},{"./utilities":7}],6:[function(t,e,o){function n(t,e,o,n){var i;i="wheel"===a?o:function(t,o){function e(t){var e={originalEvent:t=t||window.event,target:t.target||t.srcElement,type:"wheel",deltaMode:"MozMousePixelScroll"==t.type?0:1,deltaX:0,delatZ:0,preventDefault:function(){t.preventDefault?t.preventDefault():t.returnValue=!1}};return"mousewheel"==a?(e.deltaY=-.025*t.wheelDelta,t.wheelDeltaX&&(e.deltaX=-.025*t.wheelDeltaX)):e.deltaY=t.detail,o(e)}return u.push({element:t,fn:e}),e}(t,o),t[s](l+e,i,!!n&&h)}function i(t,e,o,n){var i;i="wheel"===a?o:function(t){for(var e=0;e<u.length;e++)if(u[e].element===t)return u[e].fn;return function(){}}(t),t[r](l+e,i,!!n&&h),function(t){for(var e=0;e<u.length;e++)if(u[e].element===t)return u.splice(e,1)}(t)}var s,r,a,l,u,h;e.exports=(u=[],h={passive:!(l="")},window.addEventListener?(s="addEventListener",r="removeEventListener"):(s="attachEvent",r="detachEvent",l="on"),a="onwheel"in document.createElement("div")?"wheel":void 0!==document.onmousewheel?"mousewheel":"DOMMouseScroll",{on:function(t,e,o){n(t,a,e,o),"DOMMouseScroll"==a&&n(t,"MozMousePixelScroll",e,o)},off:function(t,e,o){i(t,a,e,o),"DOMMouseScroll"==a&&i(t,"MozMousePixelScroll",e,o)}})},{}],7:[function(t,e,o){function n(e){return function(t){window.setTimeout(t,e)}}e.exports={extend:function(t,e){for(var o in t=t||{},e)this.isObject(e[o])?t[o]=this.extend(t[o],e[o]):t[o]=e[o];return t},isElement:function(t){return t instanceof HTMLElement||t instanceof SVGElement||t instanceof SVGSVGElement||t&&"object"==typeof t&&null!==t&&1===t.nodeType&&"string"==typeof t.nodeName},isObject:function(t){return"[object Object]"===Object.prototype.toString.call(t)},isNumber:function(t){return!isNaN(parseFloat(t))&&isFinite(t)},getSvg:function(t){var e,o;if(this.isElement(t))e=t;else{if(!("string"==typeof t||t instanceof String))throw new Error("Provided selector is not an HTML object nor String");if(!(e=document.querySelector(t)))throw new Error("Provided selector did not find any elements. Selector: "+t)}if("svg"===e.tagName.toLowerCase())o=e;else if("object"===e.tagName.toLowerCase())o=e.contentDocument.documentElement;else{if("embed"!==e.tagName.toLowerCase())throw"img"===e.tagName.toLowerCase()?new Error('Cannot script an SVG in an "img" element. Please use an "object" element or an in-line SVG.'):new Error("Cannot get SVG.");o=e.getSVGDocument().documentElement}return o},proxy:function(t,e){return function(){return t.apply(e,arguments)}},getType:function(t){return Object.prototype.toString.apply(t).replace(/^\[object\s/,"").replace(/\]$/,"")},mouseAndTouchNormalize:function(t,e){if(void 0===t.clientX||null===t.clientX)if(t.clientX=0,void(t.clientY=0)!==t.touches&&t.touches.length){if(void 0!==t.touches[0].clientX)t.clientX=t.touches[0].clientX,t.clientY=t.touches[0].clientY;else if(void 0!==t.touches[0].pageX){var o=e.getBoundingClientRect();t.clientX=t.touches[0].pageX-o.left,t.clientY=t.touches[0].pageY-o.top}}else void 0!==t.originalEvent&&void 0!==t.originalEvent.clientX&&(t.clientX=t.originalEvent.clientX,t.clientY=t.originalEvent.clientY)},isDblClick:function(t,e){if(2===t.detail)return!0;if(null==e)return!1;var o=t.timeStamp-e.timeStamp,n=Math.sqrt(Math.pow(t.clientX-e.clientX,2)+Math.pow(t.clientY-e.clientY,2));return o<250&&n<10},now:Date.now||function(){return(new Date).getTime()},throttle:function(o,n,i){var s,r,a,l=this,u=null,h=0;i=i||{};function c(){h=!1===i.leading?0:l.now(),u=null,a=o.apply(s,r),u||(s=r=null)}return function(){var t=l.now();h||!1!==i.leading||(h=t);var e=n-(t-h);return s=this,r=arguments,e<=0||n<e?(clearTimeout(u),u=null,h=t,a=o.apply(s,r),u||(s=r=null)):u||!1===i.trailing||(u=setTimeout(c,e)),a}},createRequestAnimationFrame:function(t){var e=null;return"auto"!==t&&t<60&&1<t&&(e=Math.floor(1e3/t)),null===e?window.requestAnimationFrame||n(33):n(e)}}},{}]},{},[3]);
            </script>
            <script>
                // La fonctionnalité de drag & drop a été supprimée.
                
                // Fonction pour masquer/afficher la légende
                function toggleLegend() {
                    const legend = document.getElementById('legend');
                    const toggleBtn = document.querySelector('.legend-toggle-btn');
                    
                    if (legend.classList.contains('hidden')) {
                        legend.classList.remove('hidden');
                        toggleBtn.innerHTML = '👁️';
                        toggleBtn.title = 'Masquer la légende';
                    } else {
                        legend.classList.add('hidden');
                        toggleBtn.innerHTML = '👁️‍🗨️';
                        toggleBtn.title = 'Afficher la légende';
                    }
                }
                
                // Fonction pour réduire/étendre le contenu de la légende
                function toggleLegendContent() {
                    const content = document.getElementById('legend-content');
                    const icon = document.getElementById('toggle-icon');
                    const legend = document.getElementById('legend');
                    
                    if (content.classList.contains('hidden')) {
                        content.classList.remove('hidden');
                        icon.textContent = '−';
                        legend.classList.remove('legend-collapsed');
                    } else {
                        content.classList.add('hidden');
                        icon.textContent = '+';
                        legend.classList.add('legend-collapsed');
                    }
                }

                // Initialisation du pan/zoom sur le SVG
                window.addEventListener('load', () => {
                    const svgElement = document.querySelector('#svg-container svg');
                    if (svgElement) {
                        const panZoomInstance = svgPanZoom(svgElement, {
                            zoomEnabled: true,
                            panEnabled: true,
                            controlIconsEnabled: false, // On utilise nos propres contrôles
                            fit: true,
                            center: true,
                            minZoom: 0.1,
                            maxZoom: 20
                        });

                        document.getElementById('zoom-in-btn').addEventListener('click', () => panZoomInstance.zoomIn());
                        document.getElementById('zoom-out-btn').addEventListener('click', () => panZoomInstance.zoomOut());
                        document.getElementById('reset-zoom-btn').addEventListener('click', () => panZoomInstance.reset());
                    }
                });
            </script>
        </body>
        </html>"""

    def _get_protocol_styles_from_model(self, threat_model) -> Dict[str, Dict]:
        """
        Extracts defined protocol styles from the threat model.
        """
        try:
            if hasattr(threat_model, 'get_all_protocol_styles'):
                return threat_model.get_all_protocol_styles()
            if hasattr(threat_model, 'protocol_styles'):
                return threat_model.protocol_styles
        except Exception as e:
            logging.warning(f"⚠️ Error extracting protocol styles: {e}")
        
        return {}

    def check_graphviz_installation(self) -> bool:
        """Checks if Graphviz is installed"""
        try:
            result = subprocess.run([self.dot_executable, "-V"], 
                                  capture_output=True, text=True, check=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except subprocess.CalledProcessError as e:
            
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

