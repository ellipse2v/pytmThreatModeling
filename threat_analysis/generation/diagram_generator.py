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
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from threat_analysis.core.models_module import ThreatModel

class DiagramGenerator:
    """Enhanced class for threat model diagram generation with protocol styles and boundary attributes"""
    
    def __init__(self):
        self.dot_executable = "dot"
        self.supported_formats = ["svg", "png", "pdf", "ps"]
        self.template_env = Environment(loader=FileSystemLoader(Path(__file__).parent.parent / "templates"))
    
    def generate_dot_file_from_model(self, threat_model, output_file: str) -> Optional[str]:
        """
        Generates DOT code from the threat model, saves it to a file,
        and returns the DOT code as a string.
        """
        try:
            dot_code = self._generate_manual_dot(threat_model)
            
            if not dot_code or not dot_code.strip():
                logging.error("❌ Unable to generate DOT code from model. DOT code is empty.")
                return None

            cleaned_dot = self._clean_dot_code(dot_code)
            output_path_obj = Path(output_file)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path_obj, "w", encoding="utf-8", newline='\n') as f:
                f.write(cleaned_dot)
            logging.info(f"✅ DOT file generated: {output_file}")
            return cleaned_dot  # Return the content
        except Exception as e:
            logging.error(f"❌ Error during DOT file generation: {e}")
            return None

    def generate_diagram_from_dot(self, dot_code: str, output_file: str, format: str = "svg") -> Optional[str]:
        """Generates a diagram from a DOT string using Graphviz."""
        if format not in self.supported_formats:
            logging.error(f"❌ Unsupported format: {format}. Supported formats: {self.supported_formats}")
            return None
            
        if not self.check_graphviz_installation():
            logging.error("❌ Graphviz not found!")
            logging.warning(self.get_installation_instructions())
            return None
            
        try:
            output_path_obj = Path(output_file)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)
            output_path = str(output_path_obj.with_suffix(f'.{format}'))

            cleaned_dot = self._clean_dot_code(dot_code)
            
            subprocess.run(
                [self.dot_executable, f"-T{format}", "-o", output_path],
                input=cleaned_dot,
                text=True,
                encoding='utf-8',
                capture_output=True,
                check=True
            )
            
            if Path(output_path).exists():
                return output_path
            else:
                logging.error(f"❌ Output file was not created: {output_path}")
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
            attributes.append('shape=box')
            attributes.append('style=filled')
            attributes.append('fillcolor=lightgreen')
            icon = '🌐 '
            default_fillcolor = 'lightgreen'
        
        # Check for API
        elif 'api' in node_name_lower:
            attributes.append('shape=box')
            attributes.append('style=filled')
            attributes.append('fillcolor=lightyellow')
            icon = '🔌 '
            default_fillcolor = 'lightyellow'
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

        # Add id for easier lookup
        attributes.append(f'id="{self._sanitize_name(node_name)}"')
        
        return f'[{", ".join(attributes)}]'

    def add_links_to_svg(self, svg_content: str, threat_model: ThreatModel) -> str:
        """
        Adds hyperlinks to the SVG content for nodes with submodels.
        """
        ET.register_namespace("", "http://www.w3.org/2000/svg")
        ET.register_namespace("xlink", "http://www.w3.org/1999/xlink")

        root = ET.fromstring(svg_content)

        for server in threat_model.servers:
            if 'submodel' in server:
                server_name = server['name']
                sanitized_name = self._sanitize_name(server_name)

                submodel_path = Path(server['submodel'])
                # Correctly form the relative path for the link
                link_href = f"{submodel_path.parent.name}/{submodel_path.stem}_diagram.html"

                # Find the node group for the server
                for g in root.findall(f".//{{http://www.w3.org/2000/svg}}g[@id='{sanitized_name}']"):
                    link = ET.Element('a')
                    link.set('xlink:href', link_href)

                    # Move all children of g to the new link element
                    for child in list(g):
                        link.append(child)
                        g.remove(child)

                    g.append(link)

        return ET.tostring(root, encoding='unicode', method='xml')

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
        template = self.template_env.get_template("diagram_template.html")
        model_name = threat_model.name if hasattr(threat_model, 'name') else 'Threat Model'
        return template.render(
            title=f"Diagramme de Menaces - {model_name}",
            svg_content=svg_content,
            legend_html=legend_html
        )

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

