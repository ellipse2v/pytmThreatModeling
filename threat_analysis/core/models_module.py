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
Threat Model Definition Module with MITRE ATT&CK Integration
"""
from pytm import TM, Boundary, Actor, Server, Dataflow, Data
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple
import logging
from .mitre_mapping_module import MitreMapping

class CustomThreat:
    """A simple class to represent a custom threat."""
    def __init__(self, name, description, stride_category, mitre_technique_id, target):
        self.name = name
        self.description = description
        self.stride_category = stride_category
        self.mitre_technique_id = mitre_technique_id
        self.target = target

    def __str__(self):
        return self.name


class ThreatModel:
    """Main class for managing the threat model with MITRE ATT&CK integration"""

    def __init__(self, name: str, description: str = ""):
        self.tm = TM(name)
        self.tm.description = description
        self.boundaries = {}  # Stores Boundary objects and their properties (e.g., color)
        self.actors = []
        self.servers = []
        self.dataflows = []
        self.severity_multipliers: Dict[str, float] = {}
        self.custom_mitre_mappings: Dict[str, Any] = {}
        self.protocol_styles: Dict[str, Dict[str, Any]] = {}  # New: Store protocol styles
        self.threats_raw = []
        self.grouped_threats = defaultdict(list)
        self.data_objects = {}
        # Adding a dictionary for quick access to elements by their name
        self._elements_by_name: Dict[str, Any] = {}
        self._component_collections: Dict[type, list] = {
            Actor: self.actors,
            Server: self.servers
            # Other types like Datastore can be added here
        }
        
        # MITRE ATT&CK Integration
        self.mitre_mapper = MitreMapping(self)
        self.mitre_analysis_results = {}
        self.threat_mitre_mapping = {}

    def add_boundary(self, name: str, color: str = "lightgray", parent_name: Optional[str] = None, **kwargs) -> Boundary:
        """Adds a boundary to the model with additional properties, including an optional parent.

        Args:
            name (str): The name of the boundary.
            color (str, optional): The color of the boundary. Defaults to "lightgray".
            parent_name (Optional[str], optional): The name of the parent boundary. Defaults to None.
            **kwargs: Additional properties for the boundary.

        Returns:
            Boundary: The created Boundary object.
        """
        boundary = Boundary(name)

        # HACK: Add dummy attributes to Boundary objects to allow them to be
        # used as sources/sinks in Dataflows. The underlying pytm library
        # expects these attributes to exist on dataflow endpoints, which
        # this patch provides.
        boundary.protocol = None
        boundary.port = None
        boundary.data = None

        if parent_name:
            parent_boundary_info = self.boundaries.get(parent_name)
            if parent_boundary_info:
                boundary.inBoundary = parent_boundary_info["boundary"]
            else:
                logging.warning(f"⚠️ Warning: Parent boundary '{parent_name}' not found for boundary '{name}'.")

        # Store boundary with all properties including color and any additional kwargs
        boundary_props = {"boundary": boundary, "color": color}
        boundary_props.update(kwargs)  # Add any additional properties like isTrusted, isFilled

        self.boundaries[name] = boundary_props
        self._elements_by_name[name] = boundary
        return boundary

    def add_actor(self, name: str, boundary_name: str, color: Optional[str] = None, is_filled: bool = True) -> Actor:
        """Adds an actor to the model"""
        actor = Actor(name)
        boundary_obj = None
        if boundary_name and boundary_name in self.boundaries:
            boundary_obj = self.boundaries[boundary_name]["boundary"]
        if boundary_obj:
            actor.inBoundary = boundary_obj
        self.actors.append({'name': name, 'object': actor, 'boundary': boundary_obj, 'color': color, 'is_filled': is_filled})
        self._elements_by_name[name] = actor
        return actor

    def add_server(self, name: str, boundary_name: str, color: Optional[str] = None, is_filled: bool = True) -> Server:
        """Adds a server to the model with optional color and is_filled attributes."""
        boundary_obj = None
        if boundary_name and boundary_name in self.boundaries:
            boundary_obj = self.boundaries[boundary_name]["boundary"]
        
        server = Server(name)
        if boundary_obj:
            server.inBoundary = boundary_obj
        # Store as dict for easy attribute access (like add_actor)
        self.servers.append({
            'name': name,
            'object': server,
            'boundary': boundary_obj,
            'color': color,
            'is_filled': is_filled
        })
        self._elements_by_name[name] = server
        return server

    def add_data(self, name: str, **kwargs) -> Data:
        """Adds a Data object to the model with additional properties.
        Properties are passed as keyword arguments and are transmitted
        directly to the pytm.Data constructor.
        """
        data_obj = Data(name, **kwargs)  # Passes **kwargs to the Data constructor
        self.data_objects[name] = data_obj
        logging.info(f"   - Added Data: {name} (Props: {kwargs})")  # Debugging
        logging.debug(f"DEBUG: Data object added with name: '{name}'") # New debug log
        return data_obj

    def add_dataflow(self, from_element: Any, to_element: Any, name :str,
            protocol: str, data_name: Optional[str] = None,
            is_authenticated: bool = False,
            is_encrypted: bool = False) -> Dataflow:
        """Adds a dataflow to the model"""
        data_objects = []
        if data_name:
            data_object = self.data_objects.get(data_name)
            if data_object:
                data_objects.append(data_object)
            else:
                logging.warning(f"⚠️ Warning: Data object '{data_name}' not found for dataflow '{name}'.")

        dataflow = Dataflow(
            from_element,
            to_element,
            name,
            protocol=protocol,
            data=data_objects,  # Always pass a list
            is_authenticated=is_authenticated,
            is_encrypted=is_encrypted
        )
        self.dataflows.append(dataflow)
        return dataflow

    def add_protocol_style(self, protocol_name: str, **style_kwargs):
        """
        Adds styling information for a specific protocol.
        
        Args:
            protocol_name (str): Name of the protocol (e.g., "HTTPS", "TCP", "UDP")
            **style_kwargs: Style properties like:
                - color (str): Color for the protocol lines
                - line_style (str): Style of the line (solid, dashed, dotted, etc.)
                - width (int/float): Line width
                - arrow_style (str): Arrow style for dataflows
                - etc.
        
        Example:
            add_protocol_style("HTTPS", color="green", line_style="solid", width=2)
            add_protocol_style("HTTP", color="red", line_style="dashed", width=1)
        """
        self.protocol_styles[protocol_name] = style_kwargs
        logging.info(f"✅ Protocol style added for {protocol_name}: {style_kwargs}")

    def get_protocol_style(self, protocol_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the style configuration for a given protocol.
        
        Args:
            protocol_name (str): Name of the protocol
            
        Returns:
            Dict[str, Any]: Style configuration dictionary or None if not found
        """
        return self.protocol_styles.get(protocol_name)

    def get_all_protocol_styles(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns all protocol styles defined in the model.
        
        Returns:
            Dict[str, Dict[str, Any]]: All protocol styles
        """
        return self.protocol_styles.copy()

    def get_element_by_name(self, name: str) -> Optional[Any]:
        """Retrieves an element (Actor, Server, Boundary) by its name."""
        element = self._elements_by_name.get(name)
        if element:
            return element
        return self.data_objects.get(name)

    def process_threats(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Executes PyTM threat analysis, filters, and groups the results with MITRE mapping."""
        
        self.tm.process()

        pytm_raw_threats = []
        try:
            pytm_raw_threats = self.tm._threats
        except AttributeError:
            logging.warning("⚠️ Could not retrieve PyTM threats from tm._threats.")

        # --- Post-processing: expand class targets to all instances ---
        expanded_pytm_threats = self._expand_class_targets(pytm_raw_threats)

        # --- Generate and add custom threats ---
        from threat_analysis.custom_threats import get_custom_threats
        custom_threats_list = get_custom_threats(self)
        
        # Convert custom threats to (threat, target) tuples
        custom_threats_tuples = []
        for threat_dict in custom_threats_list:
            target_name = threat_dict.get('component')
            target_obj = self.get_element_by_name(target_name)
            if target_obj:
                custom_threat = CustomThreat(
                    name=threat_dict['description'],
                    description=threat_dict['description'],
                    stride_category=threat_dict['stride_category'],
                    mitre_technique_id=None, # You can add this if you have it
                    target=target_obj
                )
                custom_threats_tuples.append((custom_threat, target_obj))

        # Combine filtered PyTM threats with custom threats
        self.threats_raw = expanded_pytm_threats + custom_threats_tuples

        # Normalization and grouping of threats
        self.grouped_threats = self._group_threats()

        # MITRE ATT&CK Analysis
        self._perform_mitre_analysis()

        return self.grouped_threats

    def _expand_class_targets(self, threats: List[Any]) -> List[Tuple[Any, Any]]:
        """
        Expands threats that target a class (e.g., Server, Actor) into separate threats
        for each instance of that class in the model.
        This method is now generic and uses the _component_collections registry.
        """
        expanded_threats = []
        for threat in threats:
            target = getattr(threat, 'target', None)

            if isinstance(target, type) and target in self._component_collections:
                collection = self._component_collections[target]
                for item_info in collection:
                    instance = item_info['object']
                    new_threat = threat.__class__(**threat.__dict__)
                    new_threat.target = instance
                    expanded_threats.append((new_threat, instance))
            else:
                expanded_threats.append((threat, target))
        
        return expanded_threats

    def _group_threats(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Groups threats by type, skipping threats with unresolved targets."""
        grouped = defaultdict(list)

        for t in self.threats_raw:
            # threats_raw should now consistently contain (threat, target) tuples
            threat, target = t

            # Filter out threats with unresolved targets if necessary (e.g., target is None)
            if target is None or (isinstance(target, tuple) and any(x is None for x in target)):
                continue

            # Use the stride_category from the threat object if available, otherwise infer from class name
            stride_category = getattr(threat, 'stride_category', str(threat.__class__.__name__))
            grouped[stride_category].append((threat, target))

        return grouped
    
    def _perform_mitre_analysis(self):
        """Performs MITRE ATT&CK analysis on all detected threats"""
        
        
        # Analyze threats using the MITRE mapper
        self.mitre_analysis_results = self.mitre_mapper.analyze_pytm_threats_list(self.threats_raw)
        
        # Create individual mappings for each threat
        for processed_threat in self.mitre_analysis_results["processed_threats"]:
            # Ensure target is a string for the key, handling tuples and None
            if processed_threat['target'] is None:
                target_str = "Unspecified"
            elif isinstance(processed_threat['target'], tuple):
                # Handle tuples (e.g., dataflow targets or single element wrapped in tuple)
                if len(processed_threat['target']) >= 2:
                    source_obj = processed_threat['target'][0]
                    dest_obj = processed_threat['target'][1]
                    source_name = getattr(source_obj, 'name', "Unspecified") if source_obj else "Unspecified"
                    dest_name = getattr(dest_obj, 'name', "Unspecified") if dest_obj else "Unspecified"
                    target_str = f"{source_name} → {dest_name}"
                elif len(processed_threat['target']) == 1:
                    # If it's a tuple with a single element, treat it as a single target
                    single_obj = processed_threat['target'][0]
                    target_str = getattr(single_obj, 'name', "Unspecified") if single_obj else "Unspecified"
                else:
                    # Empty tuple or other unexpected case
                    target_str = "Unspecified"
            else:
                # Handle single objects with a 'name' attribute
                target_str = getattr(processed_threat['target'], 'name', "Unspecified")
            threat_key = f"{processed_threat['threat_name']}_{target_str}"
            self.threat_mitre_mapping[threat_key] = {
                "stride_category": processed_threat["stride_category"],
                "mitre_tactics": processed_threat["mitre_tactics"],
                "mitre_techniques": processed_threat["mitre_techniques"]
            }

    def get_statistics(self) -> Dict[str, int]:
        """Returns the model statistics"""
        return {
            "total_threats": len(self.threats_raw),
            "threat_types": len(self.grouped_threats),
            "actors": len(self.actors),
            "servers": len(self.servers),
            "dataflows": len(self.dataflows),
            "boundaries": len(self.boundaries),
            "protocol_styles": len(self.protocol_styles),
            "mitre_techniques_count": self.mitre_analysis_results.get("mitre_techniques_count", 0)
        }

    def add_severity_multiplier(self, element_name: str, multiplier: float):
        """Adds a severity multiplier for a given element."""
        self.severity_multipliers[element_name] = multiplier
        


    def add_custom_mitre_mapping(self, attack_name: str, tactics: List[str], techniques: List[Dict[str, str]]):
        """
        Adds a custom MITRE mapping.
        tactics: A list of MITRE ATT&CK tactic names.
        techniques: A list of dictionaries, each with 'id' and 'name' for techniques.
        """
        self.custom_mitre_mappings[attack_name] = {
            "tactics": tactics,
            "techniques": techniques
        }
        

# The get_pytm_class_by_name and expand_threat_targets functions are no longer needed.