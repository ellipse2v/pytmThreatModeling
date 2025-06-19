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
from .mitre_mapping_module import MitreMapping


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
        
        # MITRE ATT&CK Integration
        self.mitre_mapper = MitreMapping()
        self.mitre_analysis_results = {}
        self.threat_mitre_mapping = {}

    def add_boundary(self, name: str, color: str = "lightgray", **kwargs) -> Boundary:
        """Adds a boundary to the model with additional properties"""
        boundary = Boundary(name)
        
        # Store boundary with all properties including color and any additional kwargs
        boundary_props = {"boundary": boundary, "color": color}
        boundary_props.update(kwargs)  # Add any additional properties like isTrusted, isFilled
        
        self.boundaries[name] = boundary_props
        self._elements_by_name[name] = boundary
        return boundary

    def add_actor(self, name: str, boundary_name: str, color: Optional[str] = None, is_filled: bool = True) -> Actor:
        """Adds an actor to the model"""
        actor = Actor(name)
        if boundary_name in self.boundaries:
            actor.inBoundary = self.boundaries[boundary_name]["boundary"]
        self.actors.append({'name': name, 'object': actor, 'boundary': self.boundaries[boundary_name]["boundary"], 'color': color, 'is_filled': is_filled})
        self._elements_by_name[name] = actor
        return actor

    def add_server(self, name: str, boundary_name: str, color: Optional[str] = None, is_filled: bool = True) -> Server:
        """Adds a server to the model with optional color and is_filled attributes."""
        server = Server(name)
        if boundary_name in self.boundaries:
            server.inBoundary = self.boundaries[boundary_name]["boundary"]
        # Store as dict for easy attribute access (like add_actor)
        self.servers.append({
            'name': name,
            'object': server,
            'boundary': self.boundaries[boundary_name]["boundary"] if boundary_name in self.boundaries else None,
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
        print(f"   - Added Data: {name} (Props: {kwargs})")  # Debugging
        return data_obj

    def add_dataflow(self, from_element: Any, to_element: Any, name :str,
            protocol: str, data_name: Optional[str] = None,
            is_authenticated: bool = False,
            is_encrypted: bool = False) -> Dataflow:
        """Adds a dataflow to the model"""
        data_object = None
        if data_name:
            data_object = self.data_objects.get(data_name)
            if not data_object:
                print(f"⚠️ Warning: Data object '{data_name}' not found for dataflow '{name}'.")
         # Arguments are passed as keyword arguments
        dataflow = Dataflow(
            from_element,
            to_element,
            name,
            protocol=protocol,
            data=data_object,
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
        print(f"✅ Protocol style added for {protocol_name}: {style_kwargs}")

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
        """Executes PyTM threat analysis and groups the results with MITRE mapping."""
        # print("🔍 Processing threats with PyTM...")
        self.tm.process()

        try:
            self.threats_raw = self.tm._threats
            # print(f"✅ {len(self.threats_raw)} menaces détectées via tm.threats")
        except AttributeError:
            try:
                self.threats_raw = self.tm._threats
                # print(f"✅ {len(self.threats_raw)} menaces détectées via tm._threats")
            except AttributeError:
                # print("❌ Impossible de récupérer les menaces")
                self.threats_raw = []

        # print(f"DEBUG: Number of raw threats found by PyTM: {len(self.threats_raw)}")

        # --- Post-processing: expand class targets to all instances ---
        self.threats_raw = self._expand_class_targets(self.threats_raw)

        # Normalization and grouping of threats
        self.grouped_threats = self._group_threats()

        # MITRE ATT&CK Analysis
        # print("🎯 Performing MITRE ATT&CK mapping...")
        self._perform_mitre_analysis()

        return self.grouped_threats

    def _expand_class_targets(self, threats):
        """
        Expands threats whose target is a class (e.g., Server, Dataflow) into one threat per instance.
        """
        import copy
        expanded = []
        # Gather all model elements (servers, actors, dataflows, etc.)
        all_elements = []
        for server in self.servers:
            if isinstance(server, dict) and 'object' in server:
                # print(f"DEBUG: server['object'] type: {type(server['object'])}")
                all_elements.append(server['object'])
            else:
                # print(f"DEBUG: server type: {type(server)}")
                all_elements.append(server)
        for actor in self.actors:
            if isinstance(actor, dict) and 'object' in actor:
                # print(f"DEBUG: actor['object'] type: {type(actor['object'])}")
                all_elements.append(actor['object'])
            else:
                # print(f"DEBUG: actor type: {type(actor)}")
                all_elements.append(actor)
        for df in self.dataflows:
            # print(f"DEBUG: dataflow type: {type(df)}")
            all_elements.append(df)
        for b in self.boundaries.values():
            if 'boundary' in b:
                # print(f"DEBUG: boundary type: {type(b['boundary'])}")
                all_elements.append(b['boundary'])

        # print("DEBUG: Starting threat expansion...")
        for t in threats:
            if isinstance(t, tuple):
                # print("DEBUG: isinstance...")
                threat, target = t
            else:
                # print("DEBUG: not isinstance...")
                threat = t
                target = self._extract_target_from_threat(threat, expand_classes=False)

            # print(f"DEBUG: Processing threat={threat}, target={target} (type={type(target)})")
            if isinstance(target, type):
                # print(f"DEBUG: target is a class: {target}")
                found = False
                for elem in all_elements:
                    # print(f"DEBUG: Comparing elem {elem} ({type(elem)}) with target {target}")
                    if type(elem).__name__ == target.__name__ and type(elem).__module__ == target.__module__:
                        # print("DEBUG: Match found!")
                        threat_copy = copy.copy(threat)
                        if isinstance(t, tuple):
                            expanded.append((threat_copy, elem))
                        else:
                            threat_copy.target = elem
                            expanded.append(threat_copy)
                        found = True
                if not found:
                    # print(f"⚠️ No instance found for class '{target.__name__}' in the model (expand_class_targets).")
                    pass
            elif isinstance(target, tuple):
                # print(f"DEBUG: target is a tuple: {target}")
                for idx, x in enumerate(target):
                    # print(f"DEBUG: target[{idx}] = {x} (type={type(x)})")
                    if isinstance(x, type):
                        # print(f"DEBUG: class name: {x.__name__}, module: {x.__module__}, bases: {x.__bases__}")
                        # print(f"DEBUG: class dict: {x.__dict__}")
                        pass
                if any(isinstance(x, type) for x in target):
                    # print("DEBUG: At least one element in target tuple is a class, entering expansion block.")
                    # Expand all combinations for tuple targets
                    from_targets = []
                    to_targets = []
                    if isinstance(target[0], type):
                        from_targets = [
                            e for e in all_elements
                            if type(e).__name__ == target[0].__name__ and type(e).__module__ == target[0].__module__
                        ]
                    else:
                        from_targets = [target[0]]
                    if isinstance(target[1], type):
                        to_targets = [
                            e for e in all_elements
                            if type(e).__name__ == target[1].__name__ and type(e).__module__ == target[1].__module__
                        ]
                    else:
                        to_targets = [target[1]]
                    # print(f"DEBUG: from_targets={from_targets}")
                    # print(f"DEBUG: to_targets={to_targets}")
                    if from_targets and to_targets:
                        for src in from_targets:
                            for dst in to_targets:
                                threat_copy = copy.copy(threat)
                                if isinstance(t, tuple):
                                    expanded.append((threat_copy, (src, dst)))
                                else:
                                    threat_copy.target = (src, dst)
                                    expanded.append(threat_copy)
                    else:
                        # print(f"⚠️ No instance found for class tuple {target} in the model (expand_class_targets).")
                        pass
                else:
                    # print("DEBUG: No class found in target tuple, skipping expansion.")
                    expanded.append(t)
            else:
                # print("DEBUG: target is not a class or tuple, appending as is.")
                expanded.append(t)
        # print(f"DEBUG: Expansion complete. {len(expanded)} threats after expansion.")
        return expanded

    def _group_threats(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Groups threats by type, skipping threats with unresolved targets."""
        grouped = defaultdict(list)

        for t in self.threats_raw:
            # print(f"Processing threat: {t}")
            if isinstance(t, tuple):
                threat, target = t
            else:
                threat = t
                target = self._extract_target_from_threat(threat)

            # Filtrer les cibles non résolues
            #TODO update this to find the way to map the target to an instance
            #if target is None or (isinstance(target, tuple) and any(x is None for x in target)):
                # print(f"⚠️ Skipping threat '{threat}' with unresolved target: {target}")
            #    continue

            threat_type = str(threat.__class__.__name__)
            grouped[threat_type].append((threat, target))

        return grouped
    
    def _extract_target_from_threat(self, threat: Any, expand_classes: bool = True) -> Optional[Any]:
        """
        Extracts the target element(s) from a threat object.
        Returns an instance, a tuple of instances, or None if not found.
        If expand_classes is True, will expand class targets to all instances (legacy, not used in main flow).
        """
        possible_attrs = ['target', 'targets', 'destination', 'dest', 'element', 'elements', 'object', 'objects']
        # print(f"DEBUG: threat={threat}, attrs={dir(threat)}")
        for attr in possible_attrs:
            if hasattr(threat, 'target'):
                value = getattr(threat, 'target')
                # print(f"DEBUG: threat.target = {value!r}")
                # --- DEBUG: Affiche le contenu des classes dans le tuple ---
                if isinstance(value, tuple):
                    for idx, x in enumerate(value):
                        # print(f"DEBUG: target[{idx}] = {x} (type={type(x)})")
                        if isinstance(x, type):
                            # print(f"DEBUG: class name: {x.__name__}, module: {x.__module__}, bases: {x.__bases__}")
                            # print(f"DEBUG: class dict: {x.__dict__}")
                            pass
                result = self._process_target_value(value)
                # If expand_classes is False, just return as is (used by _expand_class_targets)
                if not expand_classes:
                    return result
                # If expand_classes is True and result is a class, expand to all instances
                if expand_classes and isinstance(result, type):
                    # This branch is now handled in _expand_class_targets, so just return the class
                    return result
                if expand_classes and isinstance(result, tuple) and any(isinstance(x, type) for x in result):
                    return result
                return result
            if hasattr(threat, attr):
                value = getattr(threat, attr)
                result = self._process_target_value(value)
                if not expand_classes:
                    return result
                if expand_classes and isinstance(result, type):
                    return result
                if expand_classes and isinstance(result, tuple) and any(isinstance(x, type) for x in result):
                    return result
                return result
        # Fallback: try to extract from description or other fields if needed
        if hasattr(threat, 'description'):
            desc = getattr(threat, 'description')
            if isinstance(desc, str) and desc:
                return desc
        return None

    def _process_target_value(self, target_value: Any) -> Any:
        """Process the target value to get the actual target object."""
        
        # If it's already a proper instance, return as is
        if hasattr(target_value, 'name') and not isinstance(target_value, type):
            return target_value
        
        # If it's a list or tuple of targets
        if isinstance(target_value, (list, tuple)):
            if len(target_value) == 1:
                return self._process_single_target(target_value[0])
            elif len(target_value) == 2:
                # Dataflow case
                source = self._process_single_target(target_value[0])
                dest = self._process_single_target(target_value[1])
                return (source, dest)
            else:
                # Multiple targets
                return tuple(self._process_single_target(t) for t in target_value)
        
        # Single target
        return self._process_single_target(target_value)

    def _process_single_target(self, target: Any) -> Any:
        """Process a single target item, always returning a real instance or None (never a fallback string)."""

        # If it's a class, try to find the actual instance
        if isinstance(target, type):
            class_name = target.__name__
            # Try to find the actual instance from the model
            if hasattr(self, 'tm') and hasattr(self.tm, 'elements'):
                for element in self.tm.elements:
                    if isinstance(element, target):
                        return element
            # If not found, return None (do NOT return a fallback string)
            # print(f"⚠️ No instance found for class '{class_name}' in the model.")
            return None

        # If it's already an instance (object or dict), return as is
        return target

    def _perform_mitre_analysis(self):
        """Performs MITRE ATT&CK analysis on all detected threats"""
        print("🔍 Analyzing threats with MITRE ATT&CK framework...")
        
        # Analyze threats using the MITRE mapper
        self.mitre_analysis_results = self.mitre_mapper.analyze_pytm_threats_list(self.threats_raw)
        
        # Create individual mappings for each threat
        for processed_threat in self.mitre_analysis_results["processed_threats"]:
            threat_key = f"{processed_threat['threat_name']}_{processed_threat['target']}"
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
        print(f"✅ Severity Multiplier added for {element_name}: {multiplier}")


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
        print(f"✅ Custom MITRE Mapping added for {attack_name}")

