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
        self.data_elements = {}
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

    def add_server(self, name: str, boundary_name: str) -> Server:
        """Adds a server to the model"""
        server = Server(name)
        if boundary_name in self.boundaries:
            server.inBoundary = self.boundaries[boundary_name]["boundary"]
        self.servers.append(server)
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
        print("🔍 Processing threats with PyTM...")
        self.tm.process()

        try:
            self.threats_raw = self.tm._threats
            print(f"✅ {len(self.threats_raw)} menaces détectées via tm.threats")
        except AttributeError:
            try:
                self.threats_raw = self.tm._threats
                print(f"✅ {len(self.threats_raw)} menaces détectées via tm._threats")
            except AttributeError:
                print("❌ Impossible de récupérer les menaces")
                self.threats_raw = []

        print(f"DEBUG: Number of raw threats found by PyTM: {len(self.threats_raw)}")
        
        # Normalization and grouping of threats
        self.grouped_threats = self._group_threats()
        
        # MITRE ATT&CK Analysis
        print("🎯 Performing MITRE ATT&CK mapping...")
        self._perform_mitre_analysis()
        
        return self.grouped_threats

    def _group_threats(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Groups threats by type"""
        grouped = defaultdict(list)

        for t in self.threats_raw:
            if isinstance(t, tuple):
                threat, target = t
            else:
                threat = t
                target = self._extract_target_from_threat(threat)

            threat_type = str(threat.__class__.__name__)
            grouped[threat_type].append((threat, target))

        return grouped
    
    def _extract_target_from_threat(self, threat) -> Any:
        """Extract target from threat object, handling different pytm threat types."""
        
        # Debug: Show what we're working with
        threat_attrs = [attr for attr in dir(threat) if not attr.startswith('_')]
        
        # Try different common target attributes in pytm
        target_attributes = [
            'target',           # Most common
            'targets',          # Plural version
            'destination',      # For dataflows
            'dest',            # Short version
            'source',          # Source element
            'element',         # Generic element
            'component',       # Component reference
            'asset',           # Asset reference
        ]
        
        for attr in target_attributes:
            if hasattr(threat, attr):
                target_value = getattr(threat, attr)
                #print(f"Found {attr}: {target_value} (type: {type(target_value)})")
                
                # Handle different types of target values
                if target_value is not None:
                    return self._process_target_value(target_value)
        
        # If no target found, try to extract from threat description or other fields
        if hasattr(threat, 'description'):
            print(f"No direct target found, using description-based target")
            return f"Target from {threat.__class__.__name__}"
        
        # Final fallback
        print(f"No target information found in threat")
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
        """Process a single target item."""
        
        # If it's a class, try to find the actual instance
        if isinstance(target, type):
            # This is where the problem was - we have a class instead of an instance
            class_name = target.__name__
            #print(f"Got class {class_name}, looking for instance...")
            
            # Try to find the actual instance from the model
            # This depends on how your pytm model is structured
            if hasattr(self, 'tm') and hasattr(self.tm, 'elements'):
                # Look for instances of this class in the model
                for element in self.tm.elements:
                    if isinstance(element, target):
                        #print(f"Found instance: {element}")
                        return element
            
            # If we can't find the instance, return a placeholder with the class name
            return f"Unknown_{class_name}_Instance"
        
        # If it's already an instance, return as is
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
        

    def get_mitre_mapping_for_threat(self, threat_name: str, target: str = "") -> Dict[str, Any]:
        """Returns MITRE mapping for a specific threat"""
        threat_key = f"{threat_name}_{target}"
        return self.threat_mitre_mapping.get(threat_key, {})

    def get_stride_category_for_threat(self, threat_obj) -> str:
        """Returns the STRIDE category for a threat object"""
        return self.mitre_mapper.classify_pytm_threat(threat_obj)

    def get_mitre_techniques_for_threat(self, threat_obj) -> List[Dict[str, str]]:
        """Returns MITRE techniques for a threat object"""
        return self.mitre_mapper.get_techniques_for_pytm_threat(threat_obj)

    def get_mitre_tactics_for_threat(self, threat_obj) -> List[str]:
        """Returns MITRE tactics for a threat object"""
        mapping = self.mitre_mapper.get_mapping_for_pytm_threat(threat_obj)
        return mapping.get("tactics", [])

    def get_detailed_threat_analysis(self) -> List[Dict[str, Any]]:
        """Returns detailed analysis of all threats with MITRE mapping"""
        detailed_analysis = []
        
        for threat_type, threat_list in self.grouped_threats.items():
            for threat, target in threat_list:
                # Get MITRE mapping
                stride_category = self.get_stride_category_for_threat(threat)
                mitre_techniques = self.get_mitre_techniques_for_threat(threat)
                mitre_tactics = self.get_mitre_tactics_for_threat(threat)
                
                # Get severity multiplier if defined
                target_name = str(target) if target else "Unknown"
                severity_multiplier = self.get_severity_multiplier(target_name)
                
                # Create detailed entry
                detailed_entry = {
                    "threat_type": threat_type,
                    "threat_name": str(threat.__class__.__name__),
                    "target": target_name,
                    "description": getattr(threat, 'description', ''),
                    "details": getattr(threat, 'details', ''),
                    "stride_category": stride_category,
                    "mitre_tactics": mitre_tactics,
                    "mitre_techniques": mitre_techniques,
                    "severity_multiplier": severity_multiplier,
                    "threat_object": threat
                }
                
                detailed_analysis.append(detailed_entry)
        
        return detailed_analysis

    def _get_unique_mitre_techniques(self) -> List[Dict[str, str]]:
        """Returns unique MITRE techniques used across all threats"""
        techniques = []
        technique_ids = set()
        
        if self.mitre_analysis_results:
            for threat in self.mitre_analysis_results["processed_threats"]:
                for technique in threat["mitre_techniques"]:
                    if technique["id"] not in technique_ids:
                        techniques.append(technique)
                        technique_ids.add(technique["id"])
        
        return techniques

    def _get_unique_mitre_tactics(self) -> List[str]:
        """Returns unique MITRE tactics used across all threats"""
        tactics = set()
        
        if self.mitre_analysis_results:
            for threat in self.mitre_analysis_results["processed_threats"]:
                tactics.update(threat["mitre_tactics"])
        
        return list(tactics)

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

    def get_custom_mitre_mapping(self, attack_name: str) -> Optional[Dict[str, Any]]:
        """Returns a custom MITRE mapping for a given attack name."""
        return self.custom_mitre_mappings.get(attack_name)

    def get_severity_multiplier(self, element_name: str) -> Optional[float]:
        """Returns the severity multiplier for an element, if defined."""
        return self.severity_multipliers.get(element_name)

    def search_threats_by_mitre_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """Searches for threats that use a specific MITRE technique"""
        matching_threats = []
        
        for threat_data in self.get_detailed_threat_analysis():
            for technique in threat_data["mitre_techniques"]:
                if technique["id"] == technique_id:
                    matching_threats.append(threat_data)
                    break
        
        return matching_threats

    def get_threats_by_stride_category(self, stride_category: str) -> List[Dict[str, Any]]:
        """Returns all threats belonging to a specific STRIDE category"""
        matching_threats = []
        
        for threat_data in self.get_detailed_threat_analysis():
            if threat_data["stride_category"] == stride_category:
                matching_threats.append(threat_data)
        
        return matching_threats

    def get_coverage_analysis(self) -> Dict[str, Any]:
        """Analyzes MITRE ATT&CK coverage of the threat model"""
        all_techniques = self.mitre_mapper.get_all_techniques()
        used_techniques = self._get_unique_mitre_techniques()
        
        coverage = {
            "total_mitre_techniques_available": len(all_techniques),
            "techniques_used_in_model": len(used_techniques),
            "coverage_percentage": (len(used_techniques) / len(all_techniques)) * 100 if all_techniques else 0,
            "tactics_coverage": self._analyze_tactics_coverage(),
            "stride_coverage": self._analyze_stride_coverage()
        }
        
        return coverage

    def _analyze_tactics_coverage(self) -> Dict[str, Any]:
        """Analyzes tactics coverage"""
        all_tactics = set()
        used_tactics = set(self._get_unique_mitre_tactics())
        
        # Get all possible tactics from the mapper
        for category_mapping in self.mitre_mapper.mapping.values():
            all_tactics.update(category_mapping.get("tactics", []))
        
        return {
            "total_tactics": len(all_tactics),
            "used_tactics": len(used_tactics),
            "coverage_percentage": (len(used_tactics) / len(all_tactics)) * 100 if all_tactics else 0,
            "missing_tactics": list(all_tactics - used_tactics)
        }

    def _analyze_stride_coverage(self) -> Dict[str, Any]:
        """Analyzes STRIDE coverage"""
        all_stride_categories = set(self.mitre_mapper.get_stride_categories())
        used_stride_categories = set(self.mitre_analysis_results.get("stride_distribution", {}).keys())
        
        return {
            "total_stride_categories": len(all_stride_categories),
            "used_stride_categories": len(used_stride_categories),
            "coverage_percentage": (len(used_stride_categories) / len(all_stride_categories)) * 100 if all_stride_categories else 0,
            "missing_stride_categories": list(all_stride_categories - used_stride_categories)
        }
    
    def get_threats_details(self) -> List[Dict[str, Any]]:
        """
        Returns a detailed list of all threats with their properties,
        including STRIDE type, description, and affected elements.
        """
        detailed_list = []
        for threat_tuple in self.threats_raw:
            threat_obj = threat_tuple[0] if isinstance(threat_tuple, tuple) else threat_tuple
            target_obj = threat_tuple[1] if isinstance(threat_tuple, tuple) else getattr(threat_obj, 'target', None)

            threat_type = str(threat_obj.__class__.__name__)
            description = getattr(threat_obj, 'description', 'No description provided by PyTM')
            
            affected_element_name = 'N/A'
            if target_obj:
                # If target is a dataflow (tuple of elements), get names of source and target
                if isinstance(target_obj, tuple) and len(target_obj) == 2:
                    src_name = getattr(target_obj[0], 'name', 'UnknownSource')
                    dest_name = getattr(target_obj[1], 'name', 'UnknownDestination')
                    affected_element_name = f"{src_name} -> {dest_name}"
                # If target is a single element (Actor, Server, Data), get its name
                elif hasattr(target_obj, 'name'):
                    affected_element_name = target_obj.name
                # If target is a Dataflow object directly (from PyTM's threat object itself)
                elif hasattr(threat_obj, 'dataflow'): # Check if threat is linked to a dataflow
                     df = getattr(threat_obj, 'dataflow')
                     if df and hasattr(df, 'from_element') and hasattr(df, 'to_element'):
                         affected_element_name = f"{getattr(df.from_element, 'name', 'UnknownSource')} -> {getattr(df.to_element, 'name', 'UnknownDestination')}"
                elif hasattr(threat_obj, 'element'): # Check if threat is linked to a single element
                    element = getattr(threat_obj, 'element')
                    affected_element_name = getattr(element, 'name', 'UnknownElement')

            detailed_list.append({
                "type": threat_type,
                "description": description,
                "affected_element": affected_element_name,
                "pytm_threat_object": threat_obj # Keep the raw object for further inspection if needed
            })
        return detailed_list