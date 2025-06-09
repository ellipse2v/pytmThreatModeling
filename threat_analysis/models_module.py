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
Threat Model Definition Module
"""
from pytm import TM, Boundary, Actor, Server, Dataflow, Data
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple


class ThreatModel:
    """Main class for managing the threat model"""

    def __init__(self, name: str, description: str = ""):
        self.tm = TM(name)
        self.tm.description = description
        self.boundaries = {} # Stores Boundary objects and their properties (e.g., color)
        self.actors = []
        self.servers = []
        self.dataflows = []
        self.data_elements = {}
        self.severity_multipliers: Dict[str, float] = {}
        self.custom_mitre_mappings: Dict[str, Any] = {} 
        self.threats_raw = []
        self.grouped_threats = defaultdict(list)
        self.data_objects = {}
        # Adding a dictionary for quick access to elements by their name
        self._elements_by_name: Dict[str, Any] = {}

    def add_boundary(self, name: str, color: str = "lightgray") -> Boundary:
        """Adds a boundary to the model"""
        boundary = Boundary(name)
        self.boundaries[name] = {"boundary": boundary, "color": color}
        self._elements_by_name[name] = boundary
        return boundary

    def add_actor(self, name: str, boundary_name: str) -> Actor:
        """Adds an actor to the model"""
        actor = Actor(name)
        if boundary_name in self.boundaries:
            actor.inBoundary = self.boundaries[boundary_name]["boundary"]
        self.actors.append(actor)
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
        data_obj = Data(name, **kwargs) # Passes **kwargs to the Data constructor
        self.data_objects[name] = data_obj # Ensures self.data_objects is properly initialized in __init__
        print(f"   - Added Data: {name} (Props: {kwargs})") # Debugging
        return data_obj

    def add_dataflow(self, from_element: Any, to_element: Any, name: str,
                     protocol: str, data_name: Optional[str] = None, # New parameter
                     is_authenticated: bool = False,
                     is_encrypted: bool = False) -> Dataflow:
        """Adds a dataflow to the model"""
        data_object = None
        if data_name:
            data_object = self.data_objects.get(data_name)
            if not data_object:
                print(f"⚠️ Warning: Data object '{data_name}' not found for dataflow '{name}'.")
                # Optional: create the Data object on the fly if not found.
                # data_object = Data(data_name)
                # print(f"   - On-the-fly creation of Data object: {data_name}")

        # Arguments are passed as keyword arguments
        dataflow = Dataflow(
            from_element,
            to_element,
            name,
            protocol=protocol,
            data=data_object, # Passed as keyword argument
            is_authenticated=is_authenticated, # Passed as keyword argument
            is_encrypted=is_encrypted # Passed as keyword argument
        )
        self.dataflows.append(dataflow)
        return dataflow

    def get_element_by_name(self, name: str) -> Optional[Any]:
        """Retrieves an element (Actor, Server, Boundary) by its name."""
        # First search in diagram elements, then in Data objects
        element = self._elements_by_name.get(name)
        if element:
            return element
        return self.data_objects.get(name) # Returns a Data object if found

    def process_threats(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Executes PyTM threat analysis and groups the results."""
        self.tm.process()

        try:
            self.threats_raw = self.tm.threats
            print(f"✅ {len(self.threats_raw)} menaces détectées via tm.threats")
        except AttributeError:
            try:
                self.threats_raw = self.tm._threats
                print(f"✅ {len(self.threats_raw)} menaces détectées via tm._threats")
            except AttributeError:
                print("❌ Impossible de récupérer les menaces")
                threats_raw = []

        print(f"DEBUG: Number of raw threats found by PyTM: {len(self.threats_raw)}")
        if self.threats_raw:
            for i, t in enumerate(self.threats_raw[:5]): # Print first 5 threats for inspection
                print(f"DEBUG: Raw threat {i}: {t}")       

        # Normalization and grouping of threats
        self.grouped_threats = self._group_threats()
        return self.grouped_threats

    def _group_threats(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Groups threats by type"""
        grouped = defaultdict(list)

        for t in self.threats_raw:
            if isinstance(t, tuple):
                threat, target = t
            else:
                threat = t
                target = getattr(threat, 'target', None)

            threat_type = str(threat.__class__.__name__)
            grouped[threat_type].append((threat, target))

        return grouped

    def get_boundary_colors(self) -> Dict[str, str]:
        """Returns the colors of the boundaries"""
        return {name: info["color"] for name, info in self.boundaries.items()}

    def get_statistics(self) -> Dict[str, int]:
        """Returns the model statistics"""
        return {
            "total_threats": len(self.threats_raw),
            "threat_types": len(self.grouped_threats),
            "actors": len(self.actors),
            "servers": len(self.servers),
            "dataflows": len(self.dataflows),
            "boundaries": len(self.boundaries)
        }
    
    def add_severity_multiplier(self, element_name: str, multiplier: float):
        """
        Adds a severity multiplier for a given element.
        """
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

    def get_custom_mitre_mapping(self, attack_name: str) -> Optional[Dict[str, Any]]:
        """Returns a custom MITRE mapping for a given attack name."""
        return self.custom_mitre_mappings.get(attack_name)
    
    def get_severity_multiplier(self, element_name: str) -> Optional[float]:
        """Returns the severity multiplier for an element, if defined."""
        return self.severity_multipliers.get(element_name)    