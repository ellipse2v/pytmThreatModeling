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
Threat Model Validator Module
"""

import logging
from typing import List, Dict, Any

from threat_analysis.models_module import ThreatModel

class ModelValidator:
    """Validates the threat model for consistency and correctness."""

    def __init__(self, threat_model: ThreatModel):
        """Initializes the validator."""
        self.threat_model = threat_model
        self.errors: List[str] = []

    def validate(self) -> bool:
        """Runs all validation checks."""
        self.errors = []
        self._validate_dataflow_references()
        # Add other validation checks here

        if self.errors:
            for error in self.errors:
                logging.error(f"Validation Error: {error}")
            return False
        return True

    def _validate_dataflow_references(self):
        """Checks if dataflows refer to existing elements."""
        # Get all defined element objects from the ThreatModel's registry
        defined_elements = set(self.threat_model._elements_by_name.values())

        # The dataflows are stored on the ThreatModel instance itself
        for df in self.threat_model.dataflows:
            if df.source not in defined_elements:
                self.errors.append(f"Dataflow '{df.name}' source '{df.source.name}' is not a defined element.")
            if df.sink not in defined_elements:
                self.errors.append(f"Dataflow '{df.name}' sink '{df.sink.name}' is not a defined element.")
