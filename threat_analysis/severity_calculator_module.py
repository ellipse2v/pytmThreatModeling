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
Threat severity calculation module
"""
from typing import Dict, Tuple, Optional


class SeverityCalculator:
    """Class for calculating threat severity"""
    
    def __init__(self):
        self.base_scores = {
            "ElevationOfPrivilege": 9.0,
            "Tampering": 8.0,
            "InformationDisclosure": 7.5,
            "Spoofing": 7.0,
            "DenialOfService": 6.0,
            "Repudiation": 5.0
        }
        
        self.target_multipliers = {
            "Serveur Central": 1.5,
            "Firewall": 1.0,
            "Switch": 0.8,
            "Proxy": 0.7,
            "Rupture": 0.7
        }
        
        self.protocol_adjustments = {
            "SSH": 0.5,
            "HTTPS": -0.3,
            "HTTP": 0.2
        }
        
        self.severity_levels = {
            "CRITICAL": (9.0, 10.0, "critical"),
            "HIGH": (7.5, 8.9, "high"),
            "MEDIUM": (6.0, 7.4, "medium"),
            "LOW": (4.0, 5.9, "low"),
            "INFORMATIONAL": (1.0, 3.9, "info")
        }
        
        self.classification_multipliers = {
            "PUBLIC": 1.0,
            "RESTRICTED": 1.2,
            "SECRET": 1.5,
            "TOP_SECRET": 2.0
        }
    
    def calculate_score(self, threat_type: str, target_name: str, protocol: Optional[str] = None, classification: Optional[str] = None) -> float:
        """Calculates the severity score for a threat"""
        # Base score
        score = self.base_scores.get(threat_type, 5.0)
        
        # Amplification factors based on target
        for target_key, multiplier in self.target_multipliers.items():
            if target_key in target_name:
                score += multiplier
                break
        
        # Factors based on protocol
        if protocol:
            protocol_upper = protocol.upper()
            adjustment = self.protocol_adjustments.get(protocol_upper, 0.0)
            score += adjustment
        
        # Factors based on data classification
        if classification:
            classification_upper = classification.upper()
            multiplier = self.classification_multipliers.get(classification_upper, 1.0)
            score *= multiplier
        
        # Normalization between 1.0 and 10.0
        return min(10.0, max(1.0, score))
    
    def get_severity_level(self, score: float) -> Tuple[str, str]:
        """Converts the numeric score to a severity level"""
        for level_name, (min_score, max_score, css_class) in self.severity_levels.items():
            if min_score <= score <= max_score:
                return level_name, css_class
        return "INFORMATIONAL", "info"
    
    def get_severity_info(self, threat_type: str, target_name: str, protocol: Optional[str] = None, classification: Optional[str] = None) -> Dict[str, any]:
        """Returns complete severity information"""
        score = self.calculate_score(threat_type, target_name, protocol, classification)
        level, css_class = self.get_severity_level(score)
        
        return {
            "score": score,
            "level": level,
            "css_class": css_class,
            "formatted_score": f"{score:.1f}/10"
        }
    
    def update_target_multipliers(self, new_multipliers: Dict[str, float]):
        """Updates target multipliers"""
        self.target_multipliers.update(new_multipliers)
    
    
    