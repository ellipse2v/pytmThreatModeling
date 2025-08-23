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

import unittest
import json
import os
from threat_analysis.generation.attack_navigator_generator import AttackNavigatorGenerator

class TestAttackNavigatorGenerator(unittest.TestCase):

    def setUp(self):
        self.threat_model_name = "Test Model"
        self.all_detailed_threats = [
            {
                "description": "Threat 1",
                "target": "Component A",
                "stride_category": "Spoofing",
                "mitre_techniques": [
                    {"id": "T1078", "name": "Valid Accounts"},
                    {"id": "T1566", "name": "Phishing"}
                ],
                "severity": {"score": 8.5}
            },
            {
                "description": "Threat 2",
                "target": "Component B",
                "stride_category": "Tampering",
                "mitre_techniques": [
                    {"id": "T1078", "name": "Valid Accounts"} # Duplicate technique
                ],
                "severity": {"score": 6.0}
            },
            {
                "description": "Threat 3",
                "target": "Component C",
                "stride_category": "Information Disclosure",
                "mitre_techniques": [], # No techniques
                "severity": {"score": 4.0}
            }
        ]
        self.generator = AttackNavigatorGenerator(
            threat_model_name=self.threat_model_name,
            all_detailed_threats=self.all_detailed_threats
        )

    def test_generate_layer(self):
        layer = self.generator.generate_layer()
        self.assertEqual(layer["name"], f"{self.threat_model_name} - Identified Techniques")
        self.assertEqual(len(layer["techniques"]), 2)

        t1078 = next((t for t in layer["techniques"] if t["techniqueID"] == "T1078"), None)
        self.assertIsNotNone(t1078)
        self.assertEqual(t1078["score"], 8.5) # Should take the highest score

        t1566 = next((t for t in layer["techniques"] if t["techniqueID"] == "T1566"), None)
        self.assertIsNotNone(t1566)
        self.assertEqual(t1566["score"], 8.5)

    def test_save_layer_to_file(self):
        output_path = "/tmp/test_layer.json"
        self.generator.save_layer_to_file(output_path)

        self.assertTrue(os.path.exists(output_path))

        with open(output_path, 'r') as f:
            layer_data = json.load(f)
            self.assertEqual(layer_data["name"], f"{self.threat_model_name} - Identified Techniques")

        os.remove(output_path)

if __name__ == '__main__':
    unittest.main()
