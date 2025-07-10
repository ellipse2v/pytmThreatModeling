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
Report generation module
"""
import json
import webbrowser
import os
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


class ReportGenerator:
    """Class for generating HTML and JSON reports"""

    def __init__(self, severity_calculator, mitre_mapping):
        self.severity_calculator = severity_calculator
        self.mitre_mapping = mitre_mapping
        self.env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

    def generate_html_report(self, threat_model, grouped_threats: Dict[str, List],
                             output_file: str = "stride_mitre_report.html") -> str:
        """Generates a complete HTML report with MITRE ATT&CK"""

        total_threats_analyzed = threat_model.mitre_analysis_results.get('total_threats', 0)
        total_mitre_techniques_mapped = threat_model.mitre_analysis_results.get('mitre_techniques_count', 0)
        stride_distribution = threat_model.mitre_analysis_results.get('stride_distribution', {})

        all_detailed_threats_with_mitre = self._get_all_threats_with_mitre_info(grouped_threats)
        summary_stats = self.generate_summary_stats(all_detailed_threats_with_mitre)
        
        stride_categories = sorted(list(set(threat['stride_category'] for threat in all_detailed_threats_with_mitre)))

        template = self.env.get_template('report_template.html')
        html = template.render(
            title="STRIDE & MITRE ATT&CK Report",
            report_title="🛡️ STRIDE & MITRE ATT&CK Threat Model Report",
            total_threats_analyzed=total_threats_analyzed,
            total_mitre_techniques_mapped=total_mitre_techniques_mapped,
            stride_distribution=stride_distribution,
            summary_stats=summary_stats,
            all_threats=all_detailed_threats_with_mitre,
            stride_categories=stride_categories
        )

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

        return output_file

    def generate_json_export(self, threat_model, grouped_threats: Dict[str, List],
                             output_file: str = "mitre_analysis.json") -> str:
        """Generates a JSON export of the analysis data"""

        export_data = {
            "analysis_date": datetime.now().isoformat(),
            "architecture": threat_model.tm.name,
            "threats_detected": sum(len(threats) for threats in grouped_threats.values()),
            "threat_types": list(grouped_threats.keys()),
            "mitre_mapping": self.mitre_mapping.mapping,
            "severity_levels": {
                "CRITICAL": "9.0-10.0",
                "HIGH": "7.5-8.9",
                "MEDIUM": "6.0-7.4",
                "LOW": "4.0-5.9",
                "INFORMATIONAL": "1.0-3.9"
            },
            "detailed_threats": self._export_detailed_threats(grouped_threats)
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        return output_file

    def open_report_in_browser(self, html_file: str) -> bool:
        """Opens the report in the browser"""
        try:
            webbrowser.open(html_file)
            return True
        except Exception as e:
            return False

    def _export_detailed_threats(self, grouped_threats: Dict[str, List]) -> List[Dict[str, Any]]:
        return self._get_all_threats_with_mitre_info(grouped_threats)

    def _get_all_threats_with_mitre_info(self, grouped_threats: Dict[str, List]) -> List[Dict[str, Any]]:
        """Gathers detailed information for all threats, including MITRE ATT&CK mapping and severity."""
        all_detailed_threats = []
        for threat_type, threats in grouped_threats.items():
            for item in threats:
                if isinstance(item, tuple) and len(item) == 2:
                    threat, target = item
                    target_name = self._get_target_name_for_severity_calc(target)
                    threat_description = getattr(threat, 'description', f"Threat of type {threat_type} affecting {target_name}")
                    stride_category = getattr(threat, 'stride_category', threat_type)
                else:
                    continue

                # Determine data classification for severity calculation
                data_classification = None
                if hasattr(threat, 'target') and hasattr(threat.target, 'data') and hasattr(threat.target.data, 'classification'):
                    data_classification = threat.target.data.classification.name
                
                severity_info = self.severity_calculator.get_severity_info(stride_category, target_name, classification=data_classification)
                mitre_techniques = self.mitre_mapping.map_threat_to_mitre(threat_description)

                for tech in mitre_techniques:
                    if 'defend_mitigations' in tech and tech['defend_mitigations']:
                        for mitigation in tech['defend_mitigations']:
                            # Extract the part after 'D3-XXXX ' for the URL
                            url_name_match = re.match(r'D3-[A-Z0-9]+\s(.*)', mitigation['url_friendly_name_source'])
                            url_friendly_name = url_name_match.group(1).replace(' ', '') if url_name_match else mitigation['url_friendly_name_source'].replace(' ', '')
                            mitigation['url_friendly_name'] = url_friendly_name

                all_detailed_threats.append({
                    "type": threat_type,
                    "description": threat_description,
                    "target": target_name,
                    "severity": severity_info,
                    "mitre_techniques": mitre_techniques,
                    "stride_category": stride_category
                })
        return all_detailed_threats

    def _get_target_name_for_severity_calc(self, target: Any) -> str:
        """Determines the target name for severity calculation, handling different target types."""
        if isinstance(target, tuple):
            if len(target) == 2:
                source_name = self._extract_name_from_object(target[0])
                dest_name = self._extract_name_from_object(target[1])
                result = f"{source_name} → {dest_name}"
                return result
        result = self._extract_name_from_object(target)
        return result

    def _extract_name_from_object(self, obj: Any) -> str:
        # If the object is a tuple containing a single element, extract that element
        if isinstance(obj, tuple) and len(obj) == 1:
            obj = obj[0]

        if obj is None: 
            return "Unspecified"
        
        # Directly access .name attribute, as PyTM objects are expected to have it
        try:
            return str(obj.name)
        except AttributeError:
            return "Unspecified"

    def generate_summary_stats(self, all_detailed_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generates summary statistics based on severity scores."""
        if not all_detailed_threats: return {}
        all_scores = [threat['severity']['score'] for threat in all_detailed_threats if 'severity' in threat and 'score' in threat['severity']]
        if not all_scores: return {}
        severity_distribution = {}
        for threat in all_detailed_threats:
            level = threat.get('severity', {}).get('level', 'UNKNOWN')
            severity_distribution[level] = severity_distribution.get(level, 0) + 1
        return {
            "total_threats": len(all_scores),
            "average_severity": sum(all_scores) / len(all_scores),
            "max_severity": max(all_scores),
            "min_severity": min(all_scores),
            "severity_distribution": severity_distribution
        }

    