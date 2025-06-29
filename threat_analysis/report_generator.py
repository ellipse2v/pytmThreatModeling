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
from typing import Dict, List, Any, Optional
from datetime import datetime


class ReportGenerator:
    """Class for generating HTML and JSON reports"""

    def __init__(self, severity_calculator, mitre_mapping):
        self.severity_calculator = severity_calculator
        self.mitre_mapping = mitre_mapping

    def generate_html_report(self, threat_model, grouped_threats: Dict[str, List],
                             output_file: str = "stride_mitre_report.html") -> str:
        """Generates a complete HTML report with MITRE ATT&CK"""

        total_threats_analyzed = threat_model.mitre_analysis_results.get('total_threats', 0)
        total_mitre_techniques_mapped = threat_model.mitre_analysis_results.get('mitre_techniques_count', 0)
        total_stride_categories = len(self.mitre_mapping.get_stride_categories())
        stride_distribution = threat_model.mitre_analysis_results.get('stride_distribution', {})

        html = self._get_html_header()

        all_detailed_threats_with_mitre = self._get_all_threats_with_mitre_info(grouped_threats)
        summary_stats = self.generate_summary_stats(all_detailed_threats_with_mitre)
        html += self._get_html_summary(
            total_threats_analyzed,
            total_mitre_techniques_mapped,
            total_stride_categories,
            stride_distribution,
            summary_stats
        )

        if not grouped_threats:
            html += self._get_no_threats_section()
        else:
            html += self._generate_threats_sections(all_detailed_threats_with_mitre)

        html += self._get_html_footer()

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

    def _get_html_header(self) -> str:
        """Returns the HTML header with styles"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>STRIDE & MITRE ATT&CK Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            background-color: #f8f9fa;
            color: #212529;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 2rem;
        }
        h1, h2, h3 {
            color: #343a40;
        }
        h1 {
            text-align: center;
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        h2 {
            font-size: 1.75rem;
            border-bottom: 2px solid #dee2e6;
            padding-bottom: 0.5rem;
            margin-top: 2rem;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }
        .card {
            background-color: #fff;
            border-radius: 0.5rem;
            padding: 1.5rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            border: 1px solid #dee2e6;
        }
        .card h3 {
            margin-top: 0;
            font-size: 1.25rem;
        }
        .tabs {
            display: flex;
            flex-wrap: wrap;
            border-bottom: 1px solid #dee2e6;
        }
        .tab-button {
            padding: 1rem 1.5rem;
            cursor: pointer;
            border: none;
            background-color: transparent;
            font-size: 1rem;
            border-bottom: 3px solid transparent;
        }
        .tab-button.active {
            border-bottom-color: #007bff;
            color: #007bff;
        }
        .tab-content {
            display: none;
            padding-top: 1.5rem;
        }
        .tab-content.active {
            display: block;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        th {
            background-color: #f8f9fa;
        }
        .severity-critical { background-color: #dc3545; color: white; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; }
        .severity-low { background-color: #28a745; color: white; }
        .mitre-link {
            color: #007bff;
            text-decoration: none;
        }
        .mitre-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ STRIDE & MITRE ATT&CK Threat Model Report</h1>
"""

    def _get_html_summary(self, total_threats: int, total_techniques: int, total_stride_categories: int, stride_distribution: Dict[str, int], summary_stats: Dict[str, Any]) -> str:
        """Returns the summary section HTML"""
        stride_dist_html = "".join([f"<li><strong>{k}:</strong> {v}</li>" for k, v in stride_distribution.items()])
        
        stats_html = ""
        if summary_stats:
            dist_html = "".join([f"<li>{level}: {count}</li>" for level, count in summary_stats.get('severity_distribution', {}).items()])
            stats_html = f"""
            <ul>
                <li><strong>Total Threats:</strong> {summary_stats.get('total_threats', 0)}</li>
                <li><strong>Average Severity:</strong> {summary_stats.get('average_severity', 0):.2f}</li>
                <li><strong>Max Severity:</strong> {summary_stats.get('max_severity', 0):.2f}</li>
                <li><strong>Min Severity:</strong> {summary_stats.get('min_severity', 0):.2f}</li>
                <li><strong>Severity Distribution:</strong><ul>{dist_html}</ul></li>
            </ul>
            """

        return f"""
        <div class="summary-grid">
            <div class="card">
                <h3>Threat Statistics</h3>
                {stats_html}
            </div>
            <div class="card">
                <h3>MITRE Techniques</h3>
                <p style=\"font-size: 2rem; font-weight: bold;\">{total_techniques}</p>
            </div>
            <div class="card">
                <h3>STRIDE Distribution</h3>
                <ul>{stride_dist_html}</ul>
            </div>
        </div>
"""

    def _get_no_threats_section(self) -> str:
        return """<h2>No threats identified.</h2>"""

    def _generate_threats_sections(self, all_threats: List[Dict[str, Any]]) -> str:
        """Generates sections for each threat type with a tabbed interface."""
        stride_categories = sorted(list(set(threat['stride_category'] for threat in all_threats)))
        html = "<h2>Detailed Threat Analysis</h2><div class=\"tabs\">"
        for i, category in enumerate(stride_categories):
            active_class = "active" if i == 0 else ""
            html += f"<button class=\"tab-button {active_class}\" onclick=\"openTab(event, '{category}')\">{category}</button>"
        html += "</div>"

        for i, category in enumerate(stride_categories):
            active_class = "active" if i == 0 else ""
            html += f"<div id=\"{category}\" class=\"tab-content {active_class}\">"
            html += "<table><thead><tr><th>#</th><th>Target</th><th>Description</th><th>Severity</th><th>MITRE Techniques</th><th>D3FEND Mitigations</th></tr></thead><tbody>"
            category_threats = [t for t in all_threats if t['stride_category'] == category]
            for j, threat in enumerate(category_threats):
                severity_info = threat['severity']
                mitre_html = "<ul>"
                defend_mitigations_html = "<ul>"
                for tech in threat['mitre_techniques']:
                    mitre_html += f"<li><a href='https://attack.mitre.org/techniques/{tech['id']}' target='_blank' class='mitre-link'>{tech['id']}: {tech['name']}</a></li>"
                    if 'defend_mitigations' in tech and tech['defend_mitigations']:
                        for mitigation in tech['defend_mitigations']:
                            defend_mitigations_html += f"<li>{mitigation['id']}: {mitigation['description']}</li>"
                mitre_html += "</ul>"
                defend_mitigations_html += "</ul>"
                html += f"""<tr>
                    <td>{j + 1}</td>
                    <td>{threat['target']}</td>
                    <td>{threat['description']}</td>
                    <td class="severity-{severity_info['level'].lower()}">{severity_info['level']} ({severity_info['score']})</td>
                    <td>{mitre_html}</td>
                    <td>{defend_mitigations_html}</td>
                </tr>"""
            html += "</tbody></table></div>"

        return html

    def _get_html_footer(self) -> str:
        """Returns the HTML footer"""
        year = datetime.now().year
        return f"""</div>
    <script>
        function openTab(evt, tabName) {{
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {{
                tabcontent[i].style.display = "none";
            }}
            tablinks = document.getElementsByClassName("tab-button");
            for (i = 0; i < tablinks.length; i++) {{
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }}
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }}
    </script>
</body>
</html>"""

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

    def _format_summary_stats_to_html(self, stats: Dict[str, Any]) -> str:
        """Helper to format summary statistics into an HTML string."""
        if not stats: return ""
        dist_html = "".join([f"<li>{level}: {count}</li>" for level, count in stats.get('severity_distribution', {}).items()])
        return f"""<div class="card">
            <h3>Threat Statistics</h3>
            <ul>
                <li><strong>Total Threats:</strong> {stats.get('total_threats', 0)}</li>
                <li><strong>Average Severity:</strong> {stats.get('average_severity', 0):.2f}</li>
                <li><strong>Max Severity:</strong> {stats.get('max_severity', 0):.2f}</li>
                <li><strong>Min Severity:</strong> {stats.get('min_severity', 0):.2f}</li>
                <li><strong>Severity Distribution:</strong><ul>{dist_html}</ul></li>
            </ul>
        </div>"""