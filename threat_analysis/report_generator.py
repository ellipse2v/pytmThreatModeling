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

        # These values should come from the processed threat_model's MITRE analysis results
        total_threats_analyzed = threat_model.mitre_analysis_results.get('total_threats', 0)
        total_mitre_techniques_mapped = threat_model.mitre_analysis_results.get('mitre_techniques_count', 0)
        # 'Unique STRIDE Threat Types' refers to the unique keys from PyTM's grouping
        unique_pytm_threat_types = len(grouped_threats) 

        # Get total number of STRIDE categories from the mitre_mapping
        total_stride_categories = len(self.mitre_mapping.get_stride_categories())
        
        # Get the STRIDE distribution from the threat_model's analysis results
        stride_distribution = threat_model.mitre_analysis_results.get('stride_distribution', {})


        html = self._get_html_header()
        html += self._get_html_summary(
            total_threats_analyzed,
            total_mitre_techniques_mapped,
            total_stride_categories, # Pass the dynamic value
            stride_distribution # Pass the new stride_distribution
        )

        # Populate all_detailed_threats_with_mitre correctly before using it
        all_detailed_threats_with_mitre = self._get_all_threats_with_mitre_info(grouped_threats)

        if not grouped_threats:
            html += self._get_no_threats_section()
        else:
            # Convert the summary stats dictionary to an HTML string
            summary_stats = self.generate_summary_stats(all_detailed_threats_with_mitre)
            html += self._format_summary_stats_to_html(summary_stats)
            html += self._generate_threats_sections(grouped_threats)

        html += self._get_recommendations_section()
        html += self._get_html_footer()

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

        return output_file

    def generate_json_export(self, grouped_threats: Dict[str, List],
                             output_file: str = "mitre_analysis.json") -> str:
        """Generates a JSON export of the analysis data"""

        export_data = {
            "analysis_date": datetime.now().isoformat(),
            "architecture": "DMZ with external/internal firewall and protocol break proxy",
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
            print(f"⚠️ Could not automatically open browser: {e}")
            return False

    def _get_html_header(self) -> str:
        """Returns the HTML header with styles"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>STRIDE & MITRE ATT&CK Report - DMZ Architecture</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        h1 {
            color: #2c3e50;
            text-align: center;
            border-bottom: 3px solid #3498db;
            padding-bottom: 20px;
            font-size: 2.5em;
        }
        h2 {
            color: #34495e;
            margin-top: 40px;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 8px;
            font-size: 1.5em;
        }
        .summary {
            background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            margin: 20px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .summary h3 {
            margin-top: 0;
            font-size: 1.3em;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
            font-size: 0.9em;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
            vertical-align: top;
        }
        th {
            background: linear-gradient(135deg, #2d3436 0%, #636e72 100%);
            color: white;
            font-weight: bold;
            font-size: 0.95em;
        }
        tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #e3f2fd;
            transition: all 0.3s;
        }
        /* Severity Levels */
        .critical { background: linear-gradient(135deg, #d63031 0%, #74b9ff 100%); color: white; font-weight: bold; }
        .high { background: linear-gradient(135deg, #e17055 0%, #ffeaa7 100%); color: #333; font-weight: bold; }
        .medium { background: linear-gradient(135deg, #feca57 0%, #fdcb6e 100%); color: #333; font-weight: bold; }
        .low { background: linear-gradient(135deg, #55efc4 0%, #81ecec 100%); color: #333; font-weight: bold; }
        .informational { background: linear-gradient(135deg, #a29bfe 0%, #dfe6e9 100%); color: #333; font-weight: bold; }

        .mitre-techniques {
            font-size: 0.85em;
            color: #555;
            margin-top: 5px;
            padding-left: 20px;
        }
        .mitre-techniques ul {
            list-style-type: disc;
            margin: 5px 0 0 15px;
            padding: 0;
        }
        .mitre-techniques li {
            margin-bottom: 3px;
        }
        .mitre-id {
            font-weight: bold;
            color: #2c3e50;
        }
        .mitre-id-link {
            text-decoration: none;
            color: #2980b9;
            font-weight: bold;
        }
        .mitre-id-link:hover {
            text-decoration: underline;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
        background: linear-gradient(135deg, #00b894 0%, #00cec9 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
    }
    .stat-number {
        font-size: 2em;
        font-weight: bold;
    }
    </style>
</head>
<body>
    <div class="container">
    <h1>🛡️ STRIDE & MITRE ATT&CK Report</h1>
    <h2 style="text-align: center; margin-top: 0;">DMZ Architecture - Comprehensive Security Analysis</h2>
"""

    def _get_html_summary(self, total_threats: int, total_techniques: int, total_stride_categories: int, stride_distribution: Dict[str, int]) -> str:
        """Returns the summary section HTML"""
        
        stride_dist_html = ""
        if stride_distribution:
            # Define the desired STRIDE order
            stride_order = [
                "Spoofing",
                "Tampering",
                "Repudiation",
                "InformationDisclosure",
                "DenialOfService",
                "ElevationOfPrivilege"
            ]
            
            stride_dist_html += "<ul>"
            # Iterate through the predefined order
            for stride_type in stride_order:
                # Get the count for the current STRIDE type, default to 0 if not present
                count = stride_distribution.get(stride_type, 0)
                if count > 0: # Only display if there are threats of this type
                    stride_dist_html += f"<li><strong>{stride_type}:</strong> {count} threats</li>"
            
            # Add any other types that might exist in the distribution but are not in the standard STRIDE order
            for stride_type, count in stride_distribution.items():
                if stride_type not in stride_order:
                    stride_dist_html += f"<li><strong>{stride_type}:</strong> {count} threats</li>"
            stride_dist_html += "</ul>"

        return f"""
        <div class="summary">
            <h3>📊 Analysis Summary</h3>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{total_threats}</div>
                    <div>Threats Detected</div>
                </div>
                 <div class="stat-card">
                    <div class="stat-number">{total_techniques}</div>
                    <div>Total MITRE ATT&CK Techniques Mapped</div>
                </div>
            </div>
            <h4>STRIDE Distribution:</h4>
            {stride_dist_html if stride_dist_html else "<p>No STRIDE distribution data available.</p>"}
            <p><strong>Architecture Analyzed:</strong> DMZ with external/internal firewall and protocol break proxy</p>
        </div>
"""

    def _get_no_threats_section(self) -> str:
        """Returns a section indicating no threats were found."""
        return """
        <div class="details-section">
            <h2>Threat Details</h2>
            <p>No threats were identified in the threat model. This might indicate a very secure design or an incomplete model definition.</p>
        </div>
        """

    def _generate_threats_sections(self, grouped_threats: Dict[str, List]) -> str:
        """Generates sections for each threat type, including MITRE ATT&CK details"""
        html = """
        <div class="details-section">
            <h2>🔍 Detailed Threat Analysis</h2>
        """
        if not grouped_threats:
            html += "<p>No threats to display in detail.</p>"
            return html + "</div>"

        # Re-grouping for consistent display if necessary, but assuming grouped_threats is already structured as expected
        # from ThreatModel's process() method.

        for threat_type, threats in grouped_threats.items():
            html += f"<h3>{threat_type} Threats</h3>"
            html += "<table>"
            html += """
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Target Element</th>
                        <th>Description</th>
                        <th>Severity</th>
                        <th>MITRE ATT&CK Techniques</th>
                    </tr>
                </thead>
                <tbody>
            """
            for i, (threat, target) in enumerate(threats):
                target_name = self._get_target_name_for_severity_calc(target)

                # Calculate severity for each threat (this is already a dict from SeverityCalculator)
                severity_info = self.severity_calculator.get_severity_info(threat_type, target_name)
                severity_score = severity_info['formatted_score']
                severity_class = severity_info['css_class']

                threat_description = getattr(threat, 'description', f"Threat of type {threat_type} affecting {target_name}")

                # Map to MITRE ATT&CK
                mitre_techniques = self.mitre_mapping.map_threat_to_mitre(threat_description)

                mitre_html = "<div class='mitre-techniques'><ul>"
                if mitre_techniques:
                    for technique in mitre_techniques:
                        tactic_badges = "".join([f"<span class='mitre-tactic'>{tactic}</span>" for tactic in technique.get('tactics', [])])
                        mitre_html += f"<li>{tactic_badges} <a href='https://attack.mitre.org/techniques/{technique.get('id')}' target='_blank' class='mitre-id-link'>{technique.get('id')}</a>: {technique.get('name')} - {technique.get('description')}</li>"
                else:
                    mitre_html += "<li><i>No specific MITRE technique mapped.</i></li>"
                mitre_html += "</ul></div>"

                html += f"""
                    <tr>
                        <td>{i + 1}</td>
                        <td>{target_name}</td>
                        <td>{threat_description}</td>
                        <td class="{severity_class}">{severity_score}</td>
                        <td>{mitre_html}</td>
                    </tr>
                """
            html += "</tbody></table>"
        html += "</div>" # Close details-section
        return html

    def _get_recommendations_section(self) -> str:
        """Returns the recommendations section HTML"""
        return """
        <div class="recommendations">
            <h2>💡 Recommendations and Mitigations</h2>
            <ul>
                <li>Implement strong authentication mechanisms (MFA, strong passwords) for all critical systems and user accounts.</li>
                <li>Regularly patch and update all software, operating systems, and firmware to protect against known vulnerabilities.</li>
                <li>Perform regular security audits and penetration testing to identify and remediate weaknesses.</li>
                <li>Employ intrusion detection/prevention systems (IDPS) and security information and event management (SIEM) solutions for continuous monitoring.</li>
                <li>Implement data encryption at rest and in transit for sensitive information.</li>
                <li>Establish robust logging and monitoring to detect anomalous activities indicative of repudiation attempts.</li>
                <li>Develop and test a comprehensive incident response plan, including data backup and recovery procedures for Denial of Service attacks.</li>
                <li>Apply the principle of least privilege, ensuring users and processes only have the minimum necessary permissions.</li>
                <li>Utilize web application firewalls (WAF) and API gateways to protect against common web-based attacks.</li>
                <li>Segment networks to limit the blast radius of potential breaches.</li>
                <li>Conduct regular security awareness training for all personnel to counter social engineering and phishing.</li>
            </ul>
        </div>
        """

    def _get_html_footer(self) -> str:
        """Returns the HTML footer"""
        year = datetime.now().year
        return f"""
    </div> <div class="footer">
        <p>&copy; {year} STRIDE & MITRE ATT&CK Threat Analysis. All rights reserved.</p>
    </div>
</body>
</html>
"""

    def _export_detailed_threats(self, grouped_threats: Dict[str, List]) -> List[Dict[str, Any]]:
        """
        Exports detailed threat information for JSON, including MITRE ATT&CK mapping and severity.
        This method is specifically for JSON export and might be redundant with _get_all_threats_with_mitre_info
        if the latter is designed for general detailed threat retrieval.
        """
        # This method duplicates logic from _get_all_threats_with_mitre_info
        # It's better to call _get_all_threats_with_mitre_info directly for consistency.
        return self._get_all_threats_with_mitre_info(grouped_threats)

    def _get_all_threats_with_mitre_info(self, grouped_threats: Dict[str, List]) -> List[Dict[str, Any]]:
        """
        Gathers detailed information for all threats, including MITRE ATT&CK mapping and severity.
        This is a helper for both HTML report and JSON export.
        """
        all_detailed_threats = []
        
        for threat_type, threats in grouped_threats.items():
            # Check if threats is a list of tuples (threat, target) or just strings
            for item in threats:
                if isinstance(item, tuple) and len(item) == 2:
                    # Expected format: (threat, target)
                    threat, target = item
                    target_name = self._get_target_name_for_severity_calc(target)
                    threat_description = getattr(threat, 'description', f"Threat of type {threat_type} affecting {target_name}")
                elif isinstance(item, str):
                    # If item is just a string description
                    threat_description = item
                    target_name = "Unknown Target"
                else:
                    # Handle other cases
                    threat = item
                    target_name = "Unknown Target"
                    threat_description = getattr(threat, 'description', f"Threat of type {threat_type}")

                # Calculate severity for each threat - get_severity_info returns a dictionary
                severity_info = self.severity_calculator.get_severity_info(threat_type, target_name)

                # Map to MITRE ATT&CK
                mitre_techniques = self.mitre_mapping.map_threat_to_mitre(threat_description)

                # Ensure mitre_techniques is a list of dictionaries, even if empty
                if not isinstance(mitre_techniques, list):
                    mitre_techniques = []

                all_detailed_threats.append({
                    "type": threat_type,
                    "description": threat_description,
                    "target": target_name,
                    "severity": severity_info,
                    "mitre_techniques": mitre_techniques
                })
                
        return all_detailed_threats

    def _get_target_name_for_severity_calc(self, target: Any) -> str:
        """Determines the target name for severity calculation, handling different target types."""
        
        # Check if it's a tuple
        if isinstance(target, tuple):
            if len(target) == 2:
                
                # Check attributes of tuple elements
                source_name = self._extract_name_from_object(target[0])
                dest_name = self._extract_name_from_object(target[1])
                result = f"{source_name} → {dest_name}"
                return result
        
        # Check if it has a name attribute
        if hasattr(target, "name"):
            print(f"Has 'name' attribute: {target.name}")
            return str(target.name)
        
        try:
            attrs = [attr for attr in dir(target) if not attr.startswith('_')]            
            # Try some common patterns
            for attr in attrs:
                try:
                    value = getattr(target, attr)
                    if isinstance(value, (str, int, float)) and value:
                        print(f"  {attr}: {value} (type: {type(value)})")
                except Exception as e:
                    print(f"  {attr}: Error accessing - {e}")
                    
        except Exception as e:
            print(f"Error listing attributes: {e}")
        
        return "Unspecified Element"

    def _extract_name_from_object(self, obj: Any) -> str:
        """Helper method to extract name from various object types."""
        if obj is None:
            return "None"
        
        # Try common name attributes
        for attr in ['name', 'Name', 'title', 'id', 'identifier', 'label']:
            if hasattr(obj, attr):
                value = getattr(obj, attr)
                if value:
                    return str(value)
        
        # Try to get string representation
        obj_str = str(obj)
        if obj_str and obj_str != repr(obj) and "object at" not in obj_str:
            return obj_str
        
        # Extract class name as fallback
        import re
        obj_repr = repr(obj)
        match = re.search(r'<([^>]+\.)?(\w+)\s+object', obj_repr)
        if match:
            return f"Unknown_{match.group(2)}"
        
        return "N/A"

    def generate_summary_stats(self, all_detailed_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generates summary statistics based on severity scores."""
        
        # Enhanced debugging to find all problematic entries
        print(f"Total items: {len(all_detailed_threats)}")
        
        # Check all items and categorize them
        valid_dicts = []
        invalid_items = []
        
        for i, threat in enumerate(all_detailed_threats):
            if isinstance(threat, dict):
                valid_dicts.append((i, threat))
            else:
                invalid_items.append((i, type(threat), repr(threat)))
        
        print(f"Valid dictionaries: {len(valid_dicts)}")
        print(f"Invalid items: {len(invalid_items)}")
        
        # Show details of invalid items
        if invalid_items:
            print("\nInvalid items found:")
            for index, item_type, item_repr in invalid_items:
                print(f"  Index {index}: {item_type} = {item_repr}")
        
        all_scores = []
        severity_issues = []
        
        for orig_index, threat in valid_dicts:
            severity_info = threat.get('severity')
            
            if not severity_info:
                severity_issues.append(f"Index {orig_index}: No severity info")
                continue
            
            # Handle different types of severity_info
            score = None
            
            if isinstance(severity_info, dict):
                # If it's a dictionary, try to get the score
                score = severity_info.get('score')
                if score is None:
                    severity_issues.append(f"Index {orig_index}: Dict severity missing 'score' key: {severity_info.keys()}")
                    continue
            elif isinstance(severity_info, str):
                # If it's a string, try to extract numeric value
                try:
                    import re
                    match = re.search(r'(\d+\.?\d*)', severity_info)
                    if match:
                        score = float(match.group(1))
                    else:
                        severity_issues.append(f"Index {orig_index}: Could not extract number from string: '{severity_info}'")
                        continue
                except (ValueError, AttributeError) as e:
                    severity_issues.append(f"Index {orig_index}: Error parsing string '{severity_info}': {e}")
                    continue
            elif isinstance(severity_info, (int, float)):
                # If it's already a number
                score = float(severity_info)
            else:
                severity_issues.append(f"Index {orig_index}: Unexpected severity type {type(severity_info)}: {severity_info}")
                continue
            
            # Validate score is a valid number
            if isinstance(score, (int, float)) and not (score != score):  # Check for NaN
                all_scores.append(score)
            else:
                severity_issues.append(f"Index {orig_index}: Invalid score value: {score}")
        
        # Report severity parsing issues
        if severity_issues:
            print(f"\nSeverity parsing issues ({len(severity_issues)}):")
            for issue in severity_issues[:10]:  # Show first 10 issues
                print(f"  {issue}")
            if len(severity_issues) > 10:
                print(f"  ... and {len(severity_issues) - 10} more")
        
        print(f"\nSuccessfully extracted {len(all_scores)} severity scores")
        if all_scores:
            print(f"Score range: {min(all_scores)} - {max(all_scores)}")
            print(f"Average score: {sum(all_scores) / len(all_scores):.2f}")
        
        # Generate final statistics
        if all_scores:
            # Calculate severity level distribution from the valid dictionaries
            severity_distribution = {}
            for orig_index, threat in valid_dicts:
                severity_info = threat.get('severity', {})
                if isinstance(severity_info, dict):
                    level = severity_info.get('level', 'UNKNOWN')
                    severity_distribution[level] = severity_distribution.get(level, 0) + 1
            print("\n📋 Enhanced analysis summary:")
            print(f"    • Threats detected: {len(all_scores)}")
            print(f"    • Average score: {severity_distribution}")
            return {
                "total_threats": len(all_scores),
                "average_severity": sum(all_scores) / len(all_scores),
                "max_severity": max(all_scores),
                "min_severity": min(all_scores),
                "severity_distribution": severity_distribution
            }
        else:
            return {
                "total_threats": 0,
                "average_severity": 0,
                "max_severity": 0,
                "min_severity": 0,
                "severity_distribution": {}
            }

    def _format_summary_stats_to_html(self, stats: Dict[str, Any]) -> str:
        """Helper to format summary statistics into an HTML string."""
        if not stats:
            return ""

        html_output = """
        <div class="summary-stats">
            <h2>📈 Threat Statistics</h2>
            <ul>
        """
        html_output += f"<li><strong>Total Threats Analyzed:</strong> {stats.get('total_threats', 0)}</li>"
        html_output += f"<li><strong>Average Severity Score:</strong> {stats.get('average_severity', 0):.2f}</li>"
        html_output += f"<li><strong>Maximum Severity Score:</strong> {stats.get('max_severity', 0):.2f}</li>"
        html_output += f"<li><strong>Minimum Severity Score:</strong> {stats.get('min_severity', 0):.2f}</li>"

        if stats.get('severity_distribution'):
            html_output += "<li><strong>Severity Distribution:</strong><ul>"
            for level, count in stats['severity_distribution'].items():
                html_output += f"<li>{level}: {count}</li>"
            html_output += "</ul></li>"

        html_output += """
            </ul>
        </div>
        """
        return html_output