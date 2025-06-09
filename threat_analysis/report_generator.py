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
        
        total_threats = sum(len(threats) for threats in grouped_threats.values())
        total_techniques = sum(len(self.mitre_mapping.get_techniques_for_threat(threat_type)) 
                               for threat_type in grouped_threats.keys())
        
        html = self._get_html_header()
        html += self._get_html_summary(total_threats, len(grouped_threats), total_techniques)
        
        if not grouped_threats:
            html += self._get_no_threats_section()
        else:
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
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; transition: all 0.3s; }
        
        /* Severity Levels */
        .critical { 
            background: linear-gradient(135deg, #d63031 0%, #74b9ff 100%) !important; 
            color: white; 
            font-weight: bold; 
        }
        .high { 
            background: linear-gradient(135deg, #e17055 0%, #fdcb6e 100%) !important; 
            color: white; 
            font-weight: bold; 
        }
        .medium { 
            background: linear-gradient(135deg, #fdcb6e 0%, #e17055 100%) !important; 
            color: black; 
            font-weight: bold; 
        }
        .low { 
            background: linear-gradient(135deg, #00b894 0%, #00cec9 100%) !important; 
            color: white; 
        }
        .info { 
            background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%) !important; 
            color: white; 
        }
        
        .mitre-section {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #3498db;
        }
        .technique {
            background: #e8f4f8;
            padding: 8px;
            margin: 5px 0;
            border-radius: 5px;
            font-size: 0.9em;
        }
        .tactic {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 3px 8px;
            border-radius: 15px;
            font-size: 0.8em;
            margin: 2px;
        }
        .mitre-tactic-cell {
            font-size: 0.85em;
            max-width: 120px;
        }
        .mitre-technique-cell {
            font-size: 0.85em;
            max-width: 180px;
        }
        .mitre-id {
            font-weight: bold;
            color: #2980b9;
        }
        .mitre-name {
            font-size: 0.8em;
            color: #555;
            margin-top: 2px;
        }
        .score {
            font-size: 1.2em;
            font-weight: bold;
            text-align: center;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            background: linear-gradient(135deg, #2d3436 0%, #636e72 100%);
            color: white;
            border-radius: 8px;
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
    
    def _get_html_summary(self, total_threats: int, threat_types: int, total_techniques: int) -> str:
        """Generates the summary section"""
        return f"""
        <div class="summary">
            <h3>📊 Analysis Summary</h3>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{total_threats}</div>
                    <div>Threats Detected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{threat_types}</div>
                    <div>Threat Types</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">6</div>
                    <div>STRIDE Categories</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_techniques}</div>
                    <div>MITRE Techniques</div>
                </div>
            </div>
            <p><strong>Architecture Analyzed:</strong> DMZ with external/internal firewall and protocol break proxy</p>
        </div>
"""
    
    def _get_no_threats_section(self) -> str:
        """Section displayed when no threats are detected"""
        return """
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 20px; border-radius: 8px;">
            <h3>⚠️ No Threats Detected</h3>
            <p>The STRIDE analysis did not detect any specific threats. This may be due to:</p>
            <ul>
                <li>Incomplete model configuration</li>
                <li>PyTM version not automatically generating threats</li>
                <li>Need to manually define threats</li>
            </ul>
        </div>
"""
    
    def _generate_threats_sections(self, grouped_threats: Dict[str, List]) -> str:
        """Generates sections for each threat type"""
        html = ""
        
        # Sort by priority order
        severity_order = ["ElevationOfPrivilege", "Tampering", "InformationDisclosure", 
                          "Spoofing", "DenialOfService", "Repudiation"]
        sorted_threats = sorted(grouped_threats.keys(), 
                                key=lambda x: severity_order.index(x) if x in severity_order else 99)
        
        for threat_type in sorted_threats:
            html += f"<h2>🔍 {threat_type}</h2>\n"
            
            # MITRE ATT&CK Section
            mitre_info = self.mitre_mapping.get_mapping_for_threat(threat_type)
            if mitre_info:
                html += self._generate_mitre_section(mitre_info)
            
            html += self._generate_threats_table(threat_type, grouped_threats[threat_type])
        
        return html
    
    def _generate_mitre_section(self, mitre_info: Dict[str, Any]) -> str:
        """Generates the MITRE ATT&CK section for a threat type"""
        html = f"""
        <div class="mitre-section">
            <h4>🎯 MITRE ATT&CK Correspondence</h4>
            <p><strong>Tactics:</strong> 
            {''.join(f'<span class="tactic">{tactic}</span>' for tactic in mitre_info.get("tactics", []))}
            </p>
            <p><strong>Associated Techniques:</strong></p>
        """
        
        for technique in mitre_info.get("techniques", []):
            html += f"""
            <div class="technique">
                <strong>{technique["id"]}</strong> - {technique["name"]}<br>
                <small>{technique["description"]}</small>
            </div>
            """
        
        html += "</div>"
        return html
    
    def _generate_threats_table(self, threat_type: str, threats: List) -> str:
        """Generates the threats table for a given type with MITRE columns"""
        html = """<table>
        <tr>
            <th>Targeted Element</th>
            <th>Description</th>
            <th>MITRE Tactic</th>
            <th>MITRE Technique</th>
            <th>Mitigations</th>
            <th>Score</th>
            <th>Severity</th>
        </tr>"""
        
        # Retrieve MITRE information for this threat type
        mitre_info = self.mitre_mapping.get_mapping_for_threat(threat_type)
        
        for threat, target in threats:
            # Robust target name handling
            if isinstance(target, tuple) and len(target) == 2:
                target_name = f"{getattr(target[0], 'name', 'N/A')} → {getattr(target[1], 'name', 'N/A')}"
            elif hasattr(target, "name"):
                target_name = target.name
            else:
                target_name = "Unspecified Element"

            # Calculate severity
            severity_info = self.severity_calculator.get_severity_info(threat_type, target_name)
            
            description = getattr(threat, 'description', 
                                  f'Threat of type {threat_type} identified on {target_name}')
            mitigations = getattr(threat, 'mitigations', 
                                  'Mitigations to be defined according to security best practices')

            # Format MITRE tactics
            tactics_html = ""
            if mitre_info and mitre_info.get("tactics"):
                tactics_html = "<br>".join([f'<span class="tactic">{tactic}</span>' 
                                             for tactic in mitre_info["tactics"]])
            else:
                tactics_html = "N/A"

            # Format MITRE techniques
            techniques_html = ""
            if mitre_info and mitre_info.get("techniques"):
                technique_items = []
                for technique in mitre_info["techniques"][:2]:  # Limit to 2 techniques to avoid overload
                    technique_items.append(
                        f'<div class="mitre-id">{technique["id"]}</div>'
                        f'<div class="mitre-name">{technique["name"][:40]}{"..." if len(technique["name"]) > 40 else ""}</div>'
                    )
                techniques_html = "<br>".join(technique_items)
                
                if len(mitre_info["techniques"]) > 2:
                    techniques_html += f"<br><small>+{len(mitre_info['techniques']) - 2} more</small>"
            else:
                techniques_html = "N/A"

            html += f"""<tr class='{severity_info["css_class"]}'>
                <td>{target_name}</td>
                <td>{description}</td>
                <td class="mitre-tactic-cell">{tactics_html}</td>
                <td class="mitre-technique-cell">{techniques_html}</td>
                <td>{mitigations}</td>
                <td class="score">{severity_info["formatted_score"]}</td>
                <td><strong>{severity_info["level"]}</strong></td>
            </tr>"""
        
        html += "</table>\n"
        return html
    
    def _get_recommendations_section(self) -> str:
        """Generates the recommendations section"""
        return """
        <h2>💡 General Recommendations</h2>
        <div class="mitre-section">
            <h4>🔒 Recommended Security Measures</h4>
            <ul>
                <li><strong>Monitoring:</strong> Implement SIEM to detect MITRE ATT&CK techniques</li>
                <li><strong>Segmentation:</strong> Strengthen isolation between DMZ and intranet zones</li>
                <li><strong>Authentication:</strong> Implement multi-factor authentication</li>
                <li><strong>Logs:</strong> Centralize and protect audit logs</li>
                <li><strong>Updates:</strong> Keep systems up-to-date with the latest patches</li>
                <li><strong>Training:</strong> Raise awareness among teams about attack techniques</li>
            </ul>
        </div>
"""
    
    def _get_html_footer(self) -> str:
        """Generates the HTML footer"""
        return """
        <div class="footer">
            <p>📅 Report automatically generated | 🔧 PyTM Framework + MITRE ATT&CK</p>
            <p>🔗 For more information: <a href="https://attack.mitre.org" style="color: #74b9ff;">MITRE ATT&CK Framework</a></p>
        </div>
    </div>
</body>
</html>
"""
    
    def _export_detailed_threats(self, grouped_threats: Dict[str, List]) -> Dict[str, List]:
        """Exports detailed threats for JSON"""
        detailed_threats = {}
        
        for threat_type, threats in grouped_threats.items():
            threat_details = []
            
            for threat, target in threats:
                if isinstance(target, tuple) and len(target) == 2:
                    target_name = f"{getattr(target[0], 'name', 'N/A')} → {getattr(target[1], 'name', 'N/A')}"
                elif hasattr(target, "name"):
                    target_name = target.name
                else:
                    target_name = "Unspecified Element"
                
                severity_info = self.severity_calculator.get_severity_info(threat_type, target_name)
                mitre_info = self.mitre_mapping.get_mapping_for_threat(threat_type)
                
                threat_details.append({
                    "target": target_name,
                    "description": getattr(threat, 'description', f'Threat of type {threat_type}'),
                    "severity_score": severity_info["score"],
                    "severity_level": severity_info["level"],
                    "mitre_tactics": mitre_info.get("tactics", []) if mitre_info else [],
                    "mitre_techniques": [tech["id"] for tech in mitre_info.get("techniques", [])] if mitre_info else []
                })
            
            detailed_threats[threat_type] = threat_details
        
        return detailed_threats
    
    def generate_summary_stats(self, grouped_threats: Dict[str, List]) -> Dict[str, Any]:
        """Generates summary statistics"""
        all_scores = []
        
        for threat_type, threats in grouped_threats.items():
            for threat, target in threats:
                if isinstance(target, tuple) and len(target) == 2:
                    target_name = f"{getattr(target[0], 'name', 'N/A')} → {getattr(target[1], 'name', 'N/A')}"
                elif hasattr(target, "name"):
                    target_name = target.name
                else:
                    target_name = "Unspecified Element"
                
                score = self.severity_calculator.calculate_score(threat_type, target_name)
                all_scores.append(score)
        
        if all_scores:
            return {
                "total_threats": len(all_scores),
                "average_severity": sum(all_scores) / len(all_scores),
                "max_severity": max(all_scores),
                "min_severity": min(all_scores),
                "severity_distribution": self.severity_calculator.get_severity_distribution(all_scores)
            }
        else:
            return {
                "total_threats": 0,
                "average_severity": 0,
                "max_severity": 0,
                "min_severity": 0,
                "severity_distribution": {}
            }