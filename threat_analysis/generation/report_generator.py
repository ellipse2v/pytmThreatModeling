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
import shutil
import re
import json
import logging
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime
import webbrowser
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from threat_analysis.utils import _validate_path_within_project
from threat_analysis.mitigation_suggestions import get_mitigation_suggestions

# Add project root to sys.path to allow imports from other directories
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from threat_analysis.core.model_factory import create_threat_model
from threat_analysis.generation.diagram_generator import DiagramGenerator
from threat_analysis.core.models_module import ThreatModel


class ReportGenerator:
    """Class for generating HTML and JSON reports"""

    def __init__(self, severity_calculator, mitre_mapping):
        self.severity_calculator = severity_calculator
        self.mitre_mapping = mitre_mapping
        self.env = Environment(loader=FileSystemLoader(Path(__file__).parent.parent / 'templates'))

    def generate_html_report(self, threat_model, grouped_threats: Dict[str, List],
                             output_file: Path = Path("stride_mitre_report.html")) -> Path:
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
            stride_categories=stride_categories,
            severity_calculation_note=self.severity_calculator.get_calculation_explanation()
        )

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

        return output_file

    def generate_json_export(self, threat_model, grouped_threats: Dict[str, List],
                             output_file: Path = Path("mitre_analysis.json")) -> Path:
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

    def open_report_in_browser(self, html_file: Path) -> bool:
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
                
                # Extract impact and likelihood from the threat object if available
                threat_impact = getattr(threat, 'impact', None)
                threat_likelihood = getattr(threat, 'likelihood', None)

                severity_info = self.severity_calculator.get_severity_info(stride_category, target_name, classification=data_classification, impact=threat_impact, likelihood=threat_likelihood)
                mitre_techniques = self.mitre_mapping.map_threat_to_mitre(threat_description)

                technique_ids = [tech['id'] for tech in mitre_techniques]
                automated_mitigations = get_mitigation_suggestions(technique_ids)

                owasp_mitigations = [m for m in automated_mitigations if m['framework'] == 'OWASP ASVS']
                nist_mitigations = [m for m in automated_mitigations if m['framework'] == 'NIST']
                cis_mitigations = [m for m in automated_mitigations if m['framework'] == 'CIS']

                for tech in mitre_techniques:
                    if 'defend_mitigations' in tech and tech['defend_mitigations']:
                        for mitigation in tech['defend_mitigations']:
                            # Extract the part after 'D3-XXXX ' for the URL
                            source_name = mitigation.get('url_friendly_name_source', '')
                            url_name_match = re.match(r'D3-[A-Z0-9]+\s(.*)', source_name)
                            url_friendly_name = url_name_match.group(1).replace(' ', '') if url_name_match else source_name.replace(' ', '')
                            mitigation['url_friendly_name'] = url_friendly_name

                all_detailed_threats.append({
                    "type": threat_type,
                    "description": threat_description,
                    "target": target_name,
                    "severity": severity_info,
                    "mitre_techniques": mitre_techniques,
                    "stride_category": stride_category,
                    "owasp_mitigations": owasp_mitigations,
                    "nist_mitigations": nist_mitigations,
                    "cis_mitigations": cis_mitigations,
                })
        return all_detailed_threats

    def _get_target_name_for_severity_calc(self, target: Any) -> str:
        """Determines the target name for severity calculation, handling different target types."""
        if isinstance(target, tuple):
            # Handle dataflows (source, sink)
            if len(target) == 2:
                source, sink = target
                # Check if source or sink is a Dataflow object itself
                if hasattr(source, 'source') and hasattr(source, 'sink'): # It's a dataflow
                    source_name = self._extract_name_from_object(source.source)
                else:
                    source_name = self._extract_name_from_object(source)

                if hasattr(sink, 'source') and hasattr(sink, 'sink'): # It's a dataflow
                    dest_name = self._extract_name_from_object(sink.sink)
                else:
                    dest_name = self._extract_name_from_object(sink)

                return f"{source_name} → {dest_name}"
        
        # Handle single elements (Actors, Servers, Boundaries, etc.)
        return self._extract_name_from_object(target)

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

    def generate_project_reports(self, project_path: Path, output_dir: Path):
        """
        Generates all reports for a project, ensuring a consistent legend across all diagrams.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Copy static files to the root of the output directory
        static_src_dir = Path(__file__).parent.parent / 'server' / 'static'
        static_dest_dir = output_dir / 'static'
        if static_src_dir.exists():
            # Remove existing static dir in output to ensure it's up-to-date
            if static_dest_dir.exists():
                shutil.rmtree(static_dest_dir)
            try:
                shutil.copytree(static_src_dir, static_dest_dir)
                logging.info(f"Copied static files to {static_dest_dir}")
            except Exception as e:
                logging.error(f"Failed to copy static files: {e}")

        # 1. Discover and parse all models in the project
        all_models = self._get_all_project_models(project_path)
        if not all_models:
            logging.error("No threat models found in the project. Aborting.")
            return

        # 2. Aggregate data from all models for consistent legends
        project_protocols, project_protocol_styles = self._aggregate_project_data(all_models)

        # 3. Start the recursive generation process
        self._recursively_generate_reports(
            model_path=project_path / "main.md",
            output_dir=output_dir,
            breadcrumb=[(project_path.name, "main_diagram.html")],
            project_protocols=project_protocols,
            project_protocol_styles=project_protocol_styles
        )

    def _get_all_project_models(self, project_path: Path) -> List[ThreatModel]:
        """
        Recursively finds and parses all 'model.md' or 'main.md' files in a project directory.
        """
        all_models = []
        model_files = list(project_path.glob("**/model.md")) + list(project_path.glob("**/main.md"))

        for model_path in model_files:
            try:
                with open(model_path, "r", encoding="utf-8") as f:
                    markdown_content = f.read()

                threat_model = create_threat_model(
                    markdown_content=markdown_content,
                    model_name=model_path.stem,
                    model_description=f"Threat model for {model_path.stem}",
                    mitre_mapping=self.mitre_mapping,
                    validate=False  # Validate later if needed
                )
                if threat_model:
                    all_models.append(threat_model)
            except Exception as e:
                logging.error(f"Error parsing model file {model_path}: {e}")
        return all_models

    def _aggregate_project_data(self, all_models: List[ThreatModel]) -> tuple[set, dict]:
        """
        Aggregates used protocols and protocol styles from a list of threat models.
        """
        project_protocols = set()
        project_protocol_styles = {}

        for model in all_models:
            # Aggregate used protocols
            if hasattr(model, 'dataflows'):
                for df in model.dataflows:
                    protocol = getattr(df, 'protocol', None)
                    if protocol:
                        project_protocols.add(protocol)

            # Aggregate protocol styles, allowing overrides
            if hasattr(model, 'get_all_protocol_styles'):
                styles = model.get_all_protocol_styles()
                project_protocol_styles.update(styles)

        return project_protocols, project_protocol_styles

    def _recursively_generate_reports(self, model_path: Path, output_dir: Path, breadcrumb: List[tuple[str, str]], project_protocols: set, project_protocol_styles: dict):
        """
        Recursively generates reports for each model in the project.
        """
        model_name = model_path.stem

        try:
            with open(model_path, "r", encoding="utf-8") as f:
                markdown_content = f.read()

            threat_model = create_threat_model(
                markdown_content=markdown_content,
                model_name=model_name,
                model_description=f"Threat model for {model_name}",
                mitre_mapping=self.mitre_mapping,
                validate=True
            )
            if not threat_model:
                logging.error(f"Failed to create threat model for {model_path}")
                return

            # Generate all files for the current model
            grouped_threats = threat_model.process_threats()
            self.generate_html_report(threat_model, grouped_threats, output_dir / f"{model_name}_threat_report.html")
            self.generate_json_export(threat_model, grouped_threats, output_dir / f"{model_name}.json")
            self.generate_diagram_html(threat_model, output_dir, breadcrumb, project_protocols, project_protocol_styles)

            # Recurse into submodels
            for server in threat_model.servers:
                if 'submodel' in server:
                    submodel_path_str = server['submodel']
                    # Resolve path relative to the current model file and validate
                    submodel_path = _validate_path_within_project(str(model_path.parent / submodel_path_str))

                    if submodel_path.is_file(): # .exists() is checked by _validate_path_within_project
                        sub_dir_name = submodel_path.parent.name
                        sub_output_dir = output_dir / sub_dir_name
                        sub_output_dir.mkdir(exist_ok=True)

                        new_breadcrumb = breadcrumb + [(sub_dir_name, f"{submodel_path.stem}_diagram.html")]

                        self._recursively_generate_reports(
                            model_path=submodel_path,
                            output_dir=sub_output_dir,
                            breadcrumb=new_breadcrumb,
                            project_protocols=project_protocols,
                            project_protocol_styles=project_protocol_styles
                        )
                    else:
                        logging.warning(f"Submodel file not found: {submodel_path}")
        except Exception as e:
            logging.error(f"Error processing model at {model_path}: {e}", exc_info=True)

    def generate_diagram_html(self, threat_model: ThreatModel, output_dir: Path, breadcrumb: List[tuple[str, str]], project_protocols: set, project_protocol_styles: dict):
        """
        Generates an HTML file containing just the diagram for navigation.
        """
        diagram_generator = DiagramGenerator()
        model_name = threat_model.tm.name

        dot_code = diagram_generator.generate_dot_file_from_model(threat_model, output_dir / f"{model_name}.dot", project_protocol_styles)
        if not dot_code:
            logging.error(f"Failed to generate DOT code for {model_name}")
            return

        svg_path = diagram_generator.generate_diagram_from_dot(dot_code, output_dir / f"{model_name}.svg", "svg")
        if not svg_path:
            logging.error(f"Failed to generate SVG for {model_name}")
            return

        with open(svg_path, "r", encoding="utf-8") as f:
            svg_content = f.read()

        svg_content = diagram_generator.add_links_to_svg(svg_content, threat_model)

        template = self.env.get_template('navigable_diagram_template.html')

        # Determine parent link
        parent_link = None
        if len(breadcrumb) > 1:
            parent_link = f"../{breadcrumb[-2][1]}"

        legend_html = diagram_generator._generate_legend_html(
            threat_model,
            project_protocols=project_protocols,
            project_protocol_styles=project_protocol_styles
        )

        html = template.render(
            title=f"Diagram - {model_name}",
            svg_content=svg_content,
            breadcrumb=breadcrumb,
            parent_link=parent_link,
            legend_html=legend_html
        )

        diagram_html_path = output_dir / f"{model_name}_diagram.html"
        with open(diagram_html_path, "w", encoding="utf-8") as f:
            f.write(html)
        logging.info(f"Generated diagram HTML: {diagram_html_path}")

