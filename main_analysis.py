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
Main STRIDE threat analysis module with MITRE ATT&CK integration
Complete orchestration of security analysis - Modified version
"""
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Import library modules (corrected relative imports)
from threat_analysis.models_module import ThreatModel
from threat_analysis.mitre_mapping_module import MitreMapping
from threat_analysis.severity_calculator_module import SeverityCalculator
from threat_analysis.report_generator import ReportGenerator
from threat_analysis.diagram_generator import DiagramGenerator
from threat_analysis.model_parser import ModelParser

class ThreatAnalysisFramework:
    """Main framework for threat analysis"""

    def __init__(self, model_filepath: str = "threat_model.md",
                 model_name: str = "Enhanced DMZ Security Analysis",
                 model_description: str = "Advanced DMZ architecture with 8 external flows and command zone"):
        """Initializes the analysis framework"""
        self.model_filepath = model_filepath
        self.model_name = model_name
        self.model_description = model_description

        # --- Output path management with timestamp ---
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        self.output_base_dir = os.path.join("output", timestamp)
        os.makedirs(self.output_base_dir, exist_ok=True)
        print(f"📁 Output files will be generated in: {os.path.abspath(self.output_base_dir)}")

        self.html_report_filename = f"stride_mitre_report_{timestamp}.html"
        self.json_report_filename = f"mitre_analysis_{timestamp}.json"
        self.dot_diagram_filename = f"tm_diagram_{timestamp}.dot"
        self.svg_diagram_filename = f"tm_diagram_{timestamp}.svg"
        self.html_diagram_filename = f"tm_diagram_{timestamp}.html"
        # --- End of output path management ---

        # Component initialization
        self.threat_model = ThreatModel(model_name, model_description)
        self.mitre_mapping = MitreMapping()
        self.severity_calculator = SeverityCalculator()
        self.report_generator = ReportGenerator(self.severity_calculator, self.mitre_mapping)
        self.diagram_generator = DiagramGenerator()

        print(f"🚀 Analysis framework initialized: {model_name}")

        self._load_model_from_dsl()

        # NEW: Diagnostic to check if the model has been populated
        model_stats = self.threat_model.get_statistics()
        
        if model_stats['actors'] == 0 and model_stats['servers'] == 0 and model_stats['dataflows'] == 0:
            print("⚠️ WARNING: The model appears to be empty or was not parsed correctly. Check your 'threat_model.md'.")
        
        # Analysis state (after model loading)
        self.analysis_completed = False
        self.grouped_threats = {}
        self.custom_threats_list = []
        self.elements_with_custom_threats = set()

    def _load_model_from_dsl(self):
        """Loads the threat model from the Markdown DSL file."""
        print(f"⏳ Loading model from {self.model_filepath}...")
        try:
            with open(self.model_filepath, 'r', encoding='utf-8') as f:
                markdown_content = f.read()
            parser = ModelParser(self.threat_model, self.mitre_mapping)
            parser.parse_markdown(markdown_content)
            # The custom threats are now generated within the ThreatModel class
            # self.custom_threats_list, self.elements_with_custom_threats = parser._apply_custom_threats()
            print(f"✅ Model loaded successfully from {self.model_filepath}")
        except FileNotFoundError:
            print(f"❌ Error: Model file '{self.model_filepath}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error parsing model: {e}")
            sys.exit(1)

    def run_analysis(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Executes the threat analysis."""
        print("🔬 Starting STRIDE threat analysis...")

        self.severity_calculator.update_target_multipliers(self.mitre_mapping.severity_multipliers)

        self.grouped_threats = self.threat_model.process_threats()
        self.analysis_completed = True
        print("✅ Threat analysis completed.")
        return self.grouped_threats

    def generate_reports(self) -> Dict[str, str]:
        """Generates HTML and JSON reports in the timestamped directory."""
        if not self.analysis_completed:
            print("⚠️ Analysis has not been run. Execute run_analysis() first.")
            return {}

        print("📊 Generating reports...")
        
        html_output_full_path = os.path.join(self.output_base_dir, self.html_report_filename)
        json_output_full_path = os.path.join(self.output_base_dir, self.json_report_filename)

        html_report_path = self.report_generator.generate_html_report(
            self.threat_model, self.grouped_threats, html_output_full_path
        )
        json_report_path = self.report_generator.generate_json_export(
            self.threat_model, self.grouped_threats, json_output_full_path
        )
        print("✅ Reports generated.")
        return {"html": html_report_path, "json": json_report_path}

    def generate_diagrams(self) -> Dict[str, Optional[str]]:
        """Generates DOT, SVG and HTML diagrams in the timestamped directory."""
        print("🖼️ Generating diagrams...")
        if not self.diagram_generator.check_graphviz_installation():
            print(self.diagram_generator.get_installation_instructions())
            return {"dot": None, "svg": None, "html": None}

        dot_output_full_path = os.path.join(self.output_base_dir, self.dot_diagram_filename)
        svg_output_full_path = os.path.join(self.output_base_dir, self.svg_diagram_filename)
        html_output_full_path = os.path.join(self.output_base_dir, self.html_diagram_filename)

        # Generate DOT file
        dot_path = self.diagram_generator.generate_dot_file_from_model(self.threat_model, dot_output_full_path)
        
        svg_path = None
        html_path = None
        
        if dot_path:  # If DOT file was successfully generated
            try:
                # Read DOT file content to pass to generate_diagram_from_dot
                with open(dot_path, 'r', encoding='utf-8') as f:
                    dot_code_content = f.read()
                
                # Generate SVG
                svg_path = self.diagram_generator.generate_diagram_from_dot(dot_code_content, svg_output_full_path, "svg")
                
                # Generate HTML with embedded SVG and positioned legend
                if svg_path:
                    html_path = self.diagram_generator._generate_html_with_legend(svg_path, html_output_full_path, self.threat_model)
            except Exception as e:
                print(f"❌ Error reading DOT file to generate SVG/HTML: {e}")

        
        return {"dot": dot_path, "svg": svg_path, "html": html_path}


    def open_report_in_browser(self, report_path: str):
        """Opens the HTML report in the default browser."""
        try:
            if os.path.exists(report_path):
                import webbrowser
                webbrowser.open(os.path.abspath(report_path))
                
            else:
                print(f"⚠️ HTML report not found at: {os.path.abspath(report_path)}")
        except Exception as e:
            pass


# --- Main entry point ---
if __name__ == "__main__":
    model_file = "threat_model.md"

    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    framework = ThreatAnalysisFramework(model_filepath=model_file)

    threats = framework.run_analysis()

    reports = framework.generate_reports()

    diagrams = framework.generate_diagrams()

    #if "html" in reports and reports["html"]:
    #    framework.open_report_in_browser(reports["html"])