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
import argparse
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

# Import library modules
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.severity_calculator_module import SeverityCalculator
from threat_analysis.generation.report_generator import ReportGenerator
from threat_analysis.generation.diagram_generator import DiagramGenerator
from threat_analysis.core.model_factory import create_threat_model
from threat_analysis import config


class ThreatAnalysisFramework:
    """Main framework for threat analysis"""

    def __init__(
        self, model_filepath: str, model_name: str, model_description: str
    ):
        """Initializes the analysis framework"""
        self.model_filepath = model_filepath
        self.model_name = model_name
        self.model_description = model_description

        # --- Output path management ---
        self.output_base_dir = config.OUTPUT_BASE_DIR
        os.makedirs(self.output_base_dir, exist_ok=True)
        logging.info(
            f"📁 Output files will be generated in: "
            f"{os.path.abspath(self.output_base_dir)}"
        )

        self.html_report_filename = config.HTML_REPORT_FILENAME_TPL.format(
            timestamp=config.TIMESTAMP
        )
        self.json_report_filename = config.JSON_REPORT_FILENAME_TPL.format(
            timestamp=config.TIMESTAMP
        )
        self.dot_diagram_filename = config.DOT_DIAGRAM_FILENAME_TPL.format(
            timestamp=config.TIMESTAMP
        )
        self.svg_diagram_filename = config.SVG_DIAGRAM_FILENAME_TPL.format(
            timestamp=config.TIMESTAMP
        )
        self.html_diagram_filename = config.HTML_DIAGRAM_FILENAME_TPL.format(
            timestamp=config.TIMESTAMP
        )
        # --- End of output path management ---

        # Component initialization
        self.mitre_mapping = MitreMapping()
        self.threat_model = self._load_and_validate_model()
        if not self.threat_model:
            sys.exit(1)  # Exit if model loading fails

        self.severity_calculator = SeverityCalculator(
            markdown_file_path=self.model_filepath
        )
        self.report_generator = ReportGenerator(
            self.severity_calculator, self.mitre_mapping
        )
        self.diagram_generator = DiagramGenerator()

        logging.info(f"🚀 Analysis framework initialized: {model_name}")

        # NEW: Diagnostic to check if the model has been populated
        model_stats = self.threat_model.get_statistics()

        if (
            model_stats["actors"] == 0
            and model_stats["servers"] == 0
            and model_stats["dataflows"] == 0
        ):
            logging.warning(
                "⚠️ WARNING: The model appears to be empty or was not parsed "
                "correctly. Check your 'threat_model.md'."
            )

        # Analysis state (after model loading)
        self.analysis_completed = False
        self.grouped_threats = {}
        self.custom_threats_list = []
        self.elements_with_custom_threats = set()

    def _load_and_validate_model(self) -> Optional[ThreatModel]:
        """Loads and validates the threat model from the Markdown DSL file."""
        logging.info(f"⏳ Loading model from {self.model_filepath}...")
        try:
            with open(self.model_filepath, "r", encoding="utf-8") as f:
                markdown_content = f.read()

            return create_threat_model(
                markdown_content=markdown_content,
                model_name=self.model_name,
                model_description=self.model_description,
                mitre_mapping=self.mitre_mapping,
                validate=True,
            )

        except FileNotFoundError:
            logging.error(
                f"❌ Error: Model file '{self.model_filepath}' not found."
            )
            return None
        except Exception as e:
            logging.error(f"❌ Error parsing or validating model: {e}")
            return None

    def run_analysis(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Executes the threat analysis."""
        logging.info("🔬 Starting STRIDE threat analysis...")

        self.grouped_threats = self.threat_model.process_threats()
        self.analysis_completed = True
        logging.info("✅ Threat analysis completed.")
        return self.grouped_threats

    def generate_reports(self) -> Dict[str, str]:
        """Generates HTML and JSON reports in the timestamped directory."""
        if not self.analysis_completed:
            logging.warning(
                "⚠️ Analysis has not been run. Execute run_analysis() first."
            )
            return {}

        logging.info("📊 Generating reports...")

        html_output_full_path = os.path.join(
            self.output_base_dir, self.html_report_filename
        )
        json_output_full_path = os.path.join(
            self.output_base_dir, self.json_report_filename
        )

        html_report_path = self.report_generator.generate_html_report(
            self.threat_model, self.grouped_threats, html_output_full_path
        )
        json_report_path = self.report_generator.generate_json_export(
            self.threat_model, self.grouped_threats, json_output_full_path
        )
        logging.info("✅ Reports generated.")
        return {"html": html_report_path, "json": json_report_path}

    def generate_diagrams(self) -> Dict[str, Optional[str]]:
        """Generates DOT, SVG and HTML diagrams in the timestamped directory."""
        logging.info("🖼️ Generating diagrams...")
        if not self.diagram_generator.check_graphviz_installation():
            logging.warning(
                self.diagram_generator.get_installation_instructions()
            )
            return {"dot": None, "svg": None, "html": None}

        dot_output_full_path = os.path.join(
            self.output_base_dir, self.dot_diagram_filename
        )
        svg_output_full_path = os.path.join(
            self.output_base_dir, self.svg_diagram_filename
        )
        html_output_full_path = os.path.join(
            self.output_base_dir, self.html_diagram_filename
        )

        # Generate DOT file
        dot_path = self.diagram_generator.generate_dot_file_from_model(
            self.threat_model, dot_output_full_path
        )

        svg_path = None
        html_path = None

        if dot_path:  # If DOT file was successfully generated
            try:
                # Read DOT file content to pass to generate_diagram_from_dot
                with open(dot_path, "r", encoding="utf-8") as f:
                    dot_code_content = f.read()

                # Generate SVG
                svg_path = self.diagram_generator.generate_diagram_from_dot(
                    dot_code_content, svg_output_full_path, "svg"
                )

                # Generate HTML with embedded SVG and positioned legend
                if svg_path:
                    html_path = (
                        self.diagram_generator._generate_html_with_legend(
                            svg_path, html_output_full_path, self.threat_model
                        )
                    )
            except Exception as e:
                logging.error(
                    f"❌ Error reading DOT file to generate SVG/HTML: {e}"
                )

        return {"dot": dot_path, "svg": svg_path, "html": html_path}

    def open_report_in_browser(self, report_path: str):
        """Opens the HTML report in the default browser."""
        try:
            if os.path.exists(report_path):
                import webbrowser

                webbrowser.open(os.path.abspath(report_path))

            else:
                logging.warning(
                    f"⚠️ HTML report not found at: "
                    f"{os.path.abspath(report_path)}"
                )
        except Exception:
            pass


class CustomArgumentParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="Threat Analysis Framework",
            epilog=(
                "This script also accepts PyTM arguments. "
                "Use --help with PyTM commands for more details."
            ),
        )
        self.parser.add_argument(
            "--model-file",
            type=str,
            default=config.DEFAULT_MODEL_FILEPATH,
            help="Path to the threat model Markdown file.",
        )
        self.parser.add_argument(
            "--gui", action="store_true", help="Launch the web-based GUI editor."
        )

    def parse_args(self):
        return self.parser.parse_known_args()


# --- Main entry point ---
if __name__ == "__main__":
    custom_parser = CustomArgumentParser()
    args, remaining_argv = custom_parser.parse_args()

    # Reconstruct sys.argv for PyTM
    sys.argv = [sys.argv[0]] + remaining_argv

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    if args.gui:
        try:
            from threat_analysis.server.server import run_gui

            run_gui(args.model_file)
        except ImportError:
            logging.error(
                "❌ Flask is not installed. Please install it to use the GUI: "
                "pip install Flask"
            )
            sys.exit(1)
    else:
        framework = ThreatAnalysisFramework(
            model_filepath=Path(args.model_file),
            model_name=config.DEFAULT_MODEL_NAME,
            model_description=config.DEFAULT_MODEL_DESCRIPTION,
        )

        threats = framework.run_analysis()

        reports = framework.generate_reports()

        diagrams = framework.generate_diagrams()

        # if "html" in reports and reports["html"]:
        #     framework.open_report_in_browser(reports["html"])
