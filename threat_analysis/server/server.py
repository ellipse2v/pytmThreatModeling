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
# 
import os
import sys
from flask import Flask, render_template, request, jsonify, send_from_directory
import logging
from jinja2 import Environment, FileSystemLoader

from threat_analysis.core.models_module import ThreatModel
from threat_analysis.core.model_parser import ModelParser
from threat_analysis.core.model_validator import ModelValidator
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.severity_calculator_module import SeverityCalculator
from threat_analysis.generation.report_generator import ReportGenerator
from threat_analysis.generation.diagram_generator import DiagramGenerator
from threat_analysis import config

import json
import base64
import re
import datetime
import zipfile
from io import BytesIO
from flask import send_file # Import send_file

# Add project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

app = Flask(__name__, template_folder='templates')
logging.basicConfig(level=logging.INFO, stream=sys.stdout)

# --- Global Components ---
# These are initialized once to be reused across requests.
mitre_mapping = MitreMapping()
severity_calculator = SeverityCalculator() # Assuming default initialization is sufficient
diagram_generator = DiagramGenerator()
report_generator = ReportGenerator(severity_calculator, mitre_mapping)
# ---

initial_markdown_content = ""

DEFAULT_EMPTY_MARKDOWN = """# Threat Model: New Model

## Description
A new threat model. Describe your system here.

## Boundaries
- **Default Boundary**: color=lightgray

## Actors
- **User**: boundary=Default Boundary

## Servers
- **Application Server**: boundary=Default Boundary

## Dataflows
- **User to Application Server**: from="User", to="Application Server", protocol="HTTPS"

## Severity Multipliers
# Example:
# - **Application Server**: 1.5

## Custom Mitre Mapping
# Example:
# - **Custom Attack**: tactics=["Initial Access"], techniques=[{"id": "T1000", "name": "Custom Technique"}]
"""

def run_gui(model_filepath: str = None):
    global initial_markdown_content
    if model_filepath and os.path.exists(model_filepath):
        try:
            with open(model_filepath, 'r', encoding='utf-8') as f:
                initial_markdown_content = f.read()
            logging.info(f"Loaded initial threat model from {model_filepath}")
        except Exception as e:
            logging.error(f"Error loading initial model from {model_filepath}: {e}")
            initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
            logging.info("Loaded initial threat model from a temporary model due to file loading error.")
    else:
        initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
        logging.info("No initial threat model file provided or found. Starting with a default empty model.")

    print("\n🚀 Starting Threat Model GUI. Open your browser to: http://127.0.0.1:5001\n")
    app.run(debug=True, port=5001)

@app.route('/')
def index():
    """Serves the main web interface."""
    encoded_markdown = base64.b64encode(initial_markdown_content.encode('utf-8')).decode('utf-8')
    return render_template('web_interface.html', initial_markdown=encoded_markdown)

@app.route('/api/update', methods=['POST'])
def update_diagram():
    """
    Receives Markdown content, generates a threat model diagram,
    and returns the HTML representation of the diagram.
    """
    logging.info("Entering update_diagram function.")
    markdown_content = request.json.get('markdown', '')
    logging.info(f"Received markdown content for update (first 500 chars): \n{markdown_content[:500]}...")
    if not markdown_content:
        return jsonify({'error': 'Markdown content is empty'}), 400

    try:
        # Save the received markdown to a temporary file
        tmp_md_path = os.path.join(config.TMP_DIR, "live_model.md")
        os.makedirs(config.TMP_DIR, exist_ok=True)
        with open(tmp_md_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        logging.info(f"Saved live markdown to {tmp_md_path}")

        # 1. Create a new ThreatModel instance for each request
        threat_model = ThreatModel("WebThreatModel", "Live-updated threat model")

        # 2. Parse the Markdown content
        parser = ModelParser(threat_model, mitre_mapping)
        parser.parse_markdown(markdown_content)
        logging.info(f"ThreatModel after parsing: Actors={threat_model.actors}, Boundaries={threat_model.boundaries}, Servers={threat_model.servers}, Dataflows={threat_model.dataflows}")

        # 3. Generate the DOT code from the model
        dot_code = diagram_generator._generate_manual_dot(threat_model)
        logging.info(f"Generated DOT code (first 500 chars): \n{dot_code[:500]}...")
        if not dot_code:
            return jsonify({'error': 'Failed to generate DOT code from model'}), 500

        # 4. Generate the SVG from the DOT code
        # We create a temporary file for the SVG output
        temp_svg_path = os.path.join(config.TMP_DIR, "live_preview.svg")
        os.makedirs(os.path.dirname(temp_svg_path), exist_ok=True) # Ensure directory exists
        svg_path = diagram_generator.generate_diagram_from_dot(dot_code, temp_svg_path, "svg")

        if not svg_path or not os.path.exists(svg_path):
            return jsonify({'error': 'Failed to generate SVG diagram'}), 500
        
        # 5. Read the SVG content
        with open(svg_path, 'r', encoding='utf-8') as f:
            svg_content = f.read()

        # 6. Generate the legend
        legend_html = diagram_generator._generate_legend_html(threat_model)

        # 7. Combine into a full HTML document for other purposes if needed
        full_html = diagram_generator._create_complete_html(svg_content, legend_html, threat_model)

        # 8. Return raw SVG, legend, and full HTML
        return jsonify({
            'diagram_html': full_html,
            'diagram_svg': svg_content,
            'legend_html': legend_html
        })

    except Exception as e:
        logging.error(f"Error during diagram update: {e}", exc_info=True)
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@app.route('/api/export', methods=['POST'])
def export_files():
    """
    Handles exporting the model in various formats (SVG, HTML diagram, HTML report).
    """
    markdown_content = request.json.get('markdown', '')
    export_format = request.json.get('format') # "svg", "diagram", "report"
    logging.info(f"Entering export_files function for format: {export_format}")

    if not markdown_content or not export_format:
        return jsonify({'error': 'Missing markdown content or export format'}), 400

    try:
        # --- Common processing for all formats ---
        threat_model = ThreatModel("ExportedThreatModel", "Exported from web interface")
        parser = ModelParser(threat_model, mitre_mapping)
        parser.parse_markdown(markdown_content)
        
        # Ensure the output directory exists
        os.makedirs(config.OUTPUT_BASE_DIR, exist_ok=True)

        # --- Format-specific generation ---
        if export_format == 'svg':
            dot_code = diagram_generator._generate_manual_dot(threat_model)
            output_filename = "diagram.svg"
            output_path = os.path.join(config.OUTPUT_BASE_DIR, output_filename)
            generated_path = diagram_generator.generate_diagram_from_dot(dot_code, output_path, "svg")
            if not generated_path:
                 return jsonify({'error': 'Failed to generate SVG file'}), 500
            return send_from_directory(config.OUTPUT_BASE_DIR, output_filename, as_attachment=True)

        elif export_format == 'diagram':
            dot_code = diagram_generator._generate_manual_dot(threat_model)
            svg_path_temp = os.path.join(config.OUTPUT_BASE_DIR, "temp_diagram.svg")
            diagram_generator.generate_diagram_from_dot(dot_code, svg_path_temp, "svg")
            
            output_filename = "diagram.html"
            output_path = os.path.join(config.OUTPUT_BASE_DIR, output_filename)
            diagram_generator._generate_html_with_legend(svg_path_temp, output_path, threat_model)
            return send_from_directory(config.OUTPUT_BASE_DIR, output_filename, as_attachment=True)

        elif export_format == 'report':
            # We need to run the full analysis to generate a report
            grouped_threats = threat_model.process_threats()
            output_filename = "threat_report.html"
            output_path = os.path.join(config.OUTPUT_BASE_DIR, output_filename)
            report_generator.generate_html_report(threat_model, grouped_threats, output_path)
            return send_from_directory(config.OUTPUT_BASE_DIR, output_filename, as_attachment=True)

        else:
            return jsonify({'error': 'Invalid export format'}), 400

    except Exception as e:
        logging.error(f"Error during export for format {export_format}: {e}", exc_info=True)
        return jsonify({'error': f'An error occurred during export: {str(e)}'}), 500

@app.route('/api/export_all', methods=['POST'])
def export_all_files():
    """
    Handles exporting all generated files (Markdown, SVG, HTML diagram, HTML report, JSON analysis)
    as a single ZIP archive.
    """
    markdown_content = request.json.get('markdown', '')
    if not markdown_content:
        return jsonify({'error': 'Missing markdown content'}), 400
    logging.info("Entering export_all_files function.")

    try:
        # Create a unique timestamped directory for this export
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        export_dir_name = f"export_{timestamp}"
        export_path = os.path.join(config.OUTPUT_BASE_DIR, export_dir_name)
        os.makedirs(export_path, exist_ok=True)

        # Initialize ThreatModel and parse content
        threat_model = ThreatModel("ExportedThreatModel", "Exported from web interface")
        parser = ModelParser(threat_model, mitre_mapping)
        parser.parse_markdown(markdown_content)

        # --- Generate all files ---
        # 1. Save Markdown content
        markdown_filename = "threat_model.md"
        markdown_filepath = os.path.join(export_path, markdown_filename)
        with open(markdown_filepath, 'w', encoding='utf-8') as f:
            f.write(markdown_content)

        # 2. Generate SVG diagram
        dot_code = diagram_generator._generate_manual_dot(threat_model)
        svg_filename = "tm_diagram.svg"
        svg_filepath = os.path.join(export_path, svg_filename)
        diagram_generator.generate_diagram_from_dot(dot_code, svg_filepath, "svg")

        # 3. Generate HTML diagram
        html_diagram_filename = "tm_diagram.html"
        html_diagram_filepath = os.path.join(export_path, html_diagram_filename)
        diagram_generator._generate_html_with_legend(svg_filepath, html_diagram_filepath, threat_model)

        # 4. Generate HTML report and JSON analysis
        grouped_threats = threat_model.process_threats()
        html_report_filename = "stride_mitre_report.html"
        html_report_filepath = os.path.join(export_path, html_report_filename)
        report_generator.generate_html_report(threat_model, grouped_threats, html_report_filepath)

        json_analysis_filename = "mitre_analysis.json"
        json_analysis_filepath = os.path.join(export_path, json_analysis_filename)
        report_generator.generate_json_analysis(threat_model, grouped_threats, json_analysis_filepath)

        # --- Create ZIP archive ---
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(export_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Add file to zip, preserving directory structure relative to export_path
                    zf.write(file_path, os.path.relpath(file_path, export_path))
        zip_buffer.seek(0)

        # Clean up the temporary export directory
        import shutil
        shutil.rmtree(export_path)

        return send_file(zip_buffer,
                         mimetype='application/zip',
                         as_attachment=True,
                         download_name=f'threat_model_export_{timestamp}.zip')

    except Exception as e:
        logging.error(f"Error during export all: {e}", exc_info=True)
        return jsonify({'error': f'An error occurred during export all: {str(e)}'}), 500