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

import os
import sys
import base64
import logging
import re
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file

from threat_analysis.server.threat_model_service import ThreatModelService
from threat_analysis import config

# Add project root to sys.path
project_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
if project_root not in sys.path:
    sys.sys.path.insert(0, project_root)

app = Flask(__name__, template_folder="templates")
logging.basicConfig(level=logging.INFO, stream=sys.stdout)

# Initialize the service layer
threat_model_service = ThreatModelService()

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


def get_model_name(markdown_content: str) -> str:
    match = re.search(r"^# Threat Model: (.*)$", markdown_content, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return "Untitled Model"


def run_gui(model_filepath: str = None):
    global initial_markdown_content
    if model_filepath and os.path.exists(model_filepath):
        try:
            with open(model_filepath, "r", encoding="utf-8") as f:
                initial_markdown_content = f.read()
            logging.info(f"Loaded initial threat model from {model_filepath}")
        except Exception as e:
            logging.error(
                f"Error loading initial model from {model_filepath}: {e}"
            )
            initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
            logging.info(
                "Loaded initial threat model from a temporary model due to "
                "file loading error."
            )
    else:
        initial_markdown_content = DEFAULT_EMPTY_MARKDOWN
        logging.info(
            "No initial threat model file provided or found. "
            "Starting with a default empty model."
        )

    print(
        "\n🚀 Starting Threat Model GUI. Open your browser to: "
        "http://127.0.0.1:5001\n"
    )
    app.run(debug=True, port=5001)


@app.route("/")
def index():
    """Serves the main web interface."""
    encoded_markdown = base64.b64encode(
        initial_markdown_content.encode("utf-8")
    ).decode("utf-8")
    model_name = get_model_name(initial_markdown_content)
    return render_template(
        "web_interface.html",
        initial_markdown=encoded_markdown,
        model_name=model_name,
    )


@app.route("/api/update", methods=["POST"])
def update_diagram():
    """
    Receives Markdown content, generates a threat model diagram,
    and returns the HTML representation of the diagram.
    """
    logging.info("Entering update_diagram function.")
    markdown_content = request.json.get("markdown", "")
    logging.info(
        f"Received markdown content for update (first 500 chars): "
        f"\n{markdown_content[:500]}..."
    )
    if not markdown_content:
        return jsonify({"error": "Markdown content is empty"}), 400

    try:
        result = threat_model_service.update_diagram_logic(markdown_content)
        model_name = get_model_name(markdown_content)
        result["model_name"] = model_name
        return jsonify(result)

    except ValueError as e:
        logging.error(f"Error during diagram update: {e}")
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        logging.error(f"Error during diagram update: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred during diagram update: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/api/export", methods=["POST"])
def export_files():
    """
    Handles exporting the model in various formats (SVG, HTML diagram, HTML report).
    """
    markdown_content = request.json.get("markdown", "")
    export_format = request.json.get("format")  # "svg", "diagram", "report"
    logging.info(f"Entering export_files function for format: {export_format}")

    if not markdown_content or not export_format:
        return (
            jsonify({"error": "Missing markdown content or export format"}),
            400,
        )

    try:
        output_path, output_filename = threat_model_service.export_files_logic(markdown_content, export_format)
        absolute_output_directory = os.path.join(project_root, os.path.dirname(output_path))
        return send_from_directory(
            absolute_output_directory, output_filename, as_attachment=True
        )

    except ValueError as e:
        logging.error(f"Error during export: {e}")
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        logging.error(f"Error during export: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred during export: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/api/export_all", methods=["POST"])
def export_all_files():
    """
    Handles exporting all generated files (Markdown, SVG, HTML diagram, HTML report, JSON analysis)
    as a single ZIP archive.
    """
    markdown_content = request.json.get("markdown", "")
    if not markdown_content:
        return jsonify({"error": "Missing markdown content"}), 400
    logging.info("Entering export_all_files function.")

    try:
        zip_buffer, timestamp = threat_model_service.export_all_files_logic(markdown_content)
        return send_file(
            zip_buffer,
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"threat_model_export_{timestamp}.zip",
        )

    except ValueError as e:
        logging.error(f"Error during export all: {e}")
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        logging.error(f"Error during export all: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred during export all: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500