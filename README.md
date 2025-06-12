# STRIDE Threat Analysis Framework with MITRE ATT&CK Integration

## Overview

This project provides a comprehensive Python-based framework for performing STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) threat analysis, with integrated mapping to MITRE ATT&CK techniques. It orchestrates the entire security analysis process, from parsing a threat model defined in Markdown to generating detailed HTML and JSON reports, along with visual diagrams of the system architecture and identified threats.

The framework is designed to be flexible, allowing users to define their system components, data flows, boundaries, and custom severity multipliers, as well as extend MITRE ATT&CK mappings.

## Features

* **Markdown-based Threat Modeling**: Define your system architecture (Actors, Servers, Dataflows, Boundaries, Data) in a simple and human-readable Markdown DSL (`threat_model.md`).
* **Automated STRIDE Threat Identification**: Automatically identifies potential STRIDE threats based on the defined model elements and data flows.
* **MITRE ATT&CK Mapping**: Maps identified STRIDE threats to relevant MITRE ATT&CK tactics and techniques.
* **Customizable Severity Calculation**:
    * Base severity scores for each STRIDE category.
    * Target-specific multipliers (e.g., critical servers have higher impact).
    * Protocol-based adjustments.
* **Comprehensive Report Generation**:
    * Detailed HTML report (`rapport_stride_mitre_[timestamp].html`) summarizing the analysis, including threat descriptions, severity scores, and MITRE ATT&CK mappings.
    * JSON export (`mitre_analysis_[timestamp].json`) of the analysis results.
* **Visual Diagram Generation**:
    * Generates architectural diagrams in DOT format (`tm_diagram_[timestamp].dot`).
    * Converts DOT diagrams to SVG images (`tm_diagram_[timestamp].svg`) for easy visualization (requires Graphviz).
    * Highlights elements with threats in the diagram based on severity.
* **Extensible and Modular**: Designed with a clear separation of concerns, making it easy to extend or modify specific components.

### Usage

1.  **Define Your Threat Model**: Edit the `threat_model.md` file according to the syntax described below.
2.  **Run the Analysis**: Execute the main script:
    ```bash
    python main_analysis.py
    ```
3.  **View Reports and Diagrams**:
    * HTML report: `output/stride_mitre_report.html`
    * JSON report: `output/stride_mitre_report.json`
    * Diagrams: `output/tm_diagram_*.svg` (or other formats based on configuration)

## Threat Model Definition (`threat_model.md`)

The `threat_model.md` file uses a simple Markdown-based Domain Specific Language (DSL) to describe your system's architecture. Each section defines different components of your threat model.

### Structure

Each section starts with a Markdown heading (e.g., `## Boundaries`). List items (`- **Name**: property=value, another_property=value`) are used to define individual elements and their properties.


## Installation

1.  **Clone the repository:**

    ```bash
    git clone <repository_url>
    cd <repository_name>
    ```

2.  **Install Python dependencies:**

    This project uses `pytm` for threat modeling primitives. You might need to install it along with other standard libraries.

    ```bash
    pip install pytm
    ```

3.  **Install Graphviz (for diagram generation):**

    The framework relies on Graphviz to convert DOT files into visual diagrams (like SVG). Follow the installation instructions for your operating system:

    **Windows:**
    * Download from [https://graphviz.org/download/](https://graphviz.org/download/)
    * Or use Chocolatey: `choco install graphviz`

    **macOS:**
    * Use Homebrew: `brew install graphviz`
    * Or MacPorts: `sudo port install graphviz`

    **Linux (Ubuntu/Debian):**
    * `sudo apt-get install graphviz`

    **Linux (CentOS/RHEL):**
    * `sudo yum install graphviz`
    * or `sudo dnf install graphviz`

    After installation, restart your terminal or IDE to ensure the `dot` command is in your PATH.

## Usage

1.  **Define your Threat Model:**
    Edit the `threat_model.md` file to describe your system's architecture using the provided DSL.
    An example `threat_model.md` is included with the repository, illustrating how to define:
    * `Boundaries` (e.g., Internet, DMZ, Intranet) with optional colors.
    * `Actors` (external clients, internal operators).
    * `Servers` (firewalls, application servers, databases).
    * `Data` types with classification and lifetime.
    * `Dataflows` between actors and servers, specifying protocols, data, authentication, and encryption status.
    * `Severity Multipliers` for specific elements.
    * `Custom Mitre Mapping` for defining new threat patterns and linking them to MITRE techniques.

    **Example Snippet from `threat_model.md`:**

    ```markdown
    # Threat Model: Advanced DMZ Architecture

    ## Description
    This model describes a network architecture with a Demilitarized Zone (DMZ), external and internal dataflows, and a potentially untrusted command zone. The goal is to identify STRIDE threats and map them to MITRE ATT&CK techniques.

    ## Boundaries
    - **Internet**: color=lightcoral
    - **DMZ**: color=khaki
    - **Intranet**: color=lightgreen
    - **Command Zone**: color=lightsteelblue

    ## Actors
    - **External Client 1**: boundary=Internet
    ...

    ## Dataflows
    - **External Client to External Firewall**: from="External Client 1", to="External Firewall", protocol="HTTPS", data="Web Traffic", is_encrypted=True
    ...

    ## Severity Multipliers
    - **Central Server**: 1.5
    - **Firewall Externe**: 2.0
    ...

    ## Custom Mitre Mapping
    - **Protocol Tampering**: tactics=["Impact", "Defense Evasion"], techniques=[{"id": "T1565", "name": "Data Manipulation"}, {"id": "T1499", "name": "Endpoint Denial of Service"}]
    ...
    ```

2.  **Run the Analysis:**
    Execute the `main_analysis.py` script from the root directory of the project.

    ```bash
    python main_analysis.py
    ```

    The script will:
    * Load and parse your `threat_model.md`.
    * Run the STRIDE threat analysis.
    * Generate HTML and JSON reports in a timestamped `output/` directory.
    * Generate DOT and SVG diagrams in the same `output/` directory.
    * Automatically open the HTML report in your default web browser.

## Output

After running the script, a new directory under `output/` (e.g., `output/2025-06-08_15-45-24`) will be created containing the following files:

* `rapport_stride_mitre_[timestamp].html`: A comprehensive HTML report of the threat analysis.
* `mitre_analysis_[timestamp].json`: A JSON export of the identified threats and their MITRE ATT&CK mappings.
* `tm_diagram_[timestamp].dot`: The Graphviz DOT file representing your threat model.
* `tm_diagram_[timestamp].svg`: The SVG image generated from the DOT file, visualizing your threat model.

## Current Limitations / Work in Progress

Please note that this project is currently under active development. The following features from `threat_model.md` parsing are not yet fully implemented and will be ignored by the parser:

* **Severity Multipliers**: While defined in `threat_model.md`, the framework's `model_parser` currently logs these as "ignored (method not implemented)". The `SeverityCalculator` itself supports multipliers, but the automatic parsing and application from the Markdown file is pending.
    * Example logged messages:
        * `ℹ️ Severity Multiplier ignored (method not implemented): Central Server = 1.5`
        * `ℹ️ Severity Multiplier ignored (method not implemented): External Firewall = 2.0`
        * `ℹ️ Severity Multiplier ignored (method not implemented): Protocol Break Device = 1.8`
        * `ℹ️ Severity Multiplier ignored (method not implemented): Switch = 1.5`
        * `ℹ️ Severity Multiplier ignored (method not implemented): Command Machine = 2.5`
* **Custom MITRE Mapping**: Similarly, custom MITRE ATT&CK mappings defined in `threat_model.md` are currently logged as "ignored (method not implemented)". The `MitreMapping` module supports custom mappings programmatically, but automatic parsing from Markdown is a future enhancement.
    * Example logged messages:
        * `ℹ️ Custom MITRE Mapping ignored (method not implemented): Protocol Tampering`
        * `ℹ️ Custom MITRE Mapping ignored (method not implemented): Unauthorized Access`
        * `ℹ️ Custom MITRE Mapping ignored (method not implemented): Weak Authentication`
        * `ℹ️ Custom MITRE Mapping ignored (method not implemented): Data Exfiltration`
        * `ℹ️ Custom MITRE Mapping ignored (method not implemented): Denial of Service Attack`
        * `ℹ️ Custom MITRE Mapping ignored (method not implemented): Privilege Escalation`

These features are planned for full integration in upcoming releases.

## Project Structure

* `main_analysis.py`: The main entry point for running the threat analysis.
* `threat_model.md`: Markdown file where the user defines the threat model.
* `threat_analysis/`: A package containing the core modules:
    * `__init__.py`: Initializes the `threat_analysis` package and defines version/author info.
    * `models_module.py`: Defines the `ThreatModel` class and its components (Actors, Servers, Dataflows, Boundaries, Data), representing the system under analysis. It handles the initial processing of threats.
    * `mitre_mapping_module.py`: Manages the mapping between STRIDE threat types and MITRE ATT&CK tactics and techniques. Allows for custom mappings.
    * `severity_calculator_module.py`: Implements the logic for calculating threat severity scores, incorporating base scores, target multipliers, and protocol adjustments.
    * `report_generator.py`: Responsible for generating the detailed HTML and JSON reports from the analysis results.
    * `diagram_generator.py`: Handles the creation of architectural diagrams in DOT format and their conversion to SVG using Graphviz.
    * `model_parser.py`: Parses the `threat_model.md` file and populates the `ThreatModel` object.

## Customization

You can customize the analysis behavior by modifying:

* **`threat_model.md`**: Add or modify boundaries, actors, servers, data, and dataflows. Note the current limitations on Severity Multipliers and Custom Mitre Mapping parsing (see "Current Limitations" section).
* **`severity_calculator_module.py`**: Modify `self.base_scores`, `self.target_multipliers`, and `self.protocol_adjustments` to fine-tune severity calculations.
* **`mitre_mapping_module.py`**: Extend or modify `self.mapping` and `self.threat_patterns` to adjust how STRIDE threats are mapped to MITRE ATT&CK and how they are recognized.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

## Author

**ellipse2v**