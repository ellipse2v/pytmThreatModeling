# ThreatModelByPyTM: A Technical Deep Dive

## 1. Introduction

### 1.1. The Challenge: From Manual Diagrams to Automated Analysis

As software systems grow in complexity, proactively identifying security vulnerabilities during the design phase is significantly more effective than reacting to them post-deployment. Threat modeling provides a structured process for this, but traditional approaches often rely on manual diagramming and static documents that are difficult to maintain and impossible to integrate into automated development pipelines.

This document provides a detailed technical overview of the **ThreatModelByPyTM** framework, a tool designed to address these challenges by treating the threat model as a living artifact that evolves with the system itself.

### 1.2. Core Philosophy: System-Level Threat Model as Code

The guiding philosophy of this framework is **Threat Model as Code (TMaC)**, applied at the **system level**. Instead of focusing on abstract application components, our approach defines the entire system architecture—including infrastructure, network boundaries, and data flows—in a simple, version-controllable format.

This is particularly powerful when generating models directly from **Infrastructure as Code (IaC)** sources like Ansible playbooks. By parsing the same files that define the deployed environment, the framework creates a threat model that is a true representation of the running system. This enables a seamless, automated workflow where changes in infrastructure are immediately reflected in the threat analysis.

By defining the system in a Markdown DSL, the threat model becomes:
-   **Versioned**: Stored in Git to track its evolution alongside the source code and infrastructure code.
-   **Automated**: Integrated directly into CI/CD pipelines to run analysis on every change.
-   **Collaborative**: Developers and operations engineers can contribute using the same tools and workflows they use for code.

## 2. Comparison with Other Threat Modeling Tools

To understand the unique value of ThreatModelByPyTM, it's useful to compare it to other popular tools, focusing on the key differentiator: **automation**.

| Feature | Microsoft TMT | OWASP Threat Dragon | ThreatModelByPyTM (This Tool) |
| :--- | :--- | :--- | :--- |
| **Primary Paradigm** | GUI-based Diagramming | Web-based Diagramming | **Threat Model as Code (TMaC)** |
| **Input Format** | Proprietary `.tm7` format | JSON, with a web UI | **Markdown (DSL) / IaC Playbooks** |
| **Automation & CI/CD** | None. Fully manual process. | Limited. Has an API but is not designed for pipeline integration. | **Core Feature**. Designed to be run from the CLI in a pipeline. |
| **IaC Integration** | None. | None. | **Yes (Ansible)**. Can generate a model directly from infrastructure definitions. |
| **Version Control** | Possible by archiving the `.tm7` model file. However, the format is complex (XML-based) and not well-suited for line-by-line diffing or merging. | Feasible (JSON), but the diagram is the primary source of truth, not the code. | **Seamless**. Markdown is text-based and ideal for Git. |
| **Extensibility** | Limited to templates. | Good. Open-source and extensible. | **High**. Mappings and logic are in simple Python dictionaries and modules. |

## 3. High-Level Architecture

The framework is a Python-based application that can be run as a command-line tool (for automation) or a web server (for interactive editing). It ingests a threat model source and produces a suite of artifacts.

```mermaid
graph TD
    subgraph Input Sources
        A[Markdown File (.md)]
        B[Project Directory]
        C[Ansible Playbook]
    end

    subgraph Processing Core
        D[Model Parser & Factory]
        E[Rule-Based Threat Engine]
        F[Severity Calculator]
        G[MITRE/CAPEC Mapping Module]
    end

    subgraph Output Artifacts
        H[HTML Report]
        I[JSON Analysis]
        J[STIX 2.1 Bundle]
        K[Navigable HTML Diagram]
        L[SVG/PNG Diagram]
    end

    A --> D
    B --> D
    C --> D

    D -- Parsed Model --> E
    E -- Identified Threats --> F
    F -- Scored Threats --> G
    G -- Enriched Threats --> H
    G -- Enriched Threats --> I
    G -- Enriched Threats --> J
    D -- Parsed Model --> K
    D -- Parsed Model --> L
```

## 4. Technical Deep Dive: Module by Module

This section provides a comprehensive breakdown of each component of the ThreatModelByPyTM framework.

### 4.1. Entrypoint and Orchestration (`threat_analysis/__main__.py`)

The execution of the framework begins in `__main__.py`. This script is responsible for:
-   **Argument Parsing**: It uses a `CustomArgumentParser` to handle command-line arguments. This includes standard arguments like `--model-file`, `--gui`, and `--project`, but it also dynamically loads IaC plugins from the `iac_plugins` directory and adds corresponding arguments for them (e.g., `--ansible-path`).
-   **Mode Selection**: It determines the execution mode based on the arguments:
    -   `--gui`: Launches the Flask web server via `server.run_gui()`.
    -   `--project`: Initiates a hierarchical project analysis via `report_generator.generate_project_reports()`.
    -   `--<iac-plugin>-path`: Triggers the IaC import workflow.
    -   Default: Proceeds with a standard single-file analysis.
-   **Framework Orchestration**: For standard and IaC-based runs, it instantiates the `ThreatAnalysisFramework` class, which coordinates the entire analysis pipeline from model loading to report generation.

### 4.2. Core Model (`threat_analysis/core/models_module.py`)

The `ThreatModel` class is the central data structure, encapsulating the entire state of the system being analyzed.
-   **Inheritance**: It wraps the `pytm.TM` object, leveraging its foundational threat generation capabilities.
-   **Data Structures**: It maintains collections for all system components: `boundaries`, `actors`, `servers`, `dataflows`, `data_objects`, and configuration settings like `protocol_styles` and `severity_multipliers`.
-   **Element Management**: The `add_*` methods (`add_boundary`, `add_server`, etc.) are responsible for creating `pytm` objects and storing them along with their metadata (like colors and custom properties) in the appropriate collections. The `_elements_by_name` dictionary provides a fast lookup mechanism for retrieving any component by its name.
-   **`process_threats()`**: This is the primary analysis method. It orchestrates validation, threat generation (from both `pytm` and custom rules), grouping, and MITRE analysis.
-   **`_expand_class_targets()`**: A crucial helper method that takes generic threats targeted at a *class* of objects (e.g., `Server`) and creates a specific threat instance for every `Server` object defined in the model. This ensures that all components are evaluated correctly.

### 4.3. Model Parsing and Validation

-   **`model_factory.py`**: The `create_threat_model` function acts as a centralized factory. It simplifies the creation process by encapsulating the instantiation of `ThreatModel`, `ModelParser`, and `ModelValidator`, ensuring a consistent and valid model is produced.
-   **`model_parser.py`**: The `ModelParser` class is responsible for translating the Markdown DSL into the in-memory `ThreatModel` object.
    -   It employs a **two-pass parsing strategy**. The first pass processes element definitions (Boundaries, Actors, Servers, Data) to ensure all components exist before relationships are established. The second pass processes Dataflows and other configurations that reference these elements.
    -   The `_parse_key_value_params` method uses a regular expression to flexibly parse `key=value` attributes, handling quoted strings, booleans, and numbers.
-   **`model_validator.py`**: The `ModelValidator` ensures the integrity of the parsed model. It performs several checks:
    -   **Unique Names**: Verifies that all elements (actors, servers, dataflows, etc.) have unique names.
    -   **Dataflow References**: Confirms that the `from` and `to` fields in dataflows refer to elements that actually exist in the model.
    -   **Boundary References**: Ensures that actors and servers assigned to a boundary refer to a defined boundary.

### 4.4. Threat Generation Engine

-   **`threat_rules.py`**: This file is a static dictionary (`THREAT_RULES`) that defines the conditions under which threats are generated. It is structured by component type (`servers`, `dataflows`, `actors`). Each rule contains:
    -   `conditions`: A dictionary of properties that a component must have to trigger the rule (e.g., `{"is_encrypted": False}`).
    -   `threats`: A list of threat templates to be created if the conditions are met.
-   **`custom_threats.py`**: This module contains the `RuleBasedThreatGenerator`.
    -   Its `generate_threats` method iterates through all components in the `ThreatModel`.
    -   For each component, it checks its properties against the rules in `threat_rules.py`.
    -   A key feature is its **boundary-aware logic** for dataflows. It checks the source and sink boundaries of a flow (e.g., `source_boundary: "DMZ"`, `sink_boundary: "Internal"`) to apply highly specific threats for traffic crossing between different network zones.

### 4.5. The STRIDE, CAPEC, and ATT&CK Mapping (`mitre_mapping_module.py`)

This is the most complex and critical module for enriching the raw threat data.

-   **`tooling/download_stride_mappings.py`**: This utility script is the origin of the STRIDE-to-CAPEC mapping. It downloads data from public sources, parses it to extract CAPEC IDs associated with each STRIDE element, and saves the result to `stride_to_capec.json`. This ensures the mapping is based on established methodologies and is easily updatable.
-   **`MitreMapping` Class**:
    -   **Initialization**: When instantiated, it loads multiple external data sources:
        -   `stride_to_capec.json`: For the initial STRIDE to CAPEC link.
        -   `d3fend.csv`: For mapping ATT&CK techniques to D3FEND countermeasures.
        -   `CAPEC_VIEW_ATT&CK_Related_Patterns.csv`: For mapping CAPEC patterns to ATT&CK techniques.
    -   **`map_threat_to_capec()`**: This function is the first step in the enrichment chain. It takes a threat's description and STRIDE category. It filters the patterns from `stride_to_capec.json` to only those relevant to the STRIDE category and then uses regular expressions (built from keywords in the CAPEC descriptions) to find matches in the threat description.
    -   **`map_threat_to_mitre()`**: This function takes a threat description and uses a large dictionary of regex patterns (`_initialize_threat_patterns`) to directly map keywords in the description to specific MITRE ATT&CK Technique IDs (e.g., "sql injection" maps to T1190).
    -   **Enrichment Pipeline**: The full analysis connects these pieces: A generated threat (e.g., "SQL injection on WebServer") is first mapped to ATT&CK Technique T1190. The framework then uses its data to find that T1190 is a CAPEC-19 attack pattern. This provides a multi-layered view, from the general STRIDE category (Tampering) to the specific technique (T1190) and the attack pattern (CAPEC-19).

### 4.6. Severity Calculation (`severity_calculator_module.py`)

The `SeverityCalculator` provides a nuanced risk score for each threat.
-   **Multi-Factor Calculation**: The final score is not a static value but a composite calculated from:
    1.  **Base Score**: A default score for each STRIDE category.
    2.  **Rule-Defined Score**: The impact and likelihood values (1-5) defined in the `threat_rules.py` entry for that threat.
    3.  **Target Multipliers**: The score can be increased by multipliers defined in the `## Severity Multipliers` section of the threat model, which are loaded from the markdown file.
    4.  **Protocol Adjustments**: The protocol of a dataflow can adjust the score (e.g., HTTP increases it, HTTPS decreases it).
    5.  **Data Classification**: The classification of the data in a flow (`PUBLIC`, `SECRET`, etc.) acts as a final multiplier.
-   **Normalization**: The final score is clamped between 1.0 and 10.0 and assigned a qualitative level (e.g., "HIGH", "CRITICAL").

### 4.7. Output Generation (`generation/`)

-   **`diagram_generator.py`**: This module is responsible for all visual representations.
    -   It uses a Jinja2 template (`threat_model.dot.j2`) to generate Graphviz DOT language code from the `ThreatModel` object.
    -   **Visual Styling**: The generator includes logic for rich visual styling:
        -   It automatically assigns shapes based on keywords in element names (e.g., `cylinder` for "database", `hexagon` for "firewall").
        -   It adds icons (e.g., 👤 for actors, 🖥️ for servers, 🔥 for firewalls) to node labels for better readability.
    -   It calls the `dot` command-line tool to render the DOT code into SVG, PNG, or other formats.
    -   **Navigable Diagrams**: For hierarchical projects, it makes diagrams navigable by post-processing the SVG. The `add_links_to_svg` function uses Python's `xml.etree.ElementTree` to find SVG nodes corresponding to elements with a `submodel` property and wraps them in an `<a>` hyperlink tag pointing to the sub-model's diagram.
-   **`report_generator.py`**: Creates the primary user-facing artifacts.
    -   It uses Jinja2 templates (`report_template.html`, `navigable_diagram_template.html`) for generating rich HTML outputs.
    -   **Hierarchical Project Generation**: The `generate_project_reports` method orchestrates the analysis of complex, multi-part systems.
        -   It starts from a root `main.md` file and recursively discovers all `model.md` files referenced in `submodel:` properties of servers.
        -   Before generation, it aggregates all protocol definitions and styles from every model in the project to create a single, consistent legend for all diagrams.
        -   It generates a full set of reports (threat analysis, JSON, navigable diagram) for each model.
        -   It constructs a breadcrumb navigation trail for each diagram, allowing users to easily navigate up and down the model hierarchy.
-   **`stix_generator.py`**: This module provides interoperability.
    -   It translates the framework's findings into STIX 2.1, a standardized language for cyber threat intelligence.
    -   It leverages the `attack-flow` STIX extension to create a structured representation of the attack chains, creating `attack-action` and `attack-asset` objects and linking them with relationships.

### 4.8. Web Interface (`server/`)

-   **`server.py`**: A simple Flask application that defines the API endpoints:
    -   `/`: Serves the main `web_interface.html`.
    -   `/api/update`: Receives Markdown from the editor, triggers a live analysis, and returns the resulting SVG diagram and legend.
    -   `/api/export` & `/api/export_all`: Handle requests to download the generated artifacts.
-   **`threat_model_service.py`**: This service layer acts as a bridge between the web server and the core analysis engine. It encapsulates the logic for handling web requests, calling the appropriate framework components, and managing temporary files, keeping the Flask app clean and focused on routing.

### 4.9. Mitigation Suggestions (`mitigation_suggestions.py`)

This module provides actionable mitigation advice for the threats identified during the analysis. It bridges the gap between threat identification and remediation.

-   **`MITIGATION_MAP`**: The core of this module is a dictionary that maps MITRE ATT&CK technique IDs to a curated list of mitigation suggestions.
-   **Framework Integration**: The suggestions are sourced from well-known security frameworks, including:
    -   OWASP Application Security Verification Standard (ASVS)
    -   NIST Special Publication 800-53
    -   CIS Controls
-   **`get_mitigation_suggestions()`**: This function takes a list of ATT&CK technique IDs and returns all corresponding mitigation suggestions from the map, which are then embedded in the final HTML report.

### 4.10. Centralized Configuration (`config.py`)

To improve maintainability and ease of modification, the framework uses a central `config.py` file. This module contains static configuration values that are used throughout the application.

Key configurations include:
-   **Default Paths**: `DEFAULT_MODEL_FILEPATH` and `BASE_PROTOCOL_STYLES_FILEPATH`.
-   **Output Management**: `TIMESTAMP` for unique output directories, `OUTPUT_BASE_DIR`, and `TMP_DIR`.
-   **Filename Templates**: Templates for all output files (HTML reports, JSON, diagrams) to ensure consistent naming conventions (e.g., `HTML_REPORT_FILENAME_TPL`).

### 4.11. IaC Plugin Architecture (`iac_plugins/`)

The framework is designed to be extensible through a dedicated Infrastructure as Code (IaC) plugin system, allowing it to generate threat models from various IaC sources.

-   **Abstract Base Class**: The `iac_plugins/__init__.py` file defines an abstract base class called `IaCPlugin`. To create a new plugin, a developer must create a class that inherits from `IaCPlugin`.
-   **Required Implementations**: Any new plugin must implement three key methods:
    1.  `name`: Returns the name of the plugin (e.g., "ansible").
    2.  `parse_iac_config()`: Contains the logic to parse the IaC source files (e.g., playbooks, Terraform state).
    3.  `generate_threat_model_components()`: Contains the logic to convert the parsed data into the Markdown DSL format used by the framework.
-   **Dynamic Loading**: The main entrypoint (`__main__.py`) automatically discovers and loads any valid plugin placed in the `iac_plugins` directory. It also dynamically creates command-line arguments based on the plugin's name (e.g., `--ansible-path`).
