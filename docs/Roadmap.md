# Project Roadmap

This document outlines the development roadmap for the ThreatModelByPyTM framework, tracking both completed features and future ambitions.

---

## ✅ Implemented Features

This section highlights the core capabilities that are already integrated into the framework.

-   **Hierarchical & Interactive Threat Models**: Decompose a large system into multiple, linked sub-models with navigable HTML diagrams.
-   **Advanced Threat Model Validation**: A dedicated validation module (`model_validator.py`) checks for consistency, unique names, and valid references within the model before analysis.
-   **Automated and Enriched Mitigation Suggestions**: The framework proposes context-aware mitigations based on recognized frameworks (OWASP ASVS, NIST, CIS Controls) for each identified MITRE ATT&CK technique.
-   **Ansible IaC Integration**: Automatically generate a threat model directly from Ansible playbooks and inventories, using embedded metadata for a rich, accurate representation.
-   **Pre-defined Architecture Templates**: A library of pre-built threat models for common architectural patterns is available in the `threatModel_Template/` directory to accelerate initial setup.
-   **Web-Based GUI**: An interactive web interface for real-time editing of threat models with a live-updating diagram preview.
-   **MITRE ATT&CK Navigator Export**: Generate JSON layer files for visualization and analysis in the MITRE ATT&CK Navigator.
-   **STIX 2.1 Reporting**: Export threat intelligence data in the standardized STIX 2.1 format for interoperability with other security tools.

---

## 🚀 Future Enhancements

This section outlines the strategic vision and planned features for future releases.

-   **Integration with Vulnerability Databases (CVE)**: Link identified MITRE ATT&CK techniques to known CVEs or common vulnerabilities (e.g., OWASP Top 10) to provide even deeper context.
-   **Attack Path Enumeration and Simulation**: Implement algorithms to automatically identify and visualize potential attack paths through the threat model.
-   **Integration with Security Orchestration, Automation, and Response (SOAR) Platforms**: Develop connectors to push threat intelligence and mitigation recommendations directly into SOAR platforms.
-   **Machine Learning-Enhanced Threat Identification**: Train a machine learning model to predict potential threats that may not be covered by existing rules.
-   **Expanded IaC Tool Support (Terraform, CloudFormation)**: Create new plugins for other popular IaC tools.
-   **Enhanced User Interface (UI) and User Experience (UX)**: Redesign the web GUI to be more intuitive, with features like drag-and-drop model creation and a visual rule editor.
-   **Compliance Mapping (NIST, PCI-DSS, etc.)**: Map identified threats and suggested mitigations to specific controls in major compliance frameworks.
-   **Threat Intelligence Feed Integration**: Integrate with external threat intelligence feeds (e.g., from MISP, Anomali) to automatically update the threat model with the latest real-world attack techniques.
-   **Collaborative Real-Time Editing**: Enhance the web GUI to support real-time, multi-user collaborative editing of threat models.
-   **Risk Quantification and Financial Impact Analysis**: Integrate with risk quantification models (e.g., FAIR) to estimate the potential financial impact of identified threats.
