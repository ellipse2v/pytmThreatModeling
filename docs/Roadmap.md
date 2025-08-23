# Roadmap / TODO / Technical Debt

-   Add more realistic threats to the `custom_threats.py` module.
-   Improve threat generation to specifically account for special boundaries like DMZ and Gateway, and the components within them.
-   Enhance MITRE ATT&CK mapping in `mitre_mapping_module.py` to include more techniques per threat where applicable.
-   **Automated and Enriched Mitigation Suggestions**: Propose mitigations based on recognized frameworks (OWASP ASVS, NIST, CIS Controls) for each identified MITRE ATT&CK technique.
-   **Integration with Vulnerability Databases (CVE)**: Link identified MITRE ATT&CK techniques to known CVEs or common vulnerabilities (e.g., OWASP Top 10).
    -   **Step 1: Research CVE Data Sources**: Identify reliable CVE sources (e.g., NVD API) and understand their data formats.
    -   **Step 2: MITRE ATT&CK to CVE Mapping**: Research existing mappings or develop logic to infer potential CVEs from threat descriptions/MITRE techniques.
-   **Advanced Threat Model Validation**: Implement stricter checks for `threatModel_Template/threat_model.md` (syntax, consistency, undefined elements) with clear error messages.
    -   **Step 1: Define Validation Rules**: List comprehensive validation rules for `threatModel_Template/threat_model.md` (e.g., valid element references, unique names, required attributes).
    -   **Step 2: Implement Validation Module**: Create a new module (e.g., `threat_analysis/model_validator.py`) with validation functions.
    -   **Step 3: Integrate into Analysis Flow**: Call validation functions at the beginning of `ThreatModel.process_threats`. Stop analysis and return detailed errors if validation fails.
    -   **Step 4: Clear Error Reporting**: Ensure error messages are explicit, indicating file, line (if possible), and nature of the problem.
-   **Containerization (Optional)**: Use Docker for easy deployment and execution.
-   **EBIOS Risk Management Integration & Reporting**:
    -   **Step 1: Color-Coded Mitigations in HTML Report**: Enhance the final HTML report to visually represent the status of security mitigations.
        -   **Extend Markdown Syntax**: Introduce a `## Mitigations` section where each measure has an ID, description, and a `status` (e.g., `implemented`, `planned`, `not_implemented`).
        -   **Update Report Generator**: Modify `ReportGenerator` to parse the new section and pass mitigation data to the HTML template.
        -   **Update HTML Template**: Edit `report_template.html` to apply CSS classes based on mitigation status (e.g., green for `implemented`, orange for `planned`, red for `not_implemented`), making the report easier to interpret.
    -   **Step 2: Visual Feedback on Diagrams**: Update the `DiagramGenerator` to reflect the status of mitigations. For example, use color-coding (e.g., green border for `implemented`, orange for `planned`) or icons on diagram elements.
    -   **Step 3: Automated Verification of Controls (Advanced)**: Create a verification engine that checks the `implemented` status.
        -   **IaC Analysis**: Enhance the Ansible plugin (and add others like Terraform) to parse IaC files and confirm that security controls are correctly configured.
        -   **API Integration**: Develop a framework to connect to external security tools (vulnerability scanners, CSPM) to fetch real-time compliance data.
-   **Hierarchical & Interactive Threat Models (Drill-Down/Zoom Feature)**:
    -   **Goal**: Allow the decomposition of a large system into multiple, linked sub-models for better navigation and management of complexity.
    -   **Step 1: Extend Markdown for Model Linking**: Introduce a new attribute (e.g., `model_file`) for elements like `Server` or `Boundary`. This attribute will link an abstract element in a high-level diagram to a separate, detailed threat model file.
        -   *Example*: `- **Microservices Cluster**: boundary=Internal, model_file=./microservices_model.md`
    -   **Step 2: Multi-Model Processing Engine**: Update the core engine to manage a project of threat models instead of a single file. It will need to parse the main model and recursively follow the `model_file` links to process all related models.
    -   **Step 3: Interactive SVG Generation**: Modify the `DiagramGenerator` to create navigable diagrams.
        -   Elements with a `model_file` attribute will be rendered with an embedded hyperlink in the generated SVG.
        -   This link will point to the HTML page of the corresponding sub-model's diagram.
    -   **Step 4: Navigation UI**: Ensure the generated HTML pages for sub-models include clear navigation controls, such as a "Back to Parent" link or a breadcrumb trail, to allow users to easily move up and down the model hierarchy.
-   **Attack Path Enumeration and Simulation**:
       * Improvement: Implement algorithms to automatically identify and visualize potential attack paths through the
         threat model (e.g., from an external actor to a critical database).
       * Benefit: This helps prioritize defenses by understanding the most likely routes an attacker would take and
         allows for "what-if" scenario analysis (e.g., "What if this control fails?")