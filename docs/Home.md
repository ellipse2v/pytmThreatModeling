# Home: Elevating Cyber Resilience with Automated Threat Modeling

Welcome to the official GitHub Wiki for the **STRIDE Threat Analysis Framework with MITRE ATT&CK Integration**.

In an era of escalating cyber threats and rapid development cycles, traditional security practices often fall short. This framework is engineered to bridge that gap, transforming reactive security into proactive cyber resilience. It's more than a tool; it's a paradigm shift towards **Threat Modeling as Code (TMasC)**, empowering development, security, and operations teams to embed security from inception.

## Documentation Sections

- [Roadmap](roadmap) - Project roadmap and future plans
- [Technical Documentation](Technical_documentation) - Technical details and specifications


## Table of Contents

1.  [The Cyber Imperative: Why Automated Threat Modeling?](#the-cyber-imperative-why-automated-threat-modeling)
2.  [Core Capabilities: Unveiling the Power of STRIDE & MITRE ATT&CK](#core-capabilities-unveiling-the-power-of-stride--mitre-attck)
3.  [Getting Started: Fortifying Your Defenses](#getting-started-fortifying-your-defenses)
4.  [Operationalizing Security: CLI, GUI, and IaC Integration](#operationalizing-security-cli-gui-and-iac-integration)
    *   [The TMasC Philosophy in Action](#the-tmasc-philosophy-in-action)
    *   [Command Line Interface (CLI): Orchestrating Automated Analysis](#command-line-interface-cli-orchestrating-automated-analysis)
    *   [Infrastructure as Code (IaC) Integration: Bridging Dev & SecOps](#infrastructure-as-code-iac-integration-bridging-dev--secops)
    *   [Web-based Graphical User Interface (GUI): Visualizing the Attack Surface](#web-based-graphical-user-interface-gui-visualizing-the-attack-surface)
5.  [Architecting for Resilience: The Threat Model DSL](#architecting-for-resilience-the-threat-model-dsl)
6.  [Extending Your Cyber Arsenal: Customization & Evolution](#extending-your-cyber-arsenal-customization--evolution)
7.  [The Path Forward: Roadmap & Strategic Vision](#the-path-forward-roadmap--strategic-vision)
8.  [Contributing to Cyber Defense](#contributing-to-cyber-defense)
9.  [License & Attribution](#license--attribution)

---

## The Cyber Imperative: Why Automated Threat Modeling?

In today's dynamic threat landscape, security cannot be an afterthought. Manual threat modeling is often slow, inconsistent, and struggles to keep pace with agile development. This framework champions **Continuous Threat Modeling** and **Threat Modeling as Code (TMasC)**, enabling:

-   **Proactive Risk Identification**: Shift left on security by identifying design flaws and vulnerabilities early in the SDLC.
-   **Scalable Security**: Automate threat analysis across complex, distributed systems and microservices.
-   **Actionable Intelligence**: Translate abstract threats into concrete, MITRE ATT&CK-mapped techniques for targeted defense.
-   **DevSecOps Enablement**: Foster seamless collaboration between development, security, and operations teams through version-controlled, machine-readable threat models.
-   **Continuous Assurance**: Integrate threat analysis into CI/CD pipelines for ongoing security validation.

## Core Capabilities: Unveiling the Power of STRIDE & MITRE ATT&CK

This framework is built upon robust security principles and industry-leading intelligence:

-   **STRIDE-based Threat Identification**: Automatically uncovers threats across Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege categories for every component and dataflow.
-   **MITRE ATT&CK Mapping**: Each identified threat is meticulously mapped to relevant MITRE ATT&CK tactics and techniques, providing real-world context and actionable defensive strategies.
-   **Dynamic Severity Calculation**: Customizable scoring mechanisms (base scores, target multipliers, protocol adjustments) provide a precise risk posture for each threat.
-   **Comprehensive Reporting & Visualization**: Generate rich HTML and JSON reports for detailed analysis, alongside intuitive DOT, SVG, and interactive HTML diagrams that visually highlight threat landscapes.
-   **Extensible Security Logic**: All threat detection rules, MITRE mappings, and severity calculations are modular, allowing for easy customization and adaptation to unique organizational contexts.

## Getting Started: Fortifying Your Defenses

Embark on your journey to enhanced cyber resilience:

1.  **Acquire the Arsenal:**
    ```bash
    git clone <repository_url>
    cd <repository_name>
    ```

2.  **Provision Dependencies:**
    ```bash
    pip install pytm Flask
    ```

3.  **Integrate Visual Intelligence (Graphviz):**
    Diagram generation relies on Graphviz. Install it via your preferred method:
    *   Windows: [https://graphviz.org/download/](https://graphviz.org/download/)
    *   macOS: `brew install graphviz`
    *   Linux: `sudo apt-get install graphviz`
    (Restart your terminal/IDE after installation.)

## Operationalizing Security: CLI, GUI, and IaC Integration

This framework offers versatile operational modes to fit your security workflow.

### The TMasC Philosophy in Action

At its heart, this tool embodies Threat Modeling as Code. Your threat models are defined in human-readable, version-controllable Markdown. This enables:

-   **Version Control**: Track every evolution of your threat landscape.
-   **Automation**: Integrate security analysis directly into your CI/CD pipelines.
-   **Collaboration**: Empower cross-functional teams with a shared, transparent view of risks.

### Command Line Interface (CLI): Orchestrating Automated Analysis

For automated workflows, CI/CD integration, and batch processing:

1.  **Define Your Digital Blueprint:** Create your system architecture in a Markdown file (e.g., `my_application_model.md`). Leverage the templates in `threatModel_Template/` for architectural patterns (e.g., `threatModel_Template/Architecture_Microservices.md`).
2.  **Initiate Threat Analysis:**
    ```bash
    python -m threat_analysis --model-file my_application_model.md
    ```
    (If `--model-file` is omitted, the tool defaults to `threatModel_Template/threat_model.md`.)
3.  **Harvest Intelligence:** Review the generated artifacts in the timestamped `output/` directory (e.g., `output/2025-07-19_HH-MM-SS/`):
    *   **Comprehensive HTML Report**: (`stride_mitre_report_*.html`) - Detailed threat insights, MITRE mappings, and severity.
    *   **Machine-Readable JSON Export**: (`mitre_analysis_*.json`) - For integration with other security tools.
    *   **Visual Attack Surface Diagrams**: (`tm_diagram_*.dot`, `tm_diagram_*.svg`, `tm_diagram_*.html`) - Intuitive visualizations of your system and its threats.

### Infrastructure as Code (IaC) Integration: Bridging Dev & SecOps

Unleash the power of automated threat modeling directly from your infrastructure definitions. This framework can generate a complete threat model from your IaC configurations, automatically incorporating default protocol styles from `threatModel_Template/base_protocol_styles.md` to ensure consistent visualization.

**Ansible Integration Example:**

1.  **Prepare Your IaC Manifest:** Utilize the sample Ansible playbook at `tests/ansible_playbooks/simple_web_server.yml` or point to your own.
2.  **Generate & Analyze:**
    ```bash
    python -m threat_analysis --ansible-path tests/ansible_playbooks/simple_web_server.yml
    ```
    This command dynamically generates a comprehensive threat model based on your Ansible playbook. The generated Markdown model will be saved in the timestamped `output/` directory (e.g., `output/2025-07-19_HH-MM-SS/simple_web_server.md`).

    To specify a custom output filename for the generated model:
    ```bash
    python -m threat_analysis --ansible-path tests/ansible_playbooks/simple_web_server.yml --model-file my_ansible_threat_model.md
    ```
    The `my_ansible_threat_model.md` file will be saved inside the timestamped output directory.

#### Defining Threat Model Metadata in Ansible Playbooks

To provide comprehensive threat model information that goes beyond what can be inferred from basic Ansible tasks and inventory, you can embed a `threat_model_metadata` variable directly within your Ansible playbook's `vars` block. This approach allows you to define abstract concepts like zones, their types, and trust levels, which are crucial for a complete threat model.

This metadata is read by the `ansible_plugin` but is **ignored by Ansible itself**, ensuring that your deployment processes remain unaffected.

**Example of `threat_model_metadata` in an Ansible Playbook:**

```yaml
# my_ansible_playbook.yml
---
- name: Deploy My Application
  hosts: my_servers
  become: yes
  vars:
    threat_model_metadata:
      name: "My Application Threat Model"
      description: "Threat model for the deployed application infrastructure."
      zones:
        - name: "RIE"
          type: "External"
          trust_level: "Untrusted"
        - name: "infra_boundary"
          type: "DMZ"
          trust_level: "Trusted"
          sub_zones:
            - name: "main"
              type: "Internal"
              trust_level: "Trusted"
            - name: "fallback"
              type: "Internal"
              trust_level: "Trusted"
      # You can also define other elements here if needed, e.g.,
      # actors:
      #   - name: "Admin"
      #     isHuman: true
      #     zone: "infra_boundary"
      # components:
      #   - name: "External_LoadBalancer"
      #     type: "LoadBalancer"
      #     zone: "RIE"
  tasks:
    - name: Configure web server
      ansible.builtin.apt:
        name: nginx
        state: present
    # ... other Ansible tasks ...
```

**Structure of `threat_model_metadata`:**

*   **`name`** (string, optional): The overall name of the threat model.
*   **`description`** (string, optional): A brief description of the threat model.
*   **`zones`** (list of dictionaries, optional): Defines the security zones within your architecture.
    *   **`name`** (string, required): The name of the zone (e.g., "RIE", "infra_boundary", "main").
    *   **`type`** (string, optional): The type of zone (e.g., "External", "DMZ", "Internal").
    *   **`trust_level`** (string, optional): Indicates the trust level ("Trusted" or "Untrusted").
    *   **`sub_zones`** (list of dictionaries, optional): Nested zones, following the same structure as `zones`.

By leveraging `threat_model_metadata`, you can explicitly define your system's security architecture, including trust boundaries and their properties, directly within your IaC, providing a rich context for automated threat analysis.

**Structure of `threat_model_metadata` (continued):**

*   **`actors`** (list of dictionaries, optional): Defines human or system entities interacting with your system.
    *   **`name`** (string, required): The name of the actor (e.g., "Admin", "Operator").
    *   **`isHuman`** (boolean, optional): `true` if the actor is a human, `false` otherwise.
    *   **`boundary`** (string, optional): The name of the boundary the actor resides in.

*   **`components`** (list of dictionaries, optional): Defines the various software or hardware components in your system.
    *   **`name`** (string, required): The name of the component (e.g., "WebServer", "Database").
    *   **`stereotype`** (string, optional): The type of component (e.g., "Server", "LoadBalancer", "Switch", "Router").
    *   **`boundary`** (string, optional): The name of the boundary the component resides in.
    *   **`services`** (list of strings, optional): A list of services running on the component (e.g., "web", "app", "db", "ssh").

*   **`data`** (list of dictionaries, optional): Defines types of data flowing through your system.
    *   **`name`** (string, required): The name of the data type (e.g., "Web Traffic", "SSH Traffic", "Internal Traffic").
    *   **`classification`** (string, optional): The sensitivity of the data ("PUBLIC", "RESTRICTED", "SECRET", "TOP_SECRET", "UNKNOWN").
    *   **`lifetime`** (string, optional): The lifecycle of the data ("TRANSIENT", "LONG", "SHORT", "AUTO", "MANUAL", "HARDCODED", "NONE", "UNKNOWN").

*   **`data_flows`** (list of dictionaries, optional): Defines communication paths between actors, components, and zones.
    *   **`name`** (string, required): A descriptive name for the data flow.
    *   **`source`** (string, required): The source of the data flow. Can be prefixed with `actor:`, `component:`, or `zone:` (e.g., "actor:Operator", "component:WebServer", "zone:Internet").
    *   **`destination`** (string, required): The destination of the data flow. Can be prefixed with `actor:`, `component:`, or `zone:` (e.g., "component:Database", "zone:DMZ").
    *   **`protocol`** (string, required): The protocol used for the data flow (e.g., "HTTPS", "SSH", "Any").
    *   **`data`** (string, required): The name of the data type being transmitted (must be defined in the `data` section).
    *   **`description`** (string, optional): A detailed description of the data flow.
    *   **`is_authenticated`** (boolean, optional): `true` if the data flow is authenticated, `false` otherwise.
    *   **`is_encrypted`** (boolean, optional): `true` if the data flow is encrypted, `false` otherwise.

3.  **Review the Automated Insights:** Explore the generated reports and diagrams in the `output/` folder, now enriched with intelligence derived directly from your IaC.

### Web-based Graphical User Interface (GUI): Visualizing the Attack Surface

For interactive exploration, real-time editing, and immediate feedback:

1.  **Launch the Cyber Cockpit:**
    ```bash
    python -m threat_analysis --gui
    ```
    The console will display the address (e.g., `http://127.0.0.1:5001`) where you can access the GUI in your web browser.

> **Note:** When using `--gui`, the `--model-file` option can be used to load an initial threat model as a template into the editor. If not provided, the GUI will start with an empty editor.

## Architecting for Resilience: The Threat Model DSL

The framework leverages a intuitive Markdown-based DSL to define your system's architecture. This human-readable format facilitates collaboration and version control. Explore example models in the `threatModel_Template/` directory.

**Key DSL Elements:**

-   **Boundaries**: Define trust zones and network segmentation.
-   **Actors**: Represent users, systems, and external entities interacting with your system.
-   **Servers**: Model applications, databases, firewalls, and other infrastructure components.
-   **Data**: Classify data based on sensitivity and lifecycle.
-   **Dataflows**: Map communication paths between elements, including protocols and encryption.
-   **Protocol Styles**: Customize visualization of dataflows for clarity.
-   **Severity Multipliers**: Fine-tune risk scoring for critical assets.
-   **Custom MITRE Mapping**: Extend and tailor MITRE ATT&CK mappings to your specific threat intelligence.

## Extensibility & Customization

This framework is designed for adaptability, allowing you to tailor its capabilities to your unique security requirements:

-   **Modular Threat Detection**: Define new STRIDE categories or custom threat patterns.
-   **Flexible MITRE Mappings**: Extend and override existing MITRE ATT&CK mappings.
-   **Customizable Severity Logic**: Adjust risk scoring algorithms to align with your organizational risk appetite.
-   **PyTM Integration**: Leverage the full power of PyTM's extensible features for advanced modeling and analysis.

## The Path Forward: Roadmap & Strategic Vision

Our commitment to continuous improvement drives the evolution of this framework. Key areas of future development include:

-   **Automated and Enriched Mitigation Suggestions**: Propose context-aware mitigations based on recognized frameworks (OWASP ASVS, NIST, CIS Controls) for each identified MITRE ATT&CK technique.
-   **Advanced Threat Model Validation**: Implement stricter, more intelligent validation checks for the Markdown DSL, providing precise error feedback.
-   **Integration with Vulnerability Databases (CVE)**: Link identified MITRE ATT&CK techniques to known CVEs and common vulnerabilities, enhancing threat intelligence.
-   **Expanded IaC Integrations**: Extend automated threat model generation to other IaC tools (e.g., Terraform, CloudFormation).
-   **Pre-defined Architecture Templates**: Offer a growing library of pre-built threat models for common architectural patterns, accelerating initial setup.

## Contributing to Cyber Defense

We welcome contributions from the cybersecurity and development communities. Your insights and expertise are invaluable in strengthening this framework. Please refer to the [Developer Guide](#developer-guide) for contribution guidelines and testing procedures.

## License & Attribution

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

---

**Author:** ellipse2v