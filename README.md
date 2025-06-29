# STRIDE Threat Analysis Framework with MITRE ATT&CK Integration

## Overview

This project is a Python-based, end-to-end STRIDE threat modeling and analysis framework with MITRE ATT&CK mapping. It enables you to:

- **Model your system architecture** in Markdown (`threat_model.md`), including boundaries, actors, servers, data, and dataflows.
- **Automatically identify STRIDE threats** for each component and dataflow.
- **Map threats to MITRE ATT&CK techniques** for actionable, real-world context.
- **Calculate severity** using customizable base scores, target multipliers, and protocol adjustments.
- **Generate detailed reports** (HTML, JSON) and **visual diagrams** (DOT, SVG, HTML) with threat highlights.
- **Extend and customize** all mappings, calculations, and reporting logic.

> **Based on [PyTM](https://github.com/OWASP/pytm):** This framework leverages PyTM's modeling primitives and extends them with advanced reporting, MITRE mapping, and diagram generation.

---

## Features

- **Markdown-based Threat Modeling**: Use a simple DSL to describe your architecture and flows.
- **Automated STRIDE Analysis**: Detects threats for each element and flow.
- **MITRE ATT&CK Mapping**: Each threat is mapped to relevant MITRE tactics and techniques.
- **Severity Calculation**: Customizable scoring (base, target, protocol).
- **Comprehensive Reporting**:
  - HTML report with threat details, STRIDE/MITRE mapping, and statistics.
  - JSON export for integration or further analysis.
- **Visual Diagrams**:
  - DOT, SVG, and HTML diagrams with threat highlights.
- **Extensible**: All mappings and calculations are modular and easy to override.
- **PyTM Compatibility**: Supports PyTM's model structure and can be extended with PyTM's features.

---

## Example Output

After running the analysis, you will find a timestamped folder in `output/` (e.g., `output/2025-06-08_15-45-24`) containing:

- `stride_mitre_report_2025-06-08_15-45-24.html`:  
  ![HTML Report Screenshot](output/example/stride_mitre_report__example.png.jpg)
- `mitre_analysis_2025-06-08_15-45-24.json`:  
  ```json
  {
    "analysis_date": "2025-06-29T15:31:56.517773",
    "threats_detected": 183,
    "threat_types": [
      "Threat",
      "Tampering",
      "Information Disclosure",
      "Elevation of Privilege",
      "Spoofing",
      "Denial of Service",
      "Repudiation"
    ],
    "mitre_mapping": {
      "Spoofing": {
        "tactics": [
          "Initial Access",
          "Defense Evasion",
          "Credential Access"
        ],
        "techniques": [
          {
            "id": "T1566",
            "name": "Phishing",
            "description": "Identity spoofing via phishing"
          }
        ]
      },
      "Tampering": {
        "tactics": [
          "Defense Evasion",
          "Impact",
          "Initial Access",
          "Execution"
        ],
        "techniques": [
          {
            "id": "T1565",
            "name": "Data Manipulation",
            "description": "Unauthorized data modification"
          }
        ]
      }
    },
    "detailed_threats": [
      {
        "type": "Threat",
        "description": "Vulnerability in the management interface of External Firewall",
        "target": "External Firewall",
        "severity": {"score": 8.5, "level": "HIGH"},
        "mitre_techniques": [{"id": "T1068", "name": "Exploitation for Privilege Escalation"}],
        "stride_category": "Elevation of Privilege"
      },
      {
        "type": "Threat",
        "description": "Lateral movement from Central Server to other systems in the network",
        "target": "Central Server",
        "severity": {"score": 8.5, "level": "HIGH"},
        "mitre_techniques": [{"id": "T1021", "name": "Remote Services"}],
        "stride_category": "Elevation of Privilege"
      },
      {
        "type": "Threat",
        "description": "Insecure security configuration or hardening on App Server 1",
        "target": "App Server 1",
        "severity": {"score": 6.0, "level": "MEDIUM"},
        "mitre_techniques": [{"id": "T1562", "name": "Impair Defenses"}],
        "stride_category": "Information Disclosure"
      },
      {
        "type": "Threat",
        "description": "Data exfiltration or leakage from Application Database",
        "target": "Application Database",
        "severity": {"score": 8.5, "level": "HIGH"},
        "mitre_techniques": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"}],
        "stride_category": "Information Disclosure"
      }
    ]
  }
  ```
- `tm_diagram__example.dot`:  
  (Graphviz DOT format for architecture)
- `tm_diagram__example.svg`:  
  ![SVG Diagram Example](./output/example/tm_diagram__example.svg)
- `tm_diagram_example.html`:  
  (Interactive HTML diagram with legend and threat highlights)
  ![report  Example](output/example/stride_mitre_report__example.png.jpg)

> **Note:** All screenshots and example files are located in the `output/example/` directory for easy preview and documentation.

---


## Example Threat Model (`threat_model.md`)

```markdown
# Threat Model: Advanced DMZ Architecture

## Description
A network with a DMZ, external/internal firewalls, and a command zone. The goal is to identify STRIDE threats and map them to MITRE ATT&CK.

## Boundaries
- **Internet**: color=lightcoral
- **DMZ**: color=khaki
- **Intranet**: color=lightgreen
- **Command Zone**: color=lightsteelblue

## Actors
- **External Client 1**: boundary=Internet
- **Operator**: boundary=Command Zone

## Servers
- **External Firewall**: boundary=DMZ
- **Internal Firewall**: boundary=Intranet
- **Central Server**: boundary=Intranet

## Data
- **Web Traffic**: classification=public, lifetime=transient

## Dataflows
- **External Client to External Firewall**: from="External Client 1", to="External Firewall", protocol="HTTPS", data="Web Traffic", is_encrypted=True

## Severity Multipliers
- **Central Server**: 1.5
- **External Firewall**: 2.0

## Custom Mitre Mapping
- **Protocol Tampering**: tactics=["Impact", "Defense Evasion"], techniques=[{"id": "T1565", "name": "Data Manipulation"}]
```

## Bidirectional Dataflow Visualization

This makes bidirectional communications visually clear and reduces clutter in your architecture diagrams.

**Example:**

If your model contains:
```markdown
## Dataflows
- A to B: from="A", to="B", protocol="HTTPS"
- B to A: from="B", to="A", protocol="HTTPS"
```

The diagram will show:
```
A <--> B
```
(with a single arrow using `dir="both"` in DOT/Graphviz)

This feature is enabled by default and works for all protocols.

---

---

## Installation

1. **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd <repository_name>
    ```

2. **Install Python dependencies:**
    ```bash
    pip install pytm
    ```

3. **Install Graphviz (for diagram generation):**
    - Windows: [https://graphviz.org/download/](https://graphviz.org/download/)
    - macOS: `brew install graphviz`
    - Linux: `sudo apt-get install graphviz`

After installation, restart your terminal or IDE.

---

## Usage

1. **Edit `threat_model.md`** to describe your architecture.
2. **Run the analysis:**
    ```bash
    python main_analysis.py
    ```
3. **View the results** in the generated `output/` folder:
    - HTML report
    - JSON export
    - DOT/SVG/HTML diagrams

---

## Model Capabilities

- **STRIDE Threat Detection**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.
- **MITRE ATT&CK Mapping**: Each STRIDE threat is mapped to one or more MITRE ATT&CK techniques and tactics.
- **Severity Calculation**: 
  - Base scores per STRIDE category.
  - Target multipliers (e.g., critical servers).
  - Protocol-based adjustments (e.g., HTTP vs HTTPS).
- **Diagram Generation**:
  - DOT, SVG, and HTML diagrams with threat highlights and legends.
- **Report Generation**:
  - HTML report with summary, statistics, threat details, and recommendations.
  - JSON export for integration or further analysis.
- **Extensibility**:
  - Add new STRIDE categories or custom threat patterns.
  - Extend MITRE mappings.
  - Customize severity logic.
  - Integrate with PyTM models and features.

---

## PyTM-Based Extensions & Evolutions

You can leverage and extend all PyTM features, including:

- **Custom Threat Patterns**: Define new threat types and detection logic.
- **Advanced Dataflow Modeling**: Use PyTM's dataflow and element types.
- **Integration with PyTM Plugins**: Use or develop plugins for reporting, risk scoring, or compliance.
- **Automated Testing**: Integrate with PyTM's test harness for CI/CD.
- **Custom Reports**: Extend the reporting module to output in any format (PDF, Excel, etc.).
- **Visualization**: Use PyTM's or your own visualization tools for advanced diagrams.

---

## Limitations

- **Severity Multipliers** and **Custom MITRE Mapping** defined in `threat_model.md` are not yet parsed automatically (see logs for "ignored" messages). Programmatic customization is supported.
- The default architecture is DMZ-oriented; adapt the model for your environment as needed.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

## Author

ellipse2v