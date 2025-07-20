# Threat Model: CI/CD Pipeline (Continuous Integration and Deployment)

## Description
This threat model focuses on a CI/CD pipeline, covering the development, integration, testing, and deployment stages. It identifies potential vulnerabilities from source code to production deployment, including code repositories, build servers, artifact registries, and deployment environments.

## Boundaries
- **Development Environment**: color=lightblue, isTrusted=True
- **Code Repository**: color=gray, isTrusted=True
- **Build Server**: color=orange, isTrusted=True
- **Artifact Registry**: color=purple, isTrusted=True
- **Production Environment**: color=green, isTrusted=False

## Actors
- **Developer**: boundary="Development Environment"
- **CI/CD System**: boundary="Build Server"
- **Attacker**: color=red

## Servers
- **Git Repository**: boundary="Code Repository"
- **Jenkins/GitLab CI/GitHub Actions**: boundary="Build Server"
- **Docker Registry/Artifactory**: boundary="Artifact Registry"
- **Kubernetes Cluster/Cloud VM**: boundary="Production Environment"

## Dataflows
- **Push Code**: from="Developer", to="Git Repository", protocol="HTTPS/SSH", color=darkgreen
- **Webhook Trigger**: from="Git Repository", to="Jenkins/GitLab CI/GitHub Actions", protocol="HTTPS", color=darkgreen
- **Fetch Code**: from="Jenkins/GitLab CI/GitHub Actions", to="Git Repository", protocol="HTTPS/SSH", color=darkgreen
- **Build Application**: from="Jenkins/GitLab CI/GitHub Actions", to="Docker Registry/Artifactory", protocol="HTTPS", color=darkgreen
- **Pull Artifact**: from="Kubernetes Cluster/Cloud VM", to="Docker Registry/Artifactory", protocol="HTTPS", color=darkgreen
- **Deploy Application**: from="Jenkins/GitLab CI/GitHub Actions", to="Kubernetes Cluster/Cloud VM", protocol="API/SSH", color=blue
- **Illegitimate Access**: from="Attacker", to="Git Repository", protocol="HTTPS/SSH", color=red
- **Malicious Injection**: from="Attacker", to="Jenkins/GitLab CI/GitHub Actions", protocol="API"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **HTTPS/SSH**: color=darkgreen
- **API/SSH**: color=blue
- **API**: color=black, line_style=dotted

## Severity Multipliers
# Example:
# - **Build Server**: 1.8 (compromise can lead to supply chain attacks)
# - **Git Repository**: 1.5 (sensitive code exposure)

## Custom Mitre Mapping
# Example:
# - **Compromise Build System**: tactics=["Execution", "Persistence"], techniques=[{"id": "T1543", "name": "Create or Modify System Process"}]
# - **Supply Chain Compromise**: tactics=["Impact"], techniques=[{"id": "T1195", "name": "Supply Chain Compromise"}]