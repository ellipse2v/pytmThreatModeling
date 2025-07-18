# Threat Model: Zero Trust Architecture

## Description
This threat model outlines a Zero Trust architecture, emphasizing the principle of "never trust, always verify." It details how every access request is authenticated, authorized, and encrypted, regardless of its origin. Key components include identity providers, policy enforcement points, and micro-segmentation.

## Boundaries
- **Untrusted Network**: color=red, isTrusted=False
- **Trusted Network**: color=green, isTrusted=True
- **Identity Provider (IdP)**: color=blue, isTrusted=True
- **Policy Enforcement Point (PEP)**: color=orange, isTrusted=True
- **Workload**: color=lightblue, isTrusted=True

## Actors
- **User**: boundary="Untrusted Network"
- **Administrator**: boundary="Trusted Network"

## Servers
- **Authentication Service**: boundary="Identity Provider (IdP)"
- **Authorization Service**: boundary="Identity Provider (IdP)"
- **Policy Engine**: boundary="Policy Enforcement Point (PEP)"
- **Microservice A**: boundary="Workload"
- **Microservice B**: boundary="Workload"

## Dataflows
- **User Authentication Request**: from="User", to="Authentication Service", protocol="HTTPS", color=darkgreen
- **Authentication Response**: from="Authentication Service", to="User", protocol="HTTPS", color=darkgreen
- **Access Request**: from="User", to="PEP", protocol="HTTPS", color=darkgreen
- **Policy Evaluation**: from="PEP", to="Policy Engine", protocol="Internal API"
- **Authorization Decision**: from="Policy Engine", to="PEP", protocol="Internal API"
- **Authorized Access**: from="PEP", to="Microservice A", protocol="Encrypted TLS"
- **Inter-service Communication**: from="Microservice A", to="Microservice B", protocol="Encrypted TLS"
- **Admin Management**: from="Administrator", to="Policy Engine", protocol="HTTPS", color=darkgreen

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **Internal API**: color=grey, line_style=dotted
- **Encrypted TLS**: color=darkgreen, line_style=solid

## Severity Multipliers
# Example:
# - **Policy Engine**: 1.8 (critical component for all access decisions)
# - **Identity Provider (IdP)**: 1.7 (compromise leads to widespread unauthorized access)

## Custom Mitre Mapping
# Example:
# - **Bypass Policy Enforcement**: tactics=["Defense Evasion"], techniques=[{"id": "T1562", "name": "Impair Defenses"}]
# - **Compromise Identity Provider**: tactics=["Credential Access"], techniques=[{"id": "T1556", "name": "Forge Web Credentials"}]