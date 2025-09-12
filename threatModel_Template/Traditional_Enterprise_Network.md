# Threat Model: Traditional Enterprise Network (with Active Directory)

## Description
This threat model describes a traditional enterprise network architecture, centered on the use of Active Directory for identity and access management. It covers key components such as domain controllers, file servers, workstations, and network devices, focusing on common attack vectors in a domain-based environment.

## Boundaries
- **Internal Network**: color=lightgreen, isTrusted=True
- **DMZ (Demilitarized Zone)**: color=orange, isTrusted=False
- **Internet**: color=red, isTrusted=False

## Actors
- **Employee**: boundary="Internal Network"
- **System Administrator**: boundary="Internal Network"
- **External Attacker**: boundary="Internet"

## Servers
- **Domain Controller (Active Directory)**: boundary="Internal Network", type="domain_controller"
- **File Server**: boundary="Internal Network", type="file_server"
- **Application Server**: boundary="Internal Network", type="app_server"
- **Web Server (DMZ)**: boundary="DMZ", type="web_server"
- **Firewall**: color=gray, type="firewall"

## Dataflows
- **User Authentication**: from="Employee", to="Domain Controller (Active Directory)", protocol="Kerberos/LDAP", color=teal
- **File Access**: from="Employee", to="File Server", protocol="SMB"
- **Internal Application Access**: from="Employee", to="Application Server", protocol="HTTPS", color=darkgreen
- **External Web Request**: from="External Attacker", to="Firewall", protocol="HTTPS", color=red
- **Internal Web Request (DMZ)**: from="Firewall", to="Web Server (DMZ)", protocol="HTTPS", color=darkgreen
- **AD Synchronization**: from="Domain Controller (Active Directory)", to="Domain Controller (Active Directory)", protocol="RPC/LDAP", color=teal
- **Administrator Management**: from="System Administrator", to="Domain Controller (Active Directory)", protocol="RPC/SMB"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **Kerberos/LDAP**: color=teal
- **SMB**: color=orange
- **RPC/LDAP**: color=teal

## Severity Multipliers
# Example:
# - **Domain Controller (Active Directory)**: 2.0 (compromise leads to full domain control)
# - **File Server**: 1.5 (sensitive data exposure)

## Custom Mitre Mapping
# Example:
# - **Pass-the-Hash**: tactics=["Credential Access"], techniques=[{"id": "T1550", "name": "Use Alternate Authentication Material"}]
# - **Golden Ticket**: tactics=["Persistence", "Privilege Escalation"], techniques=[{"id": "T1208", "name": "Kerberoasting"}]