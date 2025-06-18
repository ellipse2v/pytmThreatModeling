# Threat Model: Advanced DMZ Architecture

## Description
This model describes a network architecture with a Demilitarized Zone (DMZ), external and internal dataflows, and a potentially untrusted command zone. The goal is to identify STRIDE threats and map them to MITRE ATT&CK techniques.

## Boundaries
- **Internet**: color=#F0F0F0, isTrusted=False, isFilled=True
- **DMZ**: color=khaki, isTrusted=True, isFilled=True, line_style=dashed
- **Intranet**: color=lightgreen, isTrusted=True, , isFilled=False
- **Command_Zone**: color=#F0F0F0, isFilled=True

## Actors
- **External Client 1**: boundary=Internet, color=#ADD8E6, isFilled=False
- **External Client 2**: boundary=Internet, color=#ADD8E6
- **External Client 3**: boundary=Internet, color=#ADD8E6
- **External Client 4**: boundary=Internet, color=#ADD8E6
- **External Client 5**: boundary=Internet, color=#ADD8E6
- **External Client 6**: boundary=Internet, color=#ADD8E6
- **External Client 7**: boundary=Internet, color=#ADD8E6
- **External Client 8**: boundary=Internet, color=#ADD8E6
- **Internal Operator 1**: boundary=Intranet, color=forestgreen
- **Internal Operator 2**: boundary=Intranet, color=forestgreen
- **System Administrator**: boundary=Intranet, color=forestgreen

## Servers
- **External Firewall**: boundary=DMZ, color=#D3D3D3
- **Protocol Break Device**: boundary=DMZ
- **Internal Firewall**: boundary=DMZ, color=#D3D3D3
- **Switch**: boundary=Intranet, color=#E6E6FA
- **Central Server**: boundary=Intranet, color=#98FB98
- **Application Database**: boundary=Intranet,color=#FFDAB9
- **Authentication Server**: boundary=Intranet
- **Command Machine**: boundary=Command_Zone

## Data
- **Web Traffic**: description="Standard web requests/responses", classification="PUBLIC"
- **API Request**: description="Application API calls", format="JSON/REST", classification="RESTRICTED"
- **File Transfer**: description="File upload/download", classification="SECRET"
- **DNS Query**: description="Domain Name System queries", classification="PUBLIC"
- **Mail Traffic**: description="Email messages", classification="SECRET"
- **Video Stream**: description="Live video data", classification="PUBLIC"
- **Game Data**: description="Online game session data", format="UDP", classification="PUBLIC"
- **IoT Data**: description="Sensor data from IoT devices", classification="PUBLIC"
- **Server Request**: description="Request to central server", format="Proprietary", classification="SECRET"
- **Database Query**: description="SQL database query", format="SQL", classification="SECRET"
- **SSH Traffic**: description="Secure Shell remote access", classification="TOP_SECRET", credentialsLife="SHORT"
- **Authentication Request**: description="LDAP/LDAPS authentication request", classification="SECRET"
- **General Traffic**: description="General internal network traffic", format="Various", classification="PUBLIC"

## Dataflows
- **test1**: from="External Client 1", to="External Firewall", protocol="HTTPS", data="Web Traffic", is_encrypted=True, bidirectional=True
- **test**: from="External Client 2", to="External Firewall", protocol="HTTP", data="Web Traffic"
- **Client 3 to External Firewall**: from="External Client 3", to="External Firewall", protocol="FTP", data="File Transfer"
- **Client 4 to External Firewall**: from="External Client 4", to="External Firewall", protocol="SFTP", data="File Transfer", is_encrypted=True
- **Client 5 to External Firewall**: from="External Client 5", to="External Firewall", protocol="DNS", data="DNS Query"
- **Client 6 to External Firewall**: from="External Client 6", to="External Firewall", protocol="SMTP", data="Mail Traffic"
- **Client 7 to External Firewall**: from="External Client 7", to="External Firewall", protocol="RTSP", data="Video Stream"
- **Client 8 to External Firewall**: from="External Client 8", to="External Firewall", protocol="MQTT", data="IoT Data"

- **External Firewall to Protocol Break Device**: from="External Firewall", to="Protocol Break Device", protocol="HTTPS", data="Web Traffic", is_encrypted=True
- **Protocol Break Device to Internal Firewall**: from="Protocol Break Device", to="Internal Firewall", protocol="HTTPS", data="Web Traffic", is_encrypted=True

- **Internal Firewall to Switch**: from="Internal Firewall", to="Switch", protocol="Ethernet", data="General Traffic" # CHANGED
- **Command Machine to Switch**: from="Command Machine", to="Switch", protocol="Ethernet", data="General Traffic" # CHANGED

- **Internal Operator 1 to Switch**: from="Internal Operator 1", to="Switch", protocol="Ethernet", data="General Traffic"
- **Internal Operator 2 to Switch**: from="Internal Operator 2", to="Switch", protocol="Ethernet", data="General Traffic"
- **System Administrator to Switch**: from="System Administrator", to="Switch", protocol="Ethernet", data="General Traffic"

- **Switch to Central Server**: from="Switch", to="Central Server", protocol="HTTPS", data="Server Request", is_authenticated=True, is_encrypted=True
- **Central Server to Switch**: from="Central Server", to="Switch", protocol="HTTPS", data="Server Request", is_authenticated=True, is_encrypted=True
- **System Administrator to Central Server**: from="System Administrator", to="Central Server", protocol="SSH", data="SSH Traffic", is_authenticated=True, is_encrypted=True
- **System Administrator to Authentication Server**: from="System Administrator", to="Authentication Server", protocol="LDAPS", data="Authentication Request", is_authenticated=True, is_encrypted=True
- **Central Server to Authentication Server**: from="Central Server", to="Authentication Server", protocol="LDAPS", data="Authentication Request", is_authenticated=True, is_encrypted=True

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed

## Severity Multipliers
- **Central Server**: 1.5
- **External Firewall**: 2.0
- **Protocol Break Device**: 1.8
- **Switch**: 1.5
- **Command Machine**: 2.5

## Custom Mitre Mapping
- **Protocol Tampering**: tactics=["Impact", "Defense Evasion"], techniques=[{"id": "T1565", "name": "Data Manipulation"}, {"id": "T1499", "name": "Endpoint Denial of Service"}]
- **Unauthorized Access**: tactics=["Initial Access", "Persistence"], techniques=[{"id": "T1133", "name": "External Remote Services"}, {"id": "T1078", "name": "Valid Accounts"}]
- **Weak Authentication**: tactics=["Credential Access"], techniques=[{"id": "T1110", "name": "Brute Force"}, {"id": "T1552", "name": "Unsecured Credentials"}]
- **Data Exfiltration**: tactics=["Exfiltration"], techniques=[{"id": "T1041", "name": "Exfiltration Over C2 Channel"}, {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}]
- **Denial of Service Attack**: tactics=["Impact"], techniques=[{"id": "T1499", "name": "Endpoint Denial of Service"}, {"id": "T1498", "name": "Network Denial of Service"}]
- **Privilege Escalation**: tactics=["Privilege Escalation"], techniques=[{"id": "T1068", "name": "Exploitation for Privilege Escalation"}]