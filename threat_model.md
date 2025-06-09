# Threat Model: Advanced DMZ Architecture

## Description
This model describes a network architecture with a Demilitarized Zone (DMZ), external and internal dataflows, and a potentially untrusted command zone. The goal is to identify STRIDE threats and map them to MITRE ATT&CK techniques.

## Boundaries
- **Internet**: color=lightcoral
- **DMZ**: color=khaki
- **Intranet**: color=lightgreen
- **Command_Zone**: color=lightsteelblue

## Actors
- **External Client 1**: boundary=Internet
- **External Client 2**: boundary=Internet
- **External Client 3**: boundary=Internet
- **External Client 4**: boundary=Internet
- **External Client 5**: boundary=Internet
- **External Client 6**: boundary=Internet
- **External Client 7**: boundary=Internet
- **External Client 8**: boundary=Internet
- **Internal Operator 1**: boundary=Intranet
- **Internal Operator 2**: boundary=Intranet
- **System Administrator**: boundary=Intranet

## Servers
- **External Firewall**: boundary=DMZ
- **Protocol Break Device**: boundary=DMZ
- **Internal Firewall**: boundary=DMZ
- **Switch**: boundary=Intranet
- **Central Server**: boundary=Intranet
- **Application Database**: boundary=Intranet
- **Authentication Server**: boundary=Intranet
- **Command Machine**: boundary=Command_Zone

## Data
- **Web Traffic**: description="Standard web requests/responses", format="HTTP/HTTPS", classification="PUBLIC"
- **API Request**: description="Application API calls", format="JSON/REST", classification="RESTRICTED"
- **File Transfer**: description="File upload/download", format="FTP/SFTP", classification="SECRET"
- **DNS Query**: description="Domain Name System queries", format="UDP/TCP", classification="PUBLIC"
- **Mail Traffic**: description="Email messages", format="SMTP/IMAP/POP3", classification="SECRET"
- **Video Stream**: description="Live video data", format="RTSP/RTMP", classification="PUBLIC"
- **Game Data**: description="Online game session data", format="UDP", classification="PUBLIC"
- **IoT Data**: description="Sensor data from IoT devices", format="MQTT", classification="PUBLIC"
- **Server Request**: description="Request to central server", format="Proprietary", classification="SECRET"
- **Database Query**: description="SQL database query", format="SQL", classification="SECRET"
- **SSH Traffic**: description="Secure Shell remote access", format="SSH", classification="TOP_SECRET", credentialsLife="SHORT"
- **Authentication Request**: description="LDAP/LDAPS authentication request", format="LDAPS", classification="SECRET"
- **General Traffic**: description="General internal network traffic", format="Various", classification="PUBLIC"

## Dataflows
- **Client 1 to External Firewall**: from="External Client 1", to="External Firewall", protocol="HTTPS", data="Web Traffic", is_encrypted=True
- **Client 2 to External Firewall**: from="External Client 2", to="External Firewall", protocol="HTTP", data="Web Traffic"
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
- **System Administrator to Central Server**: from="System Administrator", to="Central Server", protocol="SSH", data="SSH Traffic", is_authenticated=True, is_encrypted=True
- **System Administrator to Authentication Server**: from="System Administrator", to="Authentication Server", protocol="LDAPS", data="Authentication Request", is_authenticated=True, is_encrypted=True
- **Central Server to Authentication Server**: from="Central Server", to="Authentication Server", protocol="LDAPS", data="Authentication Request", is_authenticated=True, is_encrypted=True


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