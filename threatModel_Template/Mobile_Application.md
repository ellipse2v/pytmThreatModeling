# Threat Model: Mobile Application (iOS/Android)

## Description
This threat model focuses on a native mobile application (iOS or Android), covering interactions between the application on the user's device, backend APIs, and third-party services. It addresses vulnerabilities specific to mobile applications, such as sensitive data storage on the device, insecure communication, reverse engineering, and threats related to the mobile execution environment.

## Boundaries
- **Mobile Device (Client)**: color=lightblue, isTrusted=False
- **Backend API**: color=orange, isTrusted=True
- **Third-Party Services (Authentication, Payment)**: color=purple, isTrusted=False

## Actors
- **Mobile User**: boundary="Mobile Device (Client)"
- **Attacker**: color=red

## Servers
- **Mobile Application**: boundary="Mobile Device (Client)"
- **API Gateway/Load Balancer**: boundary="Backend API"
- **Backend Application Server**: boundary="Backend API"
- **Backend Database**: boundary="Backend API"
- **Identity Provider (OAuth/SSO)**: boundary="Third-Party Services (Authentication, Payment)"
- **Payment Gateway**: boundary="Third-Party Services (Authentication, Payment)"

## Dataflows
- **API Request (Authentication)**: from="Mobile Application", to="Identity Provider (OAuth/SSO)", protocol="HTTPS", color=darkgreen
- **Authentication Token**: from="Identity Provider (OAuth/SSO)", to="Mobile Application", protocol="HTTPS", color=darkgreen
- **API Request (Data)**: from="Mobile Application", to="API Gateway/Load Balancer", protocol="HTTPS", color=darkgreen
- **Backend Request**: from="API Gateway/Load Balancer", to="Backend Application Server", protocol="HTTPS", color=darkgreen
- **Database Request**: from="Backend Application Server", to="Backend Database", protocol="JDBC/ODBC", color=purple
- **Database Response**: from="Backend Database", to="Backend Application Server", protocol="JDBC/ODBC", color=purple
- **Backend Response**: from="Backend Application Server", to="API Gateway/Load Balancer", protocol="HTTPS", color=darkgreen
- **API Response**: from="API Gateway/Load Balancer", to="Mobile Application", protocol="HTTPS", color=darkgreen
- **Payment Request**: from="Mobile Application", to="Payment Gateway", protocol="HTTPS", color=darkgreen
- **Reverse Engineering**: from="Attacker", to="Mobile Application", protocol="Offline"
- **Communication Interception**: from="Attacker", to="API Gateway/Load Balancer", protocol="Network"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **JDBC/ODBC**: color=purple
- **Offline**: color=grey, line_style=dotted
- **Network**: color=black, line_style=dotted

## Severity Multipliers
# Example:
# - **Mobile Application**: 1.8 (due to local data storage and user interaction)
# - **Backend Database**: 1.9 (contains all sensitive user data)

## Custom Mitre Mapping
# Example:
# - **Insecure Data Storage**: tactics=["Impact"], techniques=[{"id": "T1552", "name": "Unsecured Credentials"}]
# - **Reverse Engineering**: tactics=["Discovery"], techniques=[{"id": "T1003", "name": "OS Credential Dumping"}]