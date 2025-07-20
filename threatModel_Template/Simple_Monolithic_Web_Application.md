# Threat Model: Simple Monolithic Web Application

## Description
This threat model describes a simple monolithic web application, where all functionalities (user interface, business logic, data access) are grouped into a single codebase and deployed as a single unit. It examines typical vulnerabilities of this architecture, such as single points of failure, difficulty in isolating compromised components, and complexity in managing dependencies.

## Boundaries
- **Client (Web Browser)**: color=lightblue, isTrusted=False
- **Monolithic Web Server**: color=orange, isTrusted=False
- **Database**: color=purple, isTrusted=True

## Actors
- **End User**: boundary="Client (Web Browser)"
- **Administrator**: color=blue
- **Attacker**: color=red

## Servers
- **Load Balancer (Optional)**: color=lightgray
- **Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)**: boundary="Monolithic Web Server"
- **Database Server (MySQL, PostgreSQL, MongoDB)**: boundary="Database"

## Dataflows
- **HTTP/S Request**: from="End User", to="Load Balancer (Optional)", protocol="HTTPS", color=darkgreen
- **Web Request**: from="Load Balancer (Optional)", to="Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)", protocol="HTTP/S", color=darkgreen
- **Database Request**: from="Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)", to="Database Server (MySQL, PostgreSQL, MongoDB)", protocol="JDBC/ODBC/API", color=purple
- **Database Response**: from="Database Server (MySQL, PostgreSQL, MongoDB)", to="Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)", protocol="JDBC/ODBC/API", color=purple
- **Web Response**: from="Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)", to="Load Balancer (Optional)", protocol="HTTP/S", color=darkgreen
- **HTTP/S Response**: from="Load Balancer (Optional)", to="End User", protocol="HTTPS", color=darkgreen
- **Code Injection**: from="Attacker", to="Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)", protocol="HTTP/S", color=red
- **Direct Database Access**: from="Attacker", to="Database Server (MySQL, PostgreSQL, MongoDB)", protocol="SQL/NoSQL", color=purple

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **JDBC/ODBC/API**: color=purple
- **SQL/NoSQL**: color=purple

## Severity Multipliers
# Example:
# - **Monolithic Application**: 1.8 (single point of failure, broad impact on compromise)
# - **Database**: 1.9 (contains all application data)

## Custom Mitre Mapping
# Example:
# - **Path Traversal**: tactics=["Impact"], techniques=[{"id": "T1083", "name": "File and Directory Discovery"}]
# - **Insecure Direct Object Reference (IDOR)**: tactics=["Impact"], techniques=[{"id": "T1530", "name": "Data from Local System"}]