# Threat Model: Microservices Architecture

## Description
This threat model explores a microservices-based architecture, where an application is decomposed into small, independent, and loosely coupled services. It addresses security challenges related to inter-service communication, API management, service discovery, resilience, and data consistency in a distributed environment.

## Boundaries
- **Client (Browser/Mobile)**: color=lightblue, isTrusted=False
- **API Gateway**: color=orange, isTrusted=False
- **Microservice A**: color=green, isTrusted=True
- **Microservice B**: color=purple, isTrusted=True
- **Shared/Dedicated Database**: color=gray, isTrusted=True

## Actors
- **End User**: boundary="Client (Browser/Mobile)"
- **Developer/Operator**: color=blue
- **Attacker**: color=red

## Servers
- **Load Balancer**: color=lightgray
- **API Gateway (Kong/Envoy)**: boundary="API Gateway"
- **Service A (e.g., User Service)**: boundary="Microservice A"
- **Service B (e.g., Product Service)**: boundary="Microservice B"
- **Service Discovery (Consul/Eureka)**: color=yellow
- **Message Broker (Kafka/RabbitMQ)**: color=cyan
- **Database (SQL/NoSQL)**: boundary="Shared/Dedicated Database"

## Dataflows
- **Client Request**: from="End User", to="Load Balancer", protocol="HTTPS", color=darkgreen
- **API Request**: from="Load Balancer", to="API Gateway", protocol="HTTPS", color=darkgreen
- **Inter-Service Request (Synchronous)**: from="API Gateway", to="Service A (e.g., User Service)", protocol="HTTP/gRPC", color=red
- **Inter-Service Request (Asynchronous)**: from="Service A (e.g., User Service)", to="Message Broker (Kafka/RabbitMQ)", protocol="AMQP/Kafka"
- **Message Consumption**: from="Message Broker (Kafka/RabbitMQ)", to="Service B (e.g., Product Service)", protocol="AMQP/Kafka"
- **Database Access**: from="Service A (e.g., User Service)", to="Database (SQL/NoSQL)", protocol="JDBC/ODBC/API", color=purple
- **Service Registration**: from="Service A (e.g., User Service)", to="Service Discovery (Consul/Eureka)", protocol="HTTP", color=red
- **Service Discovery**: from="Service B (e.g., Product Service)", to="Service Discovery (Consul/Eureka)", protocol="HTTP", color=red
- **API Gateway Attack**: from="Attacker", to="API Gateway (Kong/Envoy)", protocol="HTTPS", color=red
- **Service Compromise**: from="Attacker", to="Service A (e.g., User Service)", protocol="HTTP/gRPC", color=red

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **HTTP/gRPC**: color=red
- **AMQP/Kafka**: color=cyan
- **JDBC/ODBC/API**: color=purple

## Severity Multipliers
# Example:
# - **API Gateway**: 1.8 (single point of entry, critical for routing and security enforcement)
# - **Message Broker (Kafka/RabbitMQ)**: 1.6 (sensitive data in transit, potential for message tampering)

## Custom Mitre Mapping
# Example:
# - **Service Mesh Evasion**: tactics=["Defense Evasion"], techniques=[{"id": "T1562", "name": "Impair Defenses"}]
# - **Insecure Inter-Service Communication**: tactics=["Lateral Movement"], techniques=[{"id": "T1570", "name": "Web Service"}]