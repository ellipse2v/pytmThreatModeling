# Threat Model: Cloud-Native (Serverless) Architecture

## Description
This threat model focuses on a cloud-native architecture using serverless services. It examines the interactions between FaaS (Function as a Service) functions, NoSQL databases, API gateways, and object storage services, highlighting security challenges specific to this paradigm, such as Identity and Access Management (IAM), service configuration, and function code security.

## Boundaries
- **Client (Browser/Mobile)**: color=lightblue, isTrusted=False
- **API Gateway**: color=orange, isTrusted=False
- **FaaS Function (Lambda/Cloud Functions)**: color=green, isTrusted=True
- **NoSQL Database (DynamoDB/Firestore)**: color=purple, isTrusted=True
- **Object Storage (S3/Cloud Storage)**: color=gray, isTrusted=True

## Actors
- **End User**: boundary="Client (Browser/Mobile)"
- **Developer/Cloud Operator**: color=blue
- **Attacker**: color=red

## Servers
- **CloudFront/CDN**: color=lightgray
- **API Gateway (AWS API Gateway/Google Cloud Endpoints)**: boundary="API Gateway"
- **Lambda Function/Cloud Function**: boundary="FaaS Function (Lambda/Cloud Functions)"
- **DynamoDB/Firestore**: boundary="NoSQL Database (DynamoDB/Firestore)"
- **S3 Bucket/Cloud Storage**: boundary="Object Storage (S3/Cloud Storage)"

## Dataflows
- **Client Request**: from="End User", to="CloudFront/CDN", protocol="HTTPS", color=darkgreen
- **API Request**: from="CloudFront/CDN", to="API Gateway (AWS API Gateway/Google Cloud Endpoints)", protocol="HTTPS", color=darkgreen
- **Function Invocation**: from="API Gateway (AWS API Gateway/Google Cloud Endpoints)", to="Lambda Function/Cloud Function", protocol="Internal API"
- **Database Access**: from="Lambda Function/Cloud Function", to="DynamoDB/Firestore", protocol="Internal API"
- **Object Storage Access**: from="Lambda Function/Cloud Function", to="S3 Bucket/Cloud Storage", protocol="Internal API"
- **Function Response**: from="Lambda Function/Cloud Function", to="API Gateway (AWS API Gateway/Google Cloud Endpoints)", protocol="Internal API"
- **API Response**: from="API Gateway (AWS API Gateway/Google Cloud Endpoints)", to="CloudFront/CDN", protocol="HTTPS", color=darkgreen
- **Client Response**: from="CloudFront/CDN", to="End User", protocol="HTTPS", color=darkgreen
- **Function Code Injection**: from="Attacker", to="Lambda Function/Cloud Function", protocol="API"
- **Misconfigured IAM**: from="Attacker", to="DynamoDB/Firestore", protocol="API"
- **Developer to API Gateway**: from="Developer/Cloud Operator", to="API Gateway (AWS API Gateway/Google Cloud Endpoints)", protocol="API"
- **Developer to FaaS Function**: from="Developer/Cloud Operator", to="Lambda Function/Cloud Function", protocol="API"
- **Developer to NoSQL Database**: from="Developer/Cloud Operator", to="DynamoDB/Firestore", protocol="Management"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **Internal API**: color=grey, line_style=dotted
- **API**: color=black, line_style=dotted
- **Management**: color=darkblue, line_style=solid

## Severity Multipliers
# Example:
# - **API Gateway**: 1.7 (single entry point, critical for access control)
# - **FaaS Function (Lambda/Cloud Functions)**: 1.5 (vulnerable to code injection, excessive permissions)

## Custom Mitre Mapping
# Example:
# - **Improper Function Permissions**: tactics=["Privilege Escalation"], techniques=[{"id": "T1078", "name": "Valid Accounts"}]
# - **Data Exfiltration via Cloud Storage**: tactics=["Exfiltration"], techniques=[{"id": "T1537", "name": "Transfer Data to Cloud Account"}]