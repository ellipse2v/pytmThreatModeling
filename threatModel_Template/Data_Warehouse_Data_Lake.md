# Threat Model: Data Warehouse / Data Lake

## Description
This threat model focuses on a Data Warehouse or Data Lake architecture, which involves ingesting, storing, processing, and analyzing large volumes of data. It addresses security concerns related to data privacy, integrity, access control, and compliance across various stages of the data lifecycle, from raw data ingestion to analytical insights.

## Boundaries
- **Data Sources**: color=lightblue, isTrusted=False
- **Ingestion Layer**: color=orange, isTrusted=True
- **Storage Layer (Raw/Curated)**: color=purple, isTrusted=True
- **Processing Layer**: color=green, isTrusted=True
- **Consumption Layer**: color=gray, isTrusted=False

## Actors
- **Data Provider**: boundary="Data Sources"
- **Data Engineer**: boundary="Ingestion Layer"
- **Data Analyst**: boundary="Consumption Layer"
- **Business User**: boundary="Consumption Layer"

## Servers
- **ETL/ELT Tools**: boundary="Ingestion Layer"
- **Object Storage (S3/ADLS)**: boundary="Storage Layer (Raw/Curated)"
- **Data Lakehouse (Delta Lake/Iceberg)**: boundary="Storage Layer (Raw/Curated)"
- **Spark/Hadoop Cluster**: boundary="Processing Layer"
- **Data Warehouse (Snowflake/BigQuery)**: boundary="Processing Layer"
- **BI Tools/Dashboards**: boundary="Consumption Layer"

## Dataflows
- **Data Ingestion**: from="Data Provider", to="ETL/ELT Tools", protocol="Various (API, SFTP, Streaming)"
- **Load to Raw Storage**: from="ETL/ELT Tools", to="Object Storage (S3/ADLS)", protocol="Internal API"
- **Data Transformation**: from="Object Storage (S3/ADLS)", to="Spark/Hadoop Cluster", protocol="Internal API"
- **Load to Curated Storage**: from="Spark/Hadoop Cluster", to="Data Lakehouse (Delta Lake/Iceberg)", protocol="Internal API"
- **Query Data**: from="BI Tools/Dashboards", to="Data Warehouse (Snowflake/BigQuery)", protocol="JDBC/ODBC", color=purple
- **Access Raw Data**: from="Data Analyst", to="Object Storage (S3/ADLS)", protocol="API"
- **Access Curated Data**: from="Business User", to="Data Lakehouse (Delta Lake/Iceberg)", protocol="API"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **Various (API, SFTP, Streaming)**: color=grey, line_style=dotted
- **Internal API**: color=grey, line_style=dotted
- **JDBC/ODBC**: color=purple
- **API**: color=black, line_style=dotted

## Severity Multipliers
# Example:
# - **Storage Layer (Raw/Curated)**: 1.9 (contains all sensitive data)
# - **ETL/ELT Tools**: 1.6 (vulnerable to data injection/manipulation)

## Custom Mitre Mapping
# Example:
# - **Data Exfiltration from Lake**: tactics=["Exfiltration"], techniques=[{"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}]
# - **Data Tampering in Pipeline**: tactics=["Impact"], techniques=[{"id": "T1561", "name": "Disk Wipe"}]