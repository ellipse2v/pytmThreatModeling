## Boundaries
- **Infrastructure_Zone**: color=lightblue, is_trusted=True
- **Main_SubZone**: parent=Infrastructure_Zone, color=lightcyan, is_trusted=True
- **Fallback_SubZone**: parent=Infrastructure_Zone, color=lightyellow, is_trusted=True

## Servers
- **Server_Main_01**: boundary=Main_SubZone, stereotype=WebServer
- **Server_Main_02**: boundary=Main_SubZone, stereotype=AppServer
- **Server_Main_03**: boundary=Main_SubZone, stereotype=DatabaseServer
- **Server_Fallback_01**: boundary=Fallback_SubZone, stereotype=WebServer
- **Server_Fallback_02**: boundary=Fallback_SubZone, stereotype=AppServer
- **Server_Fallback_03**: boundary=Fallback_SubZone, stereotype=DatabaseServer

## Data
- **UserData**: classification=restricted, description=User personal information
- **ApplicationData**: classification=restricted, description=Data processed by the application
- **DatabaseData**: classification=secret, description=Sensitive database records

## Dataflows
- **User_to_Main_Web**: from="External_Client", to="Server_Main_01", protocol="HTTPS", data="UserData"
- **Main_Web_to_Main_App**: from="Server_Main_01", to="Server_Main_02", protocol="HTTPS", data="ApplicationData"
- **Main_App_to_Main_DB**: from="Server_Main_02", to="Server_Main_03", protocol="SQL", data="DatabaseData"
- **User_to_Fallback_Web**: from="External_Client", to="Server_Fallback_01", protocol="HTTPS", data="UserData"
- **Fallback_Web_to_Fallback_App**: from="Server_Fallback_01", to="Server_Fallback_02", protocol="HTTPS", data="ApplicationData"
- **Fallback_App_to_Fallback_DB**: from="Server_Fallback_02", to="Server_Fallback_03", protocol="SQL", data="DatabaseData"
