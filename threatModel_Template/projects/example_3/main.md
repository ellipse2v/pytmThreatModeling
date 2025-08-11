## Boundaries
- **Untrusted Zone**: isTrusted=False
- **DMZ**: isTrusted=True, line_style=dashed
- **Trusted Zone**: isTrusted=True

## Actors
- **User**: boundary="Untrusted Zone"

## Servers
- **WebApp**: submodel=./frontend/model.md, boundary="Untrusted Zone"
- **DMZ**: submodel=./dmz/model.md, boundary="DMZ", description="Demilitarized Zone"
- **BackendServices**: submodel=./backend/model.md, boundary="Trusted Zone"

## Data
- **User Request**: description="Initial request from user's browser", classification="PUBLIC"
- **API Call**: description="Internal API call from the gateway to a backend service", classification="RESTRICTED"
- **Encapsulated API Call**: description="User's request encapsulated for transit through the DMZ", classification="RESTRICTED"

## Dataflows
- **UserToWebApp**: from=User, to=WebApp, protocol=HTTPS, data="User Request"
- **WebAppToDMZ**: from=WebApp, to=DMZ, protocol=HTTPS, data="Encapsulated API Call"
- **DMZToBackend**: from=DMZ, to=BackendServices, protocol=HTTP, data="API Call"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
