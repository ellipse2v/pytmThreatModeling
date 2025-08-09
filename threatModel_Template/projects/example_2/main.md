## Actors
- **User**:

## Servers
- **WebApp**: submodel=./frontend/model.md
- **BackendServices**: submodel=./backend/model.md

## Data
- **User Request**:
- **API Call**:

## Dataflows
- **UserToWebApp**: from=User, to=WebApp, protocol=HTTPS, data="User Request"
- **WebAppToBackend**: from=WebApp, to=BackendServices, protocol=HTTP, data="API Call"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
