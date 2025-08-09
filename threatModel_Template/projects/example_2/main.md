## Actors
- **User**:

## Servers
- **WebApp**: submodel=./frontend/model.md
- **BackendServices**: submodel=./backend/model.md

## Dataflows
- **UserToWebApp**: from=User, to=WebApp, protocol=HTTPS, data="User Request"
- **WebAppToBackend**: from=WebApp, to=BackendServices, protocol=HTTP, data="API Call"
