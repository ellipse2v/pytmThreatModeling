## Boundaries
- **External**: color=red
- **Internal**: color=green

## Actors
- **User**: boundary=External

## Servers
- **WebService**: boundary=Internal
- **APIService**: boundary=Internal, submodel=./sub_project_A/model.md

## Dataflows
- **UserToWebService**: from=User, to=WebService, protocol=HTTPS
- **WebServiceToAPIService**: from=WebService, to=APIService, protocol=HTTP
