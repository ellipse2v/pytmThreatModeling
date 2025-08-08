## Boundaries
- **Internal**: color=blue

## Servers
- **AuthenticationService**: boundary=Internal
- **Database**: boundary=Internal

## Dataflows
- **AuthToDB**: from=AuthenticationService, to=Database, protocol=TCP
