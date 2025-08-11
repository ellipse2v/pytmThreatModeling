## Boundaries
- **Protected DB Zone**: isTrusted=True

## Servers
- **PrimaryDB**: boundary="Protected DB Zone"
- **ReplicaDB**: boundary="Protected DB Zone"

## Dataflows
- **Replication**: from=PrimaryDB, to=ReplicaDB, protocol="DB Sync"

## Protocol Styles
- **DB Sync**: color=purple, line_style=solid
