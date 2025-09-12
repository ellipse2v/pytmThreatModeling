## Servers
- **PrimaryDB**: type="database"
- **ReplicaDB**: type="database"

## Dataflows
- **Replication**: from=PrimaryDB, to=ReplicaDB, protocol="DB Sync"

## Protocol Styles
- **DB Sync**: color=purple, line_style=solid
