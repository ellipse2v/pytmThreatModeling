## Servers
- **WebServer**:
- **LoadBalancer**:

## Dataflows
- **EntryToLB**: from=WebServer, to=LoadBalancer, protocol=HTTPS
- **LBtoWeb**: from=LoadBalancer, to=WebServer, protocol=HTTP
