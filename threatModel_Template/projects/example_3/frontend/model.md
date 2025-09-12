## Servers
- **WebServer**: type="web_server"
- **LoadBalancer**: type="load_balancer"

## Dataflows
- **LBtoWeb**: from=LoadBalancer, to=WebServer, protocol=HTTP

## Protocol Styles
- **HTTP**: color=red, line_style=solid
