## Description
- An API Gateway is an API management tool that sits between a client and a collection of backend services. It acts as a reverse proxy to accept all application programming interface (API) calls, aggregate the various services required to fulfill them, and return the appropriate result.

## Servers
- **LoadBalancer**:
- **GatewayInstance_1**:
- **GatewayInstance_2**:

## Dataflows
- **LBtoInstance1**: from=LoadBalancer, to=GatewayInstance_1, protocol=HTTP
- **LBtoInstance2**: from=LoadBalancer, to=GatewayInstance_2, protocol=HTTP

## Protocol Styles
- **HTTP**: color=red, line_style=solid
