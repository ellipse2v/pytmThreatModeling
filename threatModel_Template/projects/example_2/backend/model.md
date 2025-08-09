## Servers
- **APIGateway**:
- **AuthService**:
- **OrderService**:
- **ProductDB**: submodel=./database/model.md

## Dataflows
- **GatewayToAuth**: from=APIGateway, to=AuthService, protocol=gRPC
- **GatewayToOrders**: from=APIGateway, to=OrderService, protocol=gRPC
- **OrdersToDB**: from=OrderService, to=ProductDB, protocol=TCP
