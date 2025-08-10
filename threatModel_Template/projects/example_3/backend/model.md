## Boundaries
- **Trusted Application Zone**: isTrusted=True
- **Protected DB Zone**: isTrusted=True

## Servers
- **CoreSwitch**: type=Switch, boundary="Trusted Application Zone"
- **AuthService**: boundary="Trusted Application Zone"
- **OrderService**: submodel=../order_service/model.md, boundary="Trusted Application Zone"
- **DBSwitch**: type=Switch, boundary="Protected DB Zone"
- **DBFirewall**: type=Firewall, boundary="Protected DB Zone"
- **ProductDB**: submodel=./database/model.md, boundary="Protected DB Zone"

## Data
- **AuthRequest**: description="Request for authentication or authorization", classification="SECRET"
- **OrderProcessingRequest**: description="Request to process an order, sent to the order service", classification="SENSITIVE"
- **DBTransaction**: description="Raw TCP traffic for database transaction", classification="SECRET"

## Dataflows
- **SwitchToAuth**: from=CoreSwitch, to=AuthService, protocol=gRPC, data="AuthRequest"
- **SwitchToOrders**: from=CoreSwitch, to=OrderService, protocol=gRPC, data="OrderProcessingRequest"
- **OrdersToDBSwitch**: from=OrderService, to=DBSwitch, protocol=TCP, data="DBTransaction"
- **DBSwitchToFirewall**: from=DBSwitch, to=DBFirewall, protocol=TCP, data="DBTransaction"
- **FirewallToDB**: from=DBFirewall, to=ProductDB, protocol=TCP, data="DBTransaction"

## Protocol Styles
- **gRPC**: color=blue, line_style=dashed
- **TCP**: color=black, line_style=dotted
