## Description
- A DMZ (Demilitarized Zone) is a perimeter network that protects an organization's internal local-area network (LAN) from untrusted traffic. It is a subnetwork that sits between the public internet and private networks.

## Servers
- **Firewall_1**: type=Firewall
- **Firewall_2**: type=Firewall
- **ApiGateway**: submodel=../api_gateway/model.md

## Dataflows
- **Firewall1ToApiGateway**: from=Firewall_1, to=ApiGateway, protocol=HTTPS
- **Firewall2ToApiGateway**: from=Firewall_2, to=ApiGateway, protocol=HTTPS

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
