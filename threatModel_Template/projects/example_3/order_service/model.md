## Description
- The Order Service is a collection of microservices responsible for handling all aspects of an order. It uses a queue to decouple the initial order intake from payment processing.

## Servers
- **OrderQueue**: type=Queue
- **PaymentService_1**:
- **PaymentService_2**:
- **ShippingService_1**:
- **ShippingService_2**:
- **NotificationService**:

## Data
- **Order**: description="Raw order data as it comes into the system", classification="SENSITIVE"
- **PaymentInfo**: description="User's payment details (e.g., credit card info)", classification="SECRET"
- **ShippingDetails**: description="User's shipping address and contact information", classification="SENSITIVE"
- **NotificationRequest**: description="Request to send a notification to the user (e.g., email)", classification="RESTRICTED"

## Dataflows
- **QueueToPayment1**: from=OrderQueue, to=PaymentService_1, data="Order", protocol=AMQP
- **QueueToPayment2**: from=OrderQueue, to=PaymentService_2, data="Order", protocol=AMQP
- **Payment1ToShipping1**: from=PaymentService_1, to=ShippingService_1, data="PaymentInfo", protocol=AMQP
- **Payment2ToShipping2**: from=PaymentService_2, to=ShippingService_2, data="PaymentInfo", protocol=AMQP
- **Shipping1ToNotify**: from=ShippingService_1, to=NotificationService, data="ShippingDetails", protocol=AMQP
- **Shipping2ToNotify**: from=ShippingService_2, to=NotificationService, data="ShippingDetails", protocol=AMQP

## Protocol Styles
- **AMQP**: color=orange, line_style=dashed
