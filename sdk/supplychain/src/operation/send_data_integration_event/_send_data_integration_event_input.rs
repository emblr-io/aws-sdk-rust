// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request parameters for SendDataIntegrationEvent.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SendDataIntegrationEventInput {
    /// <p>The AWS Supply Chain instance identifier.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The data event type.</p>
    /// <ul>
    /// <li>
    /// <p><b>scn.data.dataset</b> - Send data directly to any specified dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.supplyplan</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/supply-plan-entity.html">supply_plan</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipmentstoporder</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-stop-order-entity.html">shipment_stop_order</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipmentstop</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-stop-entity.html">shipment_stop</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipment</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-entity.html">shipment</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.reservation</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/planning-reservation-entity.html">reservation</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processproduct</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-product-entity.html">process_product</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processoperation</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-operation-entity.html">process_operation</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processheader</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-header-entity.html">process_header</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.forecast</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/forecast-forecast-entity.html">forecast</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inventorylevel</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/inventory_mgmnt-inv-level-entity.html">inv_level</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorder</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-entity.html">inbound_order</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorderline</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-line-entity.html">inbound_order_line</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorderlineschedule</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-line-schedule-entity.html">inbound_order_line_schedule</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.outboundorderline</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/outbound-fulfillment-order-line-entity.html">outbound_order_line</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.outboundshipment</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/outbound-fulfillment-shipment-entity.html">outbound_shipment</a> dataset.</p></li>
    /// </ul>
    pub event_type: ::std::option::Option<crate::types::DataIntegrationEventType>,
    /// <p>The data payload of the event, should follow the data schema of the target dataset, or see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">Data entities supported in AWS Supply Chain</a>. To send single data record, use JsonObject format; to send multiple data records, use JsonArray format.</p>
    /// <p>Note that for AWS Supply Chain dataset under <b>asc</b> namespace, it has a connection_id internal field that is not allowed to be provided by client directly, they will be auto populated.</p>
    pub data: ::std::option::Option<::std::string::String>,
    /// <p>Event identifier (for example, orderId for InboundOrder) used for data sharding or partitioning. Noted under one eventGroupId of same eventType and instanceId, events are processed sequentially in the order they are received by the server.</p>
    pub event_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp (in epoch seconds) associated with the event. If not provided, it will be assigned with current timestamp.</p>
    pub event_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The idempotent client token. The token is active for 8 hours, and within its lifetime, it ensures the request completes only once upon retry with same client token. If omitted, the AWS SDK generates a unique value so that AWS SDK can safely retry the request upon network errors.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The target dataset configuration for <b>scn.data.dataset</b> event type.</p>
    pub dataset_target: ::std::option::Option<crate::types::DataIntegrationEventDatasetTargetConfiguration>,
}
impl SendDataIntegrationEventInput {
    /// <p>The AWS Supply Chain instance identifier.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The data event type.</p>
    /// <ul>
    /// <li>
    /// <p><b>scn.data.dataset</b> - Send data directly to any specified dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.supplyplan</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/supply-plan-entity.html">supply_plan</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipmentstoporder</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-stop-order-entity.html">shipment_stop_order</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipmentstop</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-stop-entity.html">shipment_stop</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipment</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-entity.html">shipment</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.reservation</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/planning-reservation-entity.html">reservation</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processproduct</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-product-entity.html">process_product</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processoperation</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-operation-entity.html">process_operation</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processheader</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-header-entity.html">process_header</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.forecast</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/forecast-forecast-entity.html">forecast</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inventorylevel</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/inventory_mgmnt-inv-level-entity.html">inv_level</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorder</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-entity.html">inbound_order</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorderline</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-line-entity.html">inbound_order_line</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorderlineschedule</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-line-schedule-entity.html">inbound_order_line_schedule</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.outboundorderline</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/outbound-fulfillment-order-line-entity.html">outbound_order_line</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.outboundshipment</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/outbound-fulfillment-shipment-entity.html">outbound_shipment</a> dataset.</p></li>
    /// </ul>
    pub fn event_type(&self) -> ::std::option::Option<&crate::types::DataIntegrationEventType> {
        self.event_type.as_ref()
    }
    /// <p>The data payload of the event, should follow the data schema of the target dataset, or see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">Data entities supported in AWS Supply Chain</a>. To send single data record, use JsonObject format; to send multiple data records, use JsonArray format.</p>
    /// <p>Note that for AWS Supply Chain dataset under <b>asc</b> namespace, it has a connection_id internal field that is not allowed to be provided by client directly, they will be auto populated.</p>
    pub fn data(&self) -> ::std::option::Option<&str> {
        self.data.as_deref()
    }
    /// <p>Event identifier (for example, orderId for InboundOrder) used for data sharding or partitioning. Noted under one eventGroupId of same eventType and instanceId, events are processed sequentially in the order they are received by the server.</p>
    pub fn event_group_id(&self) -> ::std::option::Option<&str> {
        self.event_group_id.as_deref()
    }
    /// <p>The timestamp (in epoch seconds) associated with the event. If not provided, it will be assigned with current timestamp.</p>
    pub fn event_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.event_timestamp.as_ref()
    }
    /// <p>The idempotent client token. The token is active for 8 hours, and within its lifetime, it ensures the request completes only once upon retry with same client token. If omitted, the AWS SDK generates a unique value so that AWS SDK can safely retry the request upon network errors.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The target dataset configuration for <b>scn.data.dataset</b> event type.</p>
    pub fn dataset_target(&self) -> ::std::option::Option<&crate::types::DataIntegrationEventDatasetTargetConfiguration> {
        self.dataset_target.as_ref()
    }
}
impl ::std::fmt::Debug for SendDataIntegrationEventInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SendDataIntegrationEventInput");
        formatter.field("instance_id", &self.instance_id);
        formatter.field("event_type", &self.event_type);
        formatter.field("data", &"*** Sensitive Data Redacted ***");
        formatter.field("event_group_id", &self.event_group_id);
        formatter.field("event_timestamp", &self.event_timestamp);
        formatter.field("client_token", &self.client_token);
        formatter.field("dataset_target", &self.dataset_target);
        formatter.finish()
    }
}
impl SendDataIntegrationEventInput {
    /// Creates a new builder-style object to manufacture [`SendDataIntegrationEventInput`](crate::operation::send_data_integration_event::SendDataIntegrationEventInput).
    pub fn builder() -> crate::operation::send_data_integration_event::builders::SendDataIntegrationEventInputBuilder {
        crate::operation::send_data_integration_event::builders::SendDataIntegrationEventInputBuilder::default()
    }
}

/// A builder for [`SendDataIntegrationEventInput`](crate::operation::send_data_integration_event::SendDataIntegrationEventInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SendDataIntegrationEventInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) event_type: ::std::option::Option<crate::types::DataIntegrationEventType>,
    pub(crate) data: ::std::option::Option<::std::string::String>,
    pub(crate) event_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) event_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_target: ::std::option::Option<crate::types::DataIntegrationEventDatasetTargetConfiguration>,
}
impl SendDataIntegrationEventInputBuilder {
    /// <p>The AWS Supply Chain instance identifier.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AWS Supply Chain instance identifier.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The AWS Supply Chain instance identifier.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The data event type.</p>
    /// <ul>
    /// <li>
    /// <p><b>scn.data.dataset</b> - Send data directly to any specified dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.supplyplan</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/supply-plan-entity.html">supply_plan</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipmentstoporder</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-stop-order-entity.html">shipment_stop_order</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipmentstop</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-stop-entity.html">shipment_stop</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipment</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-entity.html">shipment</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.reservation</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/planning-reservation-entity.html">reservation</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processproduct</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-product-entity.html">process_product</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processoperation</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-operation-entity.html">process_operation</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processheader</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-header-entity.html">process_header</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.forecast</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/forecast-forecast-entity.html">forecast</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inventorylevel</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/inventory_mgmnt-inv-level-entity.html">inv_level</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorder</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-entity.html">inbound_order</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorderline</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-line-entity.html">inbound_order_line</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorderlineschedule</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-line-schedule-entity.html">inbound_order_line_schedule</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.outboundorderline</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/outbound-fulfillment-order-line-entity.html">outbound_order_line</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.outboundshipment</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/outbound-fulfillment-shipment-entity.html">outbound_shipment</a> dataset.</p></li>
    /// </ul>
    /// This field is required.
    pub fn event_type(mut self, input: crate::types::DataIntegrationEventType) -> Self {
        self.event_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data event type.</p>
    /// <ul>
    /// <li>
    /// <p><b>scn.data.dataset</b> - Send data directly to any specified dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.supplyplan</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/supply-plan-entity.html">supply_plan</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipmentstoporder</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-stop-order-entity.html">shipment_stop_order</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipmentstop</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-stop-entity.html">shipment_stop</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipment</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-entity.html">shipment</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.reservation</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/planning-reservation-entity.html">reservation</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processproduct</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-product-entity.html">process_product</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processoperation</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-operation-entity.html">process_operation</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processheader</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-header-entity.html">process_header</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.forecast</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/forecast-forecast-entity.html">forecast</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inventorylevel</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/inventory_mgmnt-inv-level-entity.html">inv_level</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorder</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-entity.html">inbound_order</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorderline</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-line-entity.html">inbound_order_line</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorderlineschedule</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-line-schedule-entity.html">inbound_order_line_schedule</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.outboundorderline</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/outbound-fulfillment-order-line-entity.html">outbound_order_line</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.outboundshipment</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/outbound-fulfillment-shipment-entity.html">outbound_shipment</a> dataset.</p></li>
    /// </ul>
    pub fn set_event_type(mut self, input: ::std::option::Option<crate::types::DataIntegrationEventType>) -> Self {
        self.event_type = input;
        self
    }
    /// <p>The data event type.</p>
    /// <ul>
    /// <li>
    /// <p><b>scn.data.dataset</b> - Send data directly to any specified dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.supplyplan</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/supply-plan-entity.html">supply_plan</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipmentstoporder</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-stop-order-entity.html">shipment_stop_order</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipmentstop</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-stop-entity.html">shipment_stop</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.shipment</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-shipment-entity.html">shipment</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.reservation</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/planning-reservation-entity.html">reservation</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processproduct</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-product-entity.html">process_product</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processoperation</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-operation-entity.html">process_operation</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.processheader</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/operation-process-header-entity.html">process_header</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.forecast</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/forecast-forecast-entity.html">forecast</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inventorylevel</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/inventory_mgmnt-inv-level-entity.html">inv_level</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorder</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-entity.html">inbound_order</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorderline</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-line-entity.html">inbound_order_line</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.inboundorderlineschedule</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/replenishment-inbound-order-line-schedule-entity.html">inbound_order_line_schedule</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.outboundorderline</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/outbound-fulfillment-order-line-entity.html">outbound_order_line</a> dataset.</p></li>
    /// <li>
    /// <p><b>scn.data.outboundshipment</b> - Send data to <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/outbound-fulfillment-shipment-entity.html">outbound_shipment</a> dataset.</p></li>
    /// </ul>
    pub fn get_event_type(&self) -> &::std::option::Option<crate::types::DataIntegrationEventType> {
        &self.event_type
    }
    /// <p>The data payload of the event, should follow the data schema of the target dataset, or see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">Data entities supported in AWS Supply Chain</a>. To send single data record, use JsonObject format; to send multiple data records, use JsonArray format.</p>
    /// <p>Note that for AWS Supply Chain dataset under <b>asc</b> namespace, it has a connection_id internal field that is not allowed to be provided by client directly, they will be auto populated.</p>
    /// This field is required.
    pub fn data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The data payload of the event, should follow the data schema of the target dataset, or see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">Data entities supported in AWS Supply Chain</a>. To send single data record, use JsonObject format; to send multiple data records, use JsonArray format.</p>
    /// <p>Note that for AWS Supply Chain dataset under <b>asc</b> namespace, it has a connection_id internal field that is not allowed to be provided by client directly, they will be auto populated.</p>
    pub fn set_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data = input;
        self
    }
    /// <p>The data payload of the event, should follow the data schema of the target dataset, or see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">Data entities supported in AWS Supply Chain</a>. To send single data record, use JsonObject format; to send multiple data records, use JsonArray format.</p>
    /// <p>Note that for AWS Supply Chain dataset under <b>asc</b> namespace, it has a connection_id internal field that is not allowed to be provided by client directly, they will be auto populated.</p>
    pub fn get_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.data
    }
    /// <p>Event identifier (for example, orderId for InboundOrder) used for data sharding or partitioning. Noted under one eventGroupId of same eventType and instanceId, events are processed sequentially in the order they are received by the server.</p>
    /// This field is required.
    pub fn event_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Event identifier (for example, orderId for InboundOrder) used for data sharding or partitioning. Noted under one eventGroupId of same eventType and instanceId, events are processed sequentially in the order they are received by the server.</p>
    pub fn set_event_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_group_id = input;
        self
    }
    /// <p>Event identifier (for example, orderId for InboundOrder) used for data sharding or partitioning. Noted under one eventGroupId of same eventType and instanceId, events are processed sequentially in the order they are received by the server.</p>
    pub fn get_event_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_group_id
    }
    /// <p>The timestamp (in epoch seconds) associated with the event. If not provided, it will be assigned with current timestamp.</p>
    pub fn event_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.event_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp (in epoch seconds) associated with the event. If not provided, it will be assigned with current timestamp.</p>
    pub fn set_event_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.event_timestamp = input;
        self
    }
    /// <p>The timestamp (in epoch seconds) associated with the event. If not provided, it will be assigned with current timestamp.</p>
    pub fn get_event_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.event_timestamp
    }
    /// <p>The idempotent client token. The token is active for 8 hours, and within its lifetime, it ensures the request completes only once upon retry with same client token. If omitted, the AWS SDK generates a unique value so that AWS SDK can safely retry the request upon network errors.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The idempotent client token. The token is active for 8 hours, and within its lifetime, it ensures the request completes only once upon retry with same client token. If omitted, the AWS SDK generates a unique value so that AWS SDK can safely retry the request upon network errors.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The idempotent client token. The token is active for 8 hours, and within its lifetime, it ensures the request completes only once upon retry with same client token. If omitted, the AWS SDK generates a unique value so that AWS SDK can safely retry the request upon network errors.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The target dataset configuration for <b>scn.data.dataset</b> event type.</p>
    pub fn dataset_target(mut self, input: crate::types::DataIntegrationEventDatasetTargetConfiguration) -> Self {
        self.dataset_target = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target dataset configuration for <b>scn.data.dataset</b> event type.</p>
    pub fn set_dataset_target(mut self, input: ::std::option::Option<crate::types::DataIntegrationEventDatasetTargetConfiguration>) -> Self {
        self.dataset_target = input;
        self
    }
    /// <p>The target dataset configuration for <b>scn.data.dataset</b> event type.</p>
    pub fn get_dataset_target(&self) -> &::std::option::Option<crate::types::DataIntegrationEventDatasetTargetConfiguration> {
        &self.dataset_target
    }
    /// Consumes the builder and constructs a [`SendDataIntegrationEventInput`](crate::operation::send_data_integration_event::SendDataIntegrationEventInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::send_data_integration_event::SendDataIntegrationEventInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::send_data_integration_event::SendDataIntegrationEventInput {
            instance_id: self.instance_id,
            event_type: self.event_type,
            data: self.data,
            event_group_id: self.event_group_id,
            event_timestamp: self.event_timestamp,
            client_token: self.client_token,
            dataset_target: self.dataset_target,
        })
    }
}
impl ::std::fmt::Debug for SendDataIntegrationEventInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SendDataIntegrationEventInputBuilder");
        formatter.field("instance_id", &self.instance_id);
        formatter.field("event_type", &self.event_type);
        formatter.field("data", &"*** Sensitive Data Redacted ***");
        formatter.field("event_group_id", &self.event_group_id);
        formatter.field("event_timestamp", &self.event_timestamp);
        formatter.field("client_token", &self.client_token);
        formatter.field("dataset_target", &self.dataset_target);
        formatter.finish()
    }
}
