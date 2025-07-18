// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateWirelessGatewayWithThingOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for AssociateWirelessGatewayWithThingOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateWirelessGatewayWithThingOutput {
    /// Creates a new builder-style object to manufacture [`AssociateWirelessGatewayWithThingOutput`](crate::operation::associate_wireless_gateway_with_thing::AssociateWirelessGatewayWithThingOutput).
    pub fn builder() -> crate::operation::associate_wireless_gateway_with_thing::builders::AssociateWirelessGatewayWithThingOutputBuilder {
        crate::operation::associate_wireless_gateway_with_thing::builders::AssociateWirelessGatewayWithThingOutputBuilder::default()
    }
}

/// A builder for [`AssociateWirelessGatewayWithThingOutput`](crate::operation::associate_wireless_gateway_with_thing::AssociateWirelessGatewayWithThingOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateWirelessGatewayWithThingOutputBuilder {
    _request_id: Option<String>,
}
impl AssociateWirelessGatewayWithThingOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateWirelessGatewayWithThingOutput`](crate::operation::associate_wireless_gateway_with_thing::AssociateWirelessGatewayWithThingOutput).
    pub fn build(self) -> crate::operation::associate_wireless_gateway_with_thing::AssociateWirelessGatewayWithThingOutput {
        crate::operation::associate_wireless_gateway_with_thing::AssociateWirelessGatewayWithThingOutput {
            _request_id: self._request_id,
        }
    }
}
