// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTransitGatewayPeeringInput {
    /// <p>The ID of the peering request.</p>
    pub peering_id: ::std::option::Option<::std::string::String>,
}
impl GetTransitGatewayPeeringInput {
    /// <p>The ID of the peering request.</p>
    pub fn peering_id(&self) -> ::std::option::Option<&str> {
        self.peering_id.as_deref()
    }
}
impl GetTransitGatewayPeeringInput {
    /// Creates a new builder-style object to manufacture [`GetTransitGatewayPeeringInput`](crate::operation::get_transit_gateway_peering::GetTransitGatewayPeeringInput).
    pub fn builder() -> crate::operation::get_transit_gateway_peering::builders::GetTransitGatewayPeeringInputBuilder {
        crate::operation::get_transit_gateway_peering::builders::GetTransitGatewayPeeringInputBuilder::default()
    }
}

/// A builder for [`GetTransitGatewayPeeringInput`](crate::operation::get_transit_gateway_peering::GetTransitGatewayPeeringInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTransitGatewayPeeringInputBuilder {
    pub(crate) peering_id: ::std::option::Option<::std::string::String>,
}
impl GetTransitGatewayPeeringInputBuilder {
    /// <p>The ID of the peering request.</p>
    /// This field is required.
    pub fn peering_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.peering_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the peering request.</p>
    pub fn set_peering_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.peering_id = input;
        self
    }
    /// <p>The ID of the peering request.</p>
    pub fn get_peering_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.peering_id
    }
    /// Consumes the builder and constructs a [`GetTransitGatewayPeeringInput`](crate::operation::get_transit_gateway_peering::GetTransitGatewayPeeringInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_transit_gateway_peering::GetTransitGatewayPeeringInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_transit_gateway_peering::GetTransitGatewayPeeringInput { peering_id: self.peering_id })
    }
}
