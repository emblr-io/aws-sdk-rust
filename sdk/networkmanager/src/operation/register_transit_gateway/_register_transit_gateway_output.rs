// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterTransitGatewayOutput {
    /// <p>Information about the transit gateway registration.</p>
    pub transit_gateway_registration: ::std::option::Option<crate::types::TransitGatewayRegistration>,
    _request_id: Option<String>,
}
impl RegisterTransitGatewayOutput {
    /// <p>Information about the transit gateway registration.</p>
    pub fn transit_gateway_registration(&self) -> ::std::option::Option<&crate::types::TransitGatewayRegistration> {
        self.transit_gateway_registration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for RegisterTransitGatewayOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RegisterTransitGatewayOutput {
    /// Creates a new builder-style object to manufacture [`RegisterTransitGatewayOutput`](crate::operation::register_transit_gateway::RegisterTransitGatewayOutput).
    pub fn builder() -> crate::operation::register_transit_gateway::builders::RegisterTransitGatewayOutputBuilder {
        crate::operation::register_transit_gateway::builders::RegisterTransitGatewayOutputBuilder::default()
    }
}

/// A builder for [`RegisterTransitGatewayOutput`](crate::operation::register_transit_gateway::RegisterTransitGatewayOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterTransitGatewayOutputBuilder {
    pub(crate) transit_gateway_registration: ::std::option::Option<crate::types::TransitGatewayRegistration>,
    _request_id: Option<String>,
}
impl RegisterTransitGatewayOutputBuilder {
    /// <p>Information about the transit gateway registration.</p>
    pub fn transit_gateway_registration(mut self, input: crate::types::TransitGatewayRegistration) -> Self {
        self.transit_gateway_registration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the transit gateway registration.</p>
    pub fn set_transit_gateway_registration(mut self, input: ::std::option::Option<crate::types::TransitGatewayRegistration>) -> Self {
        self.transit_gateway_registration = input;
        self
    }
    /// <p>Information about the transit gateway registration.</p>
    pub fn get_transit_gateway_registration(&self) -> &::std::option::Option<crate::types::TransitGatewayRegistration> {
        &self.transit_gateway_registration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RegisterTransitGatewayOutput`](crate::operation::register_transit_gateway::RegisterTransitGatewayOutput).
    pub fn build(self) -> crate::operation::register_transit_gateway::RegisterTransitGatewayOutput {
        crate::operation::register_transit_gateway::RegisterTransitGatewayOutput {
            transit_gateway_registration: self.transit_gateway_registration,
            _request_id: self._request_id,
        }
    }
}
