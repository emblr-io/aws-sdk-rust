// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateVirtualGatewayOutput {
    /// <p>A full description of the virtual gateway that was updated.</p>
    pub virtual_gateway: ::std::option::Option<crate::types::VirtualGatewayData>,
    _request_id: Option<String>,
}
impl UpdateVirtualGatewayOutput {
    /// <p>A full description of the virtual gateway that was updated.</p>
    pub fn virtual_gateway(&self) -> ::std::option::Option<&crate::types::VirtualGatewayData> {
        self.virtual_gateway.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateVirtualGatewayOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateVirtualGatewayOutput {
    /// Creates a new builder-style object to manufacture [`UpdateVirtualGatewayOutput`](crate::operation::update_virtual_gateway::UpdateVirtualGatewayOutput).
    pub fn builder() -> crate::operation::update_virtual_gateway::builders::UpdateVirtualGatewayOutputBuilder {
        crate::operation::update_virtual_gateway::builders::UpdateVirtualGatewayOutputBuilder::default()
    }
}

/// A builder for [`UpdateVirtualGatewayOutput`](crate::operation::update_virtual_gateway::UpdateVirtualGatewayOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateVirtualGatewayOutputBuilder {
    pub(crate) virtual_gateway: ::std::option::Option<crate::types::VirtualGatewayData>,
    _request_id: Option<String>,
}
impl UpdateVirtualGatewayOutputBuilder {
    /// <p>A full description of the virtual gateway that was updated.</p>
    /// This field is required.
    pub fn virtual_gateway(mut self, input: crate::types::VirtualGatewayData) -> Self {
        self.virtual_gateway = ::std::option::Option::Some(input);
        self
    }
    /// <p>A full description of the virtual gateway that was updated.</p>
    pub fn set_virtual_gateway(mut self, input: ::std::option::Option<crate::types::VirtualGatewayData>) -> Self {
        self.virtual_gateway = input;
        self
    }
    /// <p>A full description of the virtual gateway that was updated.</p>
    pub fn get_virtual_gateway(&self) -> &::std::option::Option<crate::types::VirtualGatewayData> {
        &self.virtual_gateway
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateVirtualGatewayOutput`](crate::operation::update_virtual_gateway::UpdateVirtualGatewayOutput).
    pub fn build(self) -> crate::operation::update_virtual_gateway::UpdateVirtualGatewayOutput {
        crate::operation::update_virtual_gateway::UpdateVirtualGatewayOutput {
            virtual_gateway: self.virtual_gateway,
            _request_id: self._request_id,
        }
    }
}
