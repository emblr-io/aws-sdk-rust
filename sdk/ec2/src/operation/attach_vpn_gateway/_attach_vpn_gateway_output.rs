// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the output of AttachVpnGateway.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AttachVpnGatewayOutput {
    /// <p>Information about the attachment.</p>
    pub vpc_attachment: ::std::option::Option<crate::types::VpcAttachment>,
    _request_id: Option<String>,
}
impl AttachVpnGatewayOutput {
    /// <p>Information about the attachment.</p>
    pub fn vpc_attachment(&self) -> ::std::option::Option<&crate::types::VpcAttachment> {
        self.vpc_attachment.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for AttachVpnGatewayOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AttachVpnGatewayOutput {
    /// Creates a new builder-style object to manufacture [`AttachVpnGatewayOutput`](crate::operation::attach_vpn_gateway::AttachVpnGatewayOutput).
    pub fn builder() -> crate::operation::attach_vpn_gateway::builders::AttachVpnGatewayOutputBuilder {
        crate::operation::attach_vpn_gateway::builders::AttachVpnGatewayOutputBuilder::default()
    }
}

/// A builder for [`AttachVpnGatewayOutput`](crate::operation::attach_vpn_gateway::AttachVpnGatewayOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AttachVpnGatewayOutputBuilder {
    pub(crate) vpc_attachment: ::std::option::Option<crate::types::VpcAttachment>,
    _request_id: Option<String>,
}
impl AttachVpnGatewayOutputBuilder {
    /// <p>Information about the attachment.</p>
    pub fn vpc_attachment(mut self, input: crate::types::VpcAttachment) -> Self {
        self.vpc_attachment = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the attachment.</p>
    pub fn set_vpc_attachment(mut self, input: ::std::option::Option<crate::types::VpcAttachment>) -> Self {
        self.vpc_attachment = input;
        self
    }
    /// <p>Information about the attachment.</p>
    pub fn get_vpc_attachment(&self) -> &::std::option::Option<crate::types::VpcAttachment> {
        &self.vpc_attachment
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AttachVpnGatewayOutput`](crate::operation::attach_vpn_gateway::AttachVpnGatewayOutput).
    pub fn build(self) -> crate::operation::attach_vpn_gateway::AttachVpnGatewayOutput {
        crate::operation::attach_vpn_gateway::AttachVpnGatewayOutput {
            vpc_attachment: self.vpc_attachment,
            _request_id: self._request_id,
        }
    }
}
