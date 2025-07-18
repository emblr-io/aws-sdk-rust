// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the parameters for DeleteVpnGateway.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteVpnGatewayInput {
    /// <p>The ID of the virtual private gateway.</p>
    pub vpn_gateway_id: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DeleteVpnGatewayInput {
    /// <p>The ID of the virtual private gateway.</p>
    pub fn vpn_gateway_id(&self) -> ::std::option::Option<&str> {
        self.vpn_gateway_id.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DeleteVpnGatewayInput {
    /// Creates a new builder-style object to manufacture [`DeleteVpnGatewayInput`](crate::operation::delete_vpn_gateway::DeleteVpnGatewayInput).
    pub fn builder() -> crate::operation::delete_vpn_gateway::builders::DeleteVpnGatewayInputBuilder {
        crate::operation::delete_vpn_gateway::builders::DeleteVpnGatewayInputBuilder::default()
    }
}

/// A builder for [`DeleteVpnGatewayInput`](crate::operation::delete_vpn_gateway::DeleteVpnGatewayInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteVpnGatewayInputBuilder {
    pub(crate) vpn_gateway_id: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DeleteVpnGatewayInputBuilder {
    /// <p>The ID of the virtual private gateway.</p>
    /// This field is required.
    pub fn vpn_gateway_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpn_gateway_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the virtual private gateway.</p>
    pub fn set_vpn_gateway_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpn_gateway_id = input;
        self
    }
    /// <p>The ID of the virtual private gateway.</p>
    pub fn get_vpn_gateway_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpn_gateway_id
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`DeleteVpnGatewayInput`](crate::operation::delete_vpn_gateway::DeleteVpnGatewayInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_vpn_gateway::DeleteVpnGatewayInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_vpn_gateway::DeleteVpnGatewayInput {
            vpn_gateway_id: self.vpn_gateway_id,
            dry_run: self.dry_run,
        })
    }
}
