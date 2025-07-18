// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteClientVpnEndpointInput {
    /// <p>The ID of the Client VPN to be deleted.</p>
    pub client_vpn_endpoint_id: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DeleteClientVpnEndpointInput {
    /// <p>The ID of the Client VPN to be deleted.</p>
    pub fn client_vpn_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.client_vpn_endpoint_id.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DeleteClientVpnEndpointInput {
    /// Creates a new builder-style object to manufacture [`DeleteClientVpnEndpointInput`](crate::operation::delete_client_vpn_endpoint::DeleteClientVpnEndpointInput).
    pub fn builder() -> crate::operation::delete_client_vpn_endpoint::builders::DeleteClientVpnEndpointInputBuilder {
        crate::operation::delete_client_vpn_endpoint::builders::DeleteClientVpnEndpointInputBuilder::default()
    }
}

/// A builder for [`DeleteClientVpnEndpointInput`](crate::operation::delete_client_vpn_endpoint::DeleteClientVpnEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteClientVpnEndpointInputBuilder {
    pub(crate) client_vpn_endpoint_id: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DeleteClientVpnEndpointInputBuilder {
    /// <p>The ID of the Client VPN to be deleted.</p>
    /// This field is required.
    pub fn client_vpn_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_vpn_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Client VPN to be deleted.</p>
    pub fn set_client_vpn_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_vpn_endpoint_id = input;
        self
    }
    /// <p>The ID of the Client VPN to be deleted.</p>
    pub fn get_client_vpn_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_vpn_endpoint_id
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
    /// Consumes the builder and constructs a [`DeleteClientVpnEndpointInput`](crate::operation::delete_client_vpn_endpoint::DeleteClientVpnEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_client_vpn_endpoint::DeleteClientVpnEndpointInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_client_vpn_endpoint::DeleteClientVpnEndpointInput {
            client_vpn_endpoint_id: self.client_vpn_endpoint_id,
            dry_run: self.dry_run,
        })
    }
}
