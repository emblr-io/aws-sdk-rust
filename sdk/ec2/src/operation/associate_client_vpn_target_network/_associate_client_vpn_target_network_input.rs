// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateClientVpnTargetNetworkInput {
    /// <p>The ID of the Client VPN endpoint.</p>
    pub client_vpn_endpoint_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the subnet to associate with the Client VPN endpoint.</p>
    pub subnet_id: ::std::option::Option<::std::string::String>,
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl AssociateClientVpnTargetNetworkInput {
    /// <p>The ID of the Client VPN endpoint.</p>
    pub fn client_vpn_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.client_vpn_endpoint_id.as_deref()
    }
    /// <p>The ID of the subnet to associate with the Client VPN endpoint.</p>
    pub fn subnet_id(&self) -> ::std::option::Option<&str> {
        self.subnet_id.as_deref()
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl AssociateClientVpnTargetNetworkInput {
    /// Creates a new builder-style object to manufacture [`AssociateClientVpnTargetNetworkInput`](crate::operation::associate_client_vpn_target_network::AssociateClientVpnTargetNetworkInput).
    pub fn builder() -> crate::operation::associate_client_vpn_target_network::builders::AssociateClientVpnTargetNetworkInputBuilder {
        crate::operation::associate_client_vpn_target_network::builders::AssociateClientVpnTargetNetworkInputBuilder::default()
    }
}

/// A builder for [`AssociateClientVpnTargetNetworkInput`](crate::operation::associate_client_vpn_target_network::AssociateClientVpnTargetNetworkInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateClientVpnTargetNetworkInputBuilder {
    pub(crate) client_vpn_endpoint_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl AssociateClientVpnTargetNetworkInputBuilder {
    /// <p>The ID of the Client VPN endpoint.</p>
    /// This field is required.
    pub fn client_vpn_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_vpn_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Client VPN endpoint.</p>
    pub fn set_client_vpn_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_vpn_endpoint_id = input;
        self
    }
    /// <p>The ID of the Client VPN endpoint.</p>
    pub fn get_client_vpn_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_vpn_endpoint_id
    }
    /// <p>The ID of the subnet to associate with the Client VPN endpoint.</p>
    /// This field is required.
    pub fn subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the subnet to associate with the Client VPN endpoint.</p>
    pub fn set_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_id = input;
        self
    }
    /// <p>The ID of the subnet to associate with the Client VPN endpoint.</p>
    pub fn get_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_id
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
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
    /// Consumes the builder and constructs a [`AssociateClientVpnTargetNetworkInput`](crate::operation::associate_client_vpn_target_network::AssociateClientVpnTargetNetworkInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::associate_client_vpn_target_network::AssociateClientVpnTargetNetworkInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::associate_client_vpn_target_network::AssociateClientVpnTargetNetworkInput {
                client_vpn_endpoint_id: self.client_vpn_endpoint_id,
                subnet_id: self.subnet_id,
                client_token: self.client_token,
                dry_run: self.dry_run,
            },
        )
    }
}
