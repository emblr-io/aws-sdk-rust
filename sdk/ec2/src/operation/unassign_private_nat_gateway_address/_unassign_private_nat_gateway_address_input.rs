// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnassignPrivateNatGatewayAddressInput {
    /// <p>The ID of the NAT gateway.</p>
    pub nat_gateway_id: ::std::option::Option<::std::string::String>,
    /// <p>The private IPv4 addresses you want to unassign.</p>
    pub private_ip_addresses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The maximum amount of time to wait (in seconds) before forcibly releasing the IP addresses if connections are still in progress. Default value is 350 seconds.</p>
    pub max_drain_duration_seconds: ::std::option::Option<i32>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl UnassignPrivateNatGatewayAddressInput {
    /// <p>The ID of the NAT gateway.</p>
    pub fn nat_gateway_id(&self) -> ::std::option::Option<&str> {
        self.nat_gateway_id.as_deref()
    }
    /// <p>The private IPv4 addresses you want to unassign.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.private_ip_addresses.is_none()`.
    pub fn private_ip_addresses(&self) -> &[::std::string::String] {
        self.private_ip_addresses.as_deref().unwrap_or_default()
    }
    /// <p>The maximum amount of time to wait (in seconds) before forcibly releasing the IP addresses if connections are still in progress. Default value is 350 seconds.</p>
    pub fn max_drain_duration_seconds(&self) -> ::std::option::Option<i32> {
        self.max_drain_duration_seconds
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl UnassignPrivateNatGatewayAddressInput {
    /// Creates a new builder-style object to manufacture [`UnassignPrivateNatGatewayAddressInput`](crate::operation::unassign_private_nat_gateway_address::UnassignPrivateNatGatewayAddressInput).
    pub fn builder() -> crate::operation::unassign_private_nat_gateway_address::builders::UnassignPrivateNatGatewayAddressInputBuilder {
        crate::operation::unassign_private_nat_gateway_address::builders::UnassignPrivateNatGatewayAddressInputBuilder::default()
    }
}

/// A builder for [`UnassignPrivateNatGatewayAddressInput`](crate::operation::unassign_private_nat_gateway_address::UnassignPrivateNatGatewayAddressInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnassignPrivateNatGatewayAddressInputBuilder {
    pub(crate) nat_gateway_id: ::std::option::Option<::std::string::String>,
    pub(crate) private_ip_addresses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) max_drain_duration_seconds: ::std::option::Option<i32>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl UnassignPrivateNatGatewayAddressInputBuilder {
    /// <p>The ID of the NAT gateway.</p>
    /// This field is required.
    pub fn nat_gateway_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.nat_gateway_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the NAT gateway.</p>
    pub fn set_nat_gateway_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.nat_gateway_id = input;
        self
    }
    /// <p>The ID of the NAT gateway.</p>
    pub fn get_nat_gateway_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.nat_gateway_id
    }
    /// Appends an item to `private_ip_addresses`.
    ///
    /// To override the contents of this collection use [`set_private_ip_addresses`](Self::set_private_ip_addresses).
    ///
    /// <p>The private IPv4 addresses you want to unassign.</p>
    pub fn private_ip_addresses(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.private_ip_addresses.unwrap_or_default();
        v.push(input.into());
        self.private_ip_addresses = ::std::option::Option::Some(v);
        self
    }
    /// <p>The private IPv4 addresses you want to unassign.</p>
    pub fn set_private_ip_addresses(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.private_ip_addresses = input;
        self
    }
    /// <p>The private IPv4 addresses you want to unassign.</p>
    pub fn get_private_ip_addresses(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.private_ip_addresses
    }
    /// <p>The maximum amount of time to wait (in seconds) before forcibly releasing the IP addresses if connections are still in progress. Default value is 350 seconds.</p>
    pub fn max_drain_duration_seconds(mut self, input: i32) -> Self {
        self.max_drain_duration_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of time to wait (in seconds) before forcibly releasing the IP addresses if connections are still in progress. Default value is 350 seconds.</p>
    pub fn set_max_drain_duration_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_drain_duration_seconds = input;
        self
    }
    /// <p>The maximum amount of time to wait (in seconds) before forcibly releasing the IP addresses if connections are still in progress. Default value is 350 seconds.</p>
    pub fn get_max_drain_duration_seconds(&self) -> &::std::option::Option<i32> {
        &self.max_drain_duration_seconds
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
    /// Consumes the builder and constructs a [`UnassignPrivateNatGatewayAddressInput`](crate::operation::unassign_private_nat_gateway_address::UnassignPrivateNatGatewayAddressInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::unassign_private_nat_gateway_address::UnassignPrivateNatGatewayAddressInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::unassign_private_nat_gateway_address::UnassignPrivateNatGatewayAddressInput {
                nat_gateway_id: self.nat_gateway_id,
                private_ip_addresses: self.private_ip_addresses,
                max_drain_duration_seconds: self.max_drain_duration_seconds,
                dry_run: self.dry_run,
            },
        )
    }
}
