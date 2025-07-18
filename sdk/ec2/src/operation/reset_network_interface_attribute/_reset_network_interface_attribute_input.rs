// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the parameters for ResetNetworkInterfaceAttribute.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResetNetworkInterfaceAttributeInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The ID of the network interface.</p>
    pub network_interface_id: ::std::option::Option<::std::string::String>,
    /// <p>The source/destination checking attribute. Resets the value to <code>true</code>.</p>
    pub source_dest_check: ::std::option::Option<::std::string::String>,
}
impl ResetNetworkInterfaceAttributeInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The ID of the network interface.</p>
    pub fn network_interface_id(&self) -> ::std::option::Option<&str> {
        self.network_interface_id.as_deref()
    }
    /// <p>The source/destination checking attribute. Resets the value to <code>true</code>.</p>
    pub fn source_dest_check(&self) -> ::std::option::Option<&str> {
        self.source_dest_check.as_deref()
    }
}
impl ResetNetworkInterfaceAttributeInput {
    /// Creates a new builder-style object to manufacture [`ResetNetworkInterfaceAttributeInput`](crate::operation::reset_network_interface_attribute::ResetNetworkInterfaceAttributeInput).
    pub fn builder() -> crate::operation::reset_network_interface_attribute::builders::ResetNetworkInterfaceAttributeInputBuilder {
        crate::operation::reset_network_interface_attribute::builders::ResetNetworkInterfaceAttributeInputBuilder::default()
    }
}

/// A builder for [`ResetNetworkInterfaceAttributeInput`](crate::operation::reset_network_interface_attribute::ResetNetworkInterfaceAttributeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResetNetworkInterfaceAttributeInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) network_interface_id: ::std::option::Option<::std::string::String>,
    pub(crate) source_dest_check: ::std::option::Option<::std::string::String>,
}
impl ResetNetworkInterfaceAttributeInputBuilder {
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
    /// <p>The ID of the network interface.</p>
    /// This field is required.
    pub fn network_interface_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_interface_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the network interface.</p>
    pub fn set_network_interface_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_interface_id = input;
        self
    }
    /// <p>The ID of the network interface.</p>
    pub fn get_network_interface_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_interface_id
    }
    /// <p>The source/destination checking attribute. Resets the value to <code>true</code>.</p>
    pub fn source_dest_check(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_dest_check = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source/destination checking attribute. Resets the value to <code>true</code>.</p>
    pub fn set_source_dest_check(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_dest_check = input;
        self
    }
    /// <p>The source/destination checking attribute. Resets the value to <code>true</code>.</p>
    pub fn get_source_dest_check(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_dest_check
    }
    /// Consumes the builder and constructs a [`ResetNetworkInterfaceAttributeInput`](crate::operation::reset_network_interface_attribute::ResetNetworkInterfaceAttributeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::reset_network_interface_attribute::ResetNetworkInterfaceAttributeInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::reset_network_interface_attribute::ResetNetworkInterfaceAttributeInput {
            dry_run: self.dry_run,
            network_interface_id: self.network_interface_id,
            source_dest_check: self.source_dest_check,
        })
    }
}
