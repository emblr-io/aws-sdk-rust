// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTransitGatewayPolicyTableInput {
    /// <p>The transit gateway policy table to delete.</p>
    pub transit_gateway_policy_table_id: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DeleteTransitGatewayPolicyTableInput {
    /// <p>The transit gateway policy table to delete.</p>
    pub fn transit_gateway_policy_table_id(&self) -> ::std::option::Option<&str> {
        self.transit_gateway_policy_table_id.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DeleteTransitGatewayPolicyTableInput {
    /// Creates a new builder-style object to manufacture [`DeleteTransitGatewayPolicyTableInput`](crate::operation::delete_transit_gateway_policy_table::DeleteTransitGatewayPolicyTableInput).
    pub fn builder() -> crate::operation::delete_transit_gateway_policy_table::builders::DeleteTransitGatewayPolicyTableInputBuilder {
        crate::operation::delete_transit_gateway_policy_table::builders::DeleteTransitGatewayPolicyTableInputBuilder::default()
    }
}

/// A builder for [`DeleteTransitGatewayPolicyTableInput`](crate::operation::delete_transit_gateway_policy_table::DeleteTransitGatewayPolicyTableInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTransitGatewayPolicyTableInputBuilder {
    pub(crate) transit_gateway_policy_table_id: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DeleteTransitGatewayPolicyTableInputBuilder {
    /// <p>The transit gateway policy table to delete.</p>
    /// This field is required.
    pub fn transit_gateway_policy_table_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transit_gateway_policy_table_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transit gateway policy table to delete.</p>
    pub fn set_transit_gateway_policy_table_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transit_gateway_policy_table_id = input;
        self
    }
    /// <p>The transit gateway policy table to delete.</p>
    pub fn get_transit_gateway_policy_table_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transit_gateway_policy_table_id
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
    /// Consumes the builder and constructs a [`DeleteTransitGatewayPolicyTableInput`](crate::operation::delete_transit_gateway_policy_table::DeleteTransitGatewayPolicyTableInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_transit_gateway_policy_table::DeleteTransitGatewayPolicyTableInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_transit_gateway_policy_table::DeleteTransitGatewayPolicyTableInput {
                transit_gateway_policy_table_id: self.transit_gateway_policy_table_id,
                dry_run: self.dry_run,
            },
        )
    }
}
