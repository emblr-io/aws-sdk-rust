// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCoipCidrInput {
    /// <p>A customer-owned IP address range that you want to delete.</p>
    pub cidr: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the customer-owned address pool.</p>
    pub coip_pool_id: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DeleteCoipCidrInput {
    /// <p>A customer-owned IP address range that you want to delete.</p>
    pub fn cidr(&self) -> ::std::option::Option<&str> {
        self.cidr.as_deref()
    }
    /// <p>The ID of the customer-owned address pool.</p>
    pub fn coip_pool_id(&self) -> ::std::option::Option<&str> {
        self.coip_pool_id.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DeleteCoipCidrInput {
    /// Creates a new builder-style object to manufacture [`DeleteCoipCidrInput`](crate::operation::delete_coip_cidr::DeleteCoipCidrInput).
    pub fn builder() -> crate::operation::delete_coip_cidr::builders::DeleteCoipCidrInputBuilder {
        crate::operation::delete_coip_cidr::builders::DeleteCoipCidrInputBuilder::default()
    }
}

/// A builder for [`DeleteCoipCidrInput`](crate::operation::delete_coip_cidr::DeleteCoipCidrInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCoipCidrInputBuilder {
    pub(crate) cidr: ::std::option::Option<::std::string::String>,
    pub(crate) coip_pool_id: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DeleteCoipCidrInputBuilder {
    /// <p>A customer-owned IP address range that you want to delete.</p>
    /// This field is required.
    pub fn cidr(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cidr = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A customer-owned IP address range that you want to delete.</p>
    pub fn set_cidr(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cidr = input;
        self
    }
    /// <p>A customer-owned IP address range that you want to delete.</p>
    pub fn get_cidr(&self) -> &::std::option::Option<::std::string::String> {
        &self.cidr
    }
    /// <p>The ID of the customer-owned address pool.</p>
    /// This field is required.
    pub fn coip_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.coip_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the customer-owned address pool.</p>
    pub fn set_coip_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.coip_pool_id = input;
        self
    }
    /// <p>The ID of the customer-owned address pool.</p>
    pub fn get_coip_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.coip_pool_id
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
    /// Consumes the builder and constructs a [`DeleteCoipCidrInput`](crate::operation::delete_coip_cidr::DeleteCoipCidrInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_coip_cidr::DeleteCoipCidrInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_coip_cidr::DeleteCoipCidrInput {
            cidr: self.cidr,
            coip_pool_id: self.coip_pool_id,
            dry_run: self.dry_run,
        })
    }
}
