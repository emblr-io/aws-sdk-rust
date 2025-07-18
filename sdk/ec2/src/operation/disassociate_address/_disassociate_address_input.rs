// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateAddressInput {
    /// <p>The association ID. This parameter is required.</p>
    pub association_id: ::std::option::Option<::std::string::String>,
    /// <p>Deprecated.</p>
    pub public_ip: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DisassociateAddressInput {
    /// <p>The association ID. This parameter is required.</p>
    pub fn association_id(&self) -> ::std::option::Option<&str> {
        self.association_id.as_deref()
    }
    /// <p>Deprecated.</p>
    pub fn public_ip(&self) -> ::std::option::Option<&str> {
        self.public_ip.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DisassociateAddressInput {
    /// Creates a new builder-style object to manufacture [`DisassociateAddressInput`](crate::operation::disassociate_address::DisassociateAddressInput).
    pub fn builder() -> crate::operation::disassociate_address::builders::DisassociateAddressInputBuilder {
        crate::operation::disassociate_address::builders::DisassociateAddressInputBuilder::default()
    }
}

/// A builder for [`DisassociateAddressInput`](crate::operation::disassociate_address::DisassociateAddressInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateAddressInputBuilder {
    pub(crate) association_id: ::std::option::Option<::std::string::String>,
    pub(crate) public_ip: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DisassociateAddressInputBuilder {
    /// <p>The association ID. This parameter is required.</p>
    pub fn association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The association ID. This parameter is required.</p>
    pub fn set_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.association_id = input;
        self
    }
    /// <p>The association ID. This parameter is required.</p>
    pub fn get_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.association_id
    }
    /// <p>Deprecated.</p>
    pub fn public_ip(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.public_ip = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Deprecated.</p>
    pub fn set_public_ip(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.public_ip = input;
        self
    }
    /// <p>Deprecated.</p>
    pub fn get_public_ip(&self) -> &::std::option::Option<::std::string::String> {
        &self.public_ip
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
    /// Consumes the builder and constructs a [`DisassociateAddressInput`](crate::operation::disassociate_address::DisassociateAddressInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::disassociate_address::DisassociateAddressInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::disassociate_address::DisassociateAddressInput {
            association_id: self.association_id,
            public_ip: self.public_ip,
            dry_run: self.dry_run,
        })
    }
}
