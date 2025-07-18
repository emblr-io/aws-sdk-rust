// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateFromAdministratorAccountInput {}
impl DisassociateFromAdministratorAccountInput {
    /// Creates a new builder-style object to manufacture [`DisassociateFromAdministratorAccountInput`](crate::operation::disassociate_from_administrator_account::DisassociateFromAdministratorAccountInput).
    pub fn builder() -> crate::operation::disassociate_from_administrator_account::builders::DisassociateFromAdministratorAccountInputBuilder {
        crate::operation::disassociate_from_administrator_account::builders::DisassociateFromAdministratorAccountInputBuilder::default()
    }
}

/// A builder for [`DisassociateFromAdministratorAccountInput`](crate::operation::disassociate_from_administrator_account::DisassociateFromAdministratorAccountInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateFromAdministratorAccountInputBuilder {}
impl DisassociateFromAdministratorAccountInputBuilder {
    /// Consumes the builder and constructs a [`DisassociateFromAdministratorAccountInput`](crate::operation::disassociate_from_administrator_account::DisassociateFromAdministratorAccountInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_from_administrator_account::DisassociateFromAdministratorAccountInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::disassociate_from_administrator_account::DisassociateFromAdministratorAccountInput {})
    }
}
