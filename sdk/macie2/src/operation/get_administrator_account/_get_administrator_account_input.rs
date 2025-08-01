// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAdministratorAccountInput {}
impl GetAdministratorAccountInput {
    /// Creates a new builder-style object to manufacture [`GetAdministratorAccountInput`](crate::operation::get_administrator_account::GetAdministratorAccountInput).
    pub fn builder() -> crate::operation::get_administrator_account::builders::GetAdministratorAccountInputBuilder {
        crate::operation::get_administrator_account::builders::GetAdministratorAccountInputBuilder::default()
    }
}

/// A builder for [`GetAdministratorAccountInput`](crate::operation::get_administrator_account::GetAdministratorAccountInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAdministratorAccountInputBuilder {}
impl GetAdministratorAccountInputBuilder {
    /// Consumes the builder and constructs a [`GetAdministratorAccountInput`](crate::operation::get_administrator_account::GetAdministratorAccountInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_administrator_account::GetAdministratorAccountInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_administrator_account::GetAdministratorAccountInput {})
    }
}
