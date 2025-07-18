// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAccountPreferencesInput {}
impl GetAccountPreferencesInput {
    /// Creates a new builder-style object to manufacture [`GetAccountPreferencesInput`](crate::operation::get_account_preferences::GetAccountPreferencesInput).
    pub fn builder() -> crate::operation::get_account_preferences::builders::GetAccountPreferencesInputBuilder {
        crate::operation::get_account_preferences::builders::GetAccountPreferencesInputBuilder::default()
    }
}

/// A builder for [`GetAccountPreferencesInput`](crate::operation::get_account_preferences::GetAccountPreferencesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAccountPreferencesInputBuilder {}
impl GetAccountPreferencesInputBuilder {
    /// Consumes the builder and constructs a [`GetAccountPreferencesInput`](crate::operation::get_account_preferences::GetAccountPreferencesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_account_preferences::GetAccountPreferencesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_account_preferences::GetAccountPreferencesInput {})
    }
}
