// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetChangeTokenInput {}
impl GetChangeTokenInput {
    /// Creates a new builder-style object to manufacture [`GetChangeTokenInput`](crate::operation::get_change_token::GetChangeTokenInput).
    pub fn builder() -> crate::operation::get_change_token::builders::GetChangeTokenInputBuilder {
        crate::operation::get_change_token::builders::GetChangeTokenInputBuilder::default()
    }
}

/// A builder for [`GetChangeTokenInput`](crate::operation::get_change_token::GetChangeTokenInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetChangeTokenInputBuilder {}
impl GetChangeTokenInputBuilder {
    /// Consumes the builder and constructs a [`GetChangeTokenInput`](crate::operation::get_change_token::GetChangeTokenInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_change_token::GetChangeTokenInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_change_token::GetChangeTokenInput {})
    }
}
