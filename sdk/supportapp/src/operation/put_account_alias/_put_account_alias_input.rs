// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutAccountAliasInput {
    /// <p>An alias or short name for an Amazon Web Services account.</p>
    pub account_alias: ::std::option::Option<::std::string::String>,
}
impl PutAccountAliasInput {
    /// <p>An alias or short name for an Amazon Web Services account.</p>
    pub fn account_alias(&self) -> ::std::option::Option<&str> {
        self.account_alias.as_deref()
    }
}
impl PutAccountAliasInput {
    /// Creates a new builder-style object to manufacture [`PutAccountAliasInput`](crate::operation::put_account_alias::PutAccountAliasInput).
    pub fn builder() -> crate::operation::put_account_alias::builders::PutAccountAliasInputBuilder {
        crate::operation::put_account_alias::builders::PutAccountAliasInputBuilder::default()
    }
}

/// A builder for [`PutAccountAliasInput`](crate::operation::put_account_alias::PutAccountAliasInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutAccountAliasInputBuilder {
    pub(crate) account_alias: ::std::option::Option<::std::string::String>,
}
impl PutAccountAliasInputBuilder {
    /// <p>An alias or short name for an Amazon Web Services account.</p>
    /// This field is required.
    pub fn account_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An alias or short name for an Amazon Web Services account.</p>
    pub fn set_account_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_alias = input;
        self
    }
    /// <p>An alias or short name for an Amazon Web Services account.</p>
    pub fn get_account_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_alias
    }
    /// Consumes the builder and constructs a [`PutAccountAliasInput`](crate::operation::put_account_alias::PutAccountAliasInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_account_alias::PutAccountAliasInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_account_alias::PutAccountAliasInput {
            account_alias: self.account_alias,
        })
    }
}
