// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAccountAliasInput {
    /// <p>The name of the account alias to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of lowercase letters, digits, and dashes. You cannot start or finish with a dash, nor can you have two dashes in a row.</p>
    pub account_alias: ::std::option::Option<::std::string::String>,
}
impl DeleteAccountAliasInput {
    /// <p>The name of the account alias to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of lowercase letters, digits, and dashes. You cannot start or finish with a dash, nor can you have two dashes in a row.</p>
    pub fn account_alias(&self) -> ::std::option::Option<&str> {
        self.account_alias.as_deref()
    }
}
impl DeleteAccountAliasInput {
    /// Creates a new builder-style object to manufacture [`DeleteAccountAliasInput`](crate::operation::delete_account_alias::DeleteAccountAliasInput).
    pub fn builder() -> crate::operation::delete_account_alias::builders::DeleteAccountAliasInputBuilder {
        crate::operation::delete_account_alias::builders::DeleteAccountAliasInputBuilder::default()
    }
}

/// A builder for [`DeleteAccountAliasInput`](crate::operation::delete_account_alias::DeleteAccountAliasInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAccountAliasInputBuilder {
    pub(crate) account_alias: ::std::option::Option<::std::string::String>,
}
impl DeleteAccountAliasInputBuilder {
    /// <p>The name of the account alias to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of lowercase letters, digits, and dashes. You cannot start or finish with a dash, nor can you have two dashes in a row.</p>
    /// This field is required.
    pub fn account_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the account alias to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of lowercase letters, digits, and dashes. You cannot start or finish with a dash, nor can you have two dashes in a row.</p>
    pub fn set_account_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_alias = input;
        self
    }
    /// <p>The name of the account alias to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of lowercase letters, digits, and dashes. You cannot start or finish with a dash, nor can you have two dashes in a row.</p>
    pub fn get_account_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_alias
    }
    /// Consumes the builder and constructs a [`DeleteAccountAliasInput`](crate::operation::delete_account_alias::DeleteAccountAliasInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_account_alias::DeleteAccountAliasInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_account_alias::DeleteAccountAliasInput {
            account_alias: self.account_alias,
        })
    }
}
