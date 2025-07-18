// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about about the account link.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccountLink {
    /// <p>The identifier of the account link.</p>
    pub account_link_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the account link.</p>
    pub account_link_status: ::std::option::Option<crate::types::AccountLinkStatusEnum>,
    /// <p>The identifier of the source account.</p>
    pub source_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the target account.</p>
    pub target_account_id: ::std::option::Option<::std::string::String>,
}
impl AccountLink {
    /// <p>The identifier of the account link.</p>
    pub fn account_link_id(&self) -> ::std::option::Option<&str> {
        self.account_link_id.as_deref()
    }
    /// <p>The status of the account link.</p>
    pub fn account_link_status(&self) -> ::std::option::Option<&crate::types::AccountLinkStatusEnum> {
        self.account_link_status.as_ref()
    }
    /// <p>The identifier of the source account.</p>
    pub fn source_account_id(&self) -> ::std::option::Option<&str> {
        self.source_account_id.as_deref()
    }
    /// <p>The identifier of the target account.</p>
    pub fn target_account_id(&self) -> ::std::option::Option<&str> {
        self.target_account_id.as_deref()
    }
}
impl AccountLink {
    /// Creates a new builder-style object to manufacture [`AccountLink`](crate::types::AccountLink).
    pub fn builder() -> crate::types::builders::AccountLinkBuilder {
        crate::types::builders::AccountLinkBuilder::default()
    }
}

/// A builder for [`AccountLink`](crate::types::AccountLink).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccountLinkBuilder {
    pub(crate) account_link_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_link_status: ::std::option::Option<crate::types::AccountLinkStatusEnum>,
    pub(crate) source_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) target_account_id: ::std::option::Option<::std::string::String>,
}
impl AccountLinkBuilder {
    /// <p>The identifier of the account link.</p>
    pub fn account_link_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_link_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the account link.</p>
    pub fn set_account_link_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_link_id = input;
        self
    }
    /// <p>The identifier of the account link.</p>
    pub fn get_account_link_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_link_id
    }
    /// <p>The status of the account link.</p>
    pub fn account_link_status(mut self, input: crate::types::AccountLinkStatusEnum) -> Self {
        self.account_link_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the account link.</p>
    pub fn set_account_link_status(mut self, input: ::std::option::Option<crate::types::AccountLinkStatusEnum>) -> Self {
        self.account_link_status = input;
        self
    }
    /// <p>The status of the account link.</p>
    pub fn get_account_link_status(&self) -> &::std::option::Option<crate::types::AccountLinkStatusEnum> {
        &self.account_link_status
    }
    /// <p>The identifier of the source account.</p>
    pub fn source_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the source account.</p>
    pub fn set_source_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_account_id = input;
        self
    }
    /// <p>The identifier of the source account.</p>
    pub fn get_source_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_account_id
    }
    /// <p>The identifier of the target account.</p>
    pub fn target_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the target account.</p>
    pub fn set_target_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_account_id = input;
        self
    }
    /// <p>The identifier of the target account.</p>
    pub fn get_target_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_account_id
    }
    /// Consumes the builder and constructs a [`AccountLink`](crate::types::AccountLink).
    pub fn build(self) -> crate::types::AccountLink {
        crate::types::AccountLink {
            account_link_id: self.account_link_id,
            account_link_status: self.account_link_status,
            source_account_id: self.source_account_id,
            target_account_id: self.target_account_id,
        }
    }
}
