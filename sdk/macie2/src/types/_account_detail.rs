// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the details of an account to associate with an Amazon Macie administrator account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccountDetail {
    /// <p>The Amazon Web Services account ID for the account.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The email address for the account.</p>
    pub email: ::std::option::Option<::std::string::String>,
}
impl AccountDetail {
    /// <p>The Amazon Web Services account ID for the account.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The email address for the account.</p>
    pub fn email(&self) -> ::std::option::Option<&str> {
        self.email.as_deref()
    }
}
impl AccountDetail {
    /// Creates a new builder-style object to manufacture [`AccountDetail`](crate::types::AccountDetail).
    pub fn builder() -> crate::types::builders::AccountDetailBuilder {
        crate::types::builders::AccountDetailBuilder::default()
    }
}

/// A builder for [`AccountDetail`](crate::types::AccountDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccountDetailBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) email: ::std::option::Option<::std::string::String>,
}
impl AccountDetailBuilder {
    /// <p>The Amazon Web Services account ID for the account.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID for the account.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID for the account.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The email address for the account.</p>
    /// This field is required.
    pub fn email(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email address for the account.</p>
    pub fn set_email(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email = input;
        self
    }
    /// <p>The email address for the account.</p>
    pub fn get_email(&self) -> &::std::option::Option<::std::string::String> {
        &self.email
    }
    /// Consumes the builder and constructs a [`AccountDetail`](crate::types::AccountDetail).
    pub fn build(self) -> crate::types::AccountDetail {
        crate::types::AccountDetail {
            account_id: self.account_id,
            email: self.email,
        }
    }
}
