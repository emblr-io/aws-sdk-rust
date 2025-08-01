// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about an email address.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EmailAddress {
    /// <p>The email address.</p>
    pub email: ::std::option::Option<::std::string::String>,
    /// <p>Whether the email address has been verified.</p>
    pub verified: ::std::option::Option<bool>,
}
impl EmailAddress {
    /// <p>The email address.</p>
    pub fn email(&self) -> ::std::option::Option<&str> {
        self.email.as_deref()
    }
    /// <p>Whether the email address has been verified.</p>
    pub fn verified(&self) -> ::std::option::Option<bool> {
        self.verified
    }
}
impl EmailAddress {
    /// Creates a new builder-style object to manufacture [`EmailAddress`](crate::types::EmailAddress).
    pub fn builder() -> crate::types::builders::EmailAddressBuilder {
        crate::types::builders::EmailAddressBuilder::default()
    }
}

/// A builder for [`EmailAddress`](crate::types::EmailAddress).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EmailAddressBuilder {
    pub(crate) email: ::std::option::Option<::std::string::String>,
    pub(crate) verified: ::std::option::Option<bool>,
}
impl EmailAddressBuilder {
    /// <p>The email address.</p>
    pub fn email(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email address.</p>
    pub fn set_email(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email = input;
        self
    }
    /// <p>The email address.</p>
    pub fn get_email(&self) -> &::std::option::Option<::std::string::String> {
        &self.email
    }
    /// <p>Whether the email address has been verified.</p>
    pub fn verified(mut self, input: bool) -> Self {
        self.verified = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether the email address has been verified.</p>
    pub fn set_verified(mut self, input: ::std::option::Option<bool>) -> Self {
        self.verified = input;
        self
    }
    /// <p>Whether the email address has been verified.</p>
    pub fn get_verified(&self) -> &::std::option::Option<bool> {
        &self.verified
    }
    /// Consumes the builder and constructs a [`EmailAddress`](crate::types::EmailAddress).
    pub fn build(self) -> crate::types::EmailAddress {
        crate::types::EmailAddress {
            email: self.email,
            verified: self.verified,
        }
    }
}
