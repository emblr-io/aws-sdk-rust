// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to retrieve information about an email address that's on the suppression list for your account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSuppressedDestinationInput {
    /// <p>The email address that's on the account suppression list.</p>
    pub email_address: ::std::option::Option<::std::string::String>,
}
impl GetSuppressedDestinationInput {
    /// <p>The email address that's on the account suppression list.</p>
    pub fn email_address(&self) -> ::std::option::Option<&str> {
        self.email_address.as_deref()
    }
}
impl GetSuppressedDestinationInput {
    /// Creates a new builder-style object to manufacture [`GetSuppressedDestinationInput`](crate::operation::get_suppressed_destination::GetSuppressedDestinationInput).
    pub fn builder() -> crate::operation::get_suppressed_destination::builders::GetSuppressedDestinationInputBuilder {
        crate::operation::get_suppressed_destination::builders::GetSuppressedDestinationInputBuilder::default()
    }
}

/// A builder for [`GetSuppressedDestinationInput`](crate::operation::get_suppressed_destination::GetSuppressedDestinationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSuppressedDestinationInputBuilder {
    pub(crate) email_address: ::std::option::Option<::std::string::String>,
}
impl GetSuppressedDestinationInputBuilder {
    /// <p>The email address that's on the account suppression list.</p>
    /// This field is required.
    pub fn email_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email address that's on the account suppression list.</p>
    pub fn set_email_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email_address = input;
        self
    }
    /// <p>The email address that's on the account suppression list.</p>
    pub fn get_email_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.email_address
    }
    /// Consumes the builder and constructs a [`GetSuppressedDestinationInput`](crate::operation::get_suppressed_destination::GetSuppressedDestinationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_suppressed_destination::GetSuppressedDestinationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_suppressed_destination::GetSuppressedDestinationInput {
            email_address: self.email_address,
        })
    }
}
