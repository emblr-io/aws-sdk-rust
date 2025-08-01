// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides error information about a schema conversion operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DefaultErrorDetails {
    /// <p>The error message.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl DefaultErrorDetails {
    /// <p>The error message.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl DefaultErrorDetails {
    /// Creates a new builder-style object to manufacture [`DefaultErrorDetails`](crate::types::DefaultErrorDetails).
    pub fn builder() -> crate::types::builders::DefaultErrorDetailsBuilder {
        crate::types::builders::DefaultErrorDetailsBuilder::default()
    }
}

/// A builder for [`DefaultErrorDetails`](crate::types::DefaultErrorDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DefaultErrorDetailsBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl DefaultErrorDetailsBuilder {
    /// <p>The error message.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The error message.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`DefaultErrorDetails`](crate::types::DefaultErrorDetails).
    pub fn build(self) -> crate::types::DefaultErrorDetails {
        crate::types::DefaultErrorDetails { message: self.message }
    }
}
