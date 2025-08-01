// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains details about an error related to retrieving tags.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagsError {
    /// <p>The error code.</p>
    pub error_code: ::std::string::String,
    /// <p>The error message.</p>
    pub message: ::std::string::String,
}
impl TagsError {
    /// <p>The error code.</p>
    pub fn error_code(&self) -> &str {
        use std::ops::Deref;
        self.error_code.deref()
    }
    /// <p>The error message.</p>
    pub fn message(&self) -> &str {
        use std::ops::Deref;
        self.message.deref()
    }
}
impl TagsError {
    /// Creates a new builder-style object to manufacture [`TagsError`](crate::types::TagsError).
    pub fn builder() -> crate::types::builders::TagsErrorBuilder {
        crate::types::builders::TagsErrorBuilder::default()
    }
}

/// A builder for [`TagsError`](crate::types::TagsError).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagsErrorBuilder {
    pub(crate) error_code: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl TagsErrorBuilder {
    /// <p>The error code.</p>
    /// This field is required.
    pub fn error_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error code.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The error code.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_code
    }
    /// <p>The error message.</p>
    /// This field is required.
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
    /// Consumes the builder and constructs a [`TagsError`](crate::types::TagsError).
    /// This method will fail if any of the following fields are not set:
    /// - [`error_code`](crate::types::builders::TagsErrorBuilder::error_code)
    /// - [`message`](crate::types::builders::TagsErrorBuilder::message)
    pub fn build(self) -> ::std::result::Result<crate::types::TagsError, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TagsError {
            error_code: self.error_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "error_code",
                    "error_code was not specified but it is required when building TagsError",
                )
            })?,
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building TagsError",
                )
            })?,
        })
    }
}
