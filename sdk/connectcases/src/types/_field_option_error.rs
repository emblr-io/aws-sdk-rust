// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Object for field Options errors.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FieldOptionError {
    /// <p>Error message from creating or updating field option.</p>
    pub message: ::std::string::String,
    /// <p>Error code from creating or updating field option.</p>
    pub error_code: ::std::string::String,
    /// <p>The field option value that caused the error.</p>
    pub value: ::std::string::String,
}
impl FieldOptionError {
    /// <p>Error message from creating or updating field option.</p>
    pub fn message(&self) -> &str {
        use std::ops::Deref;
        self.message.deref()
    }
    /// <p>Error code from creating or updating field option.</p>
    pub fn error_code(&self) -> &str {
        use std::ops::Deref;
        self.error_code.deref()
    }
    /// <p>The field option value that caused the error.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
}
impl FieldOptionError {
    /// Creates a new builder-style object to manufacture [`FieldOptionError`](crate::types::FieldOptionError).
    pub fn builder() -> crate::types::builders::FieldOptionErrorBuilder {
        crate::types::builders::FieldOptionErrorBuilder::default()
    }
}

/// A builder for [`FieldOptionError`](crate::types::FieldOptionError).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FieldOptionErrorBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl FieldOptionErrorBuilder {
    /// <p>Error message from creating or updating field option.</p>
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Error message from creating or updating field option.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>Error message from creating or updating field option.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>Error code from creating or updating field option.</p>
    /// This field is required.
    pub fn error_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Error code from creating or updating field option.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>Error code from creating or updating field option.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_code
    }
    /// <p>The field option value that caused the error.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The field option value that caused the error.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The field option value that caused the error.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`FieldOptionError`](crate::types::FieldOptionError).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::builders::FieldOptionErrorBuilder::message)
    /// - [`error_code`](crate::types::builders::FieldOptionErrorBuilder::error_code)
    /// - [`value`](crate::types::builders::FieldOptionErrorBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::FieldOptionError, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FieldOptionError {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building FieldOptionError",
                )
            })?,
            error_code: self.error_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "error_code",
                    "error_code was not specified but it is required when building FieldOptionError",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building FieldOptionError",
                )
            })?,
        })
    }
}
