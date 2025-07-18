// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Error messages for environment variables that couldn't be applied.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct EnvironmentError {
    /// <p>The error code.</p>
    pub error_code: ::std::option::Option<::std::string::String>,
    /// <p>The error message.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl EnvironmentError {
    /// <p>The error code.</p>
    pub fn error_code(&self) -> ::std::option::Option<&str> {
        self.error_code.as_deref()
    }
    /// <p>The error message.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Debug for EnvironmentError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EnvironmentError");
        formatter.field("error_code", &self.error_code);
        formatter.field("message", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl EnvironmentError {
    /// Creates a new builder-style object to manufacture [`EnvironmentError`](crate::types::EnvironmentError).
    pub fn builder() -> crate::types::builders::EnvironmentErrorBuilder {
        crate::types::builders::EnvironmentErrorBuilder::default()
    }
}

/// A builder for [`EnvironmentError`](crate::types::EnvironmentError).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct EnvironmentErrorBuilder {
    pub(crate) error_code: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl EnvironmentErrorBuilder {
    /// <p>The error code.</p>
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
    /// Consumes the builder and constructs a [`EnvironmentError`](crate::types::EnvironmentError).
    pub fn build(self) -> crate::types::EnvironmentError {
        crate::types::EnvironmentError {
            error_code: self.error_code,
            message: self.message,
        }
    }
}
impl ::std::fmt::Debug for EnvironmentErrorBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EnvironmentErrorBuilder");
        formatter.field("error_code", &self.error_code);
        formatter.field("message", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
