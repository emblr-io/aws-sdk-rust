// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This is an error field object that contains the error code and the reason for an operation failure.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ErrorInfo {
    /// <p>The error code for an invalid or failed operation.</p>
    pub code: ::std::option::Option<::std::string::String>,
    /// <p>The failure reason for the operation.</p>
    pub reason: ::std::option::Option<::std::string::String>,
}
impl ErrorInfo {
    /// <p>The error code for an invalid or failed operation.</p>
    pub fn code(&self) -> ::std::option::Option<&str> {
        self.code.as_deref()
    }
    /// <p>The failure reason for the operation.</p>
    pub fn reason(&self) -> ::std::option::Option<&str> {
        self.reason.as_deref()
    }
}
impl ErrorInfo {
    /// Creates a new builder-style object to manufacture [`ErrorInfo`](crate::types::ErrorInfo).
    pub fn builder() -> crate::types::builders::ErrorInfoBuilder {
        crate::types::builders::ErrorInfoBuilder::default()
    }
}

/// A builder for [`ErrorInfo`](crate::types::ErrorInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ErrorInfoBuilder {
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<::std::string::String>,
}
impl ErrorInfoBuilder {
    /// <p>The error code for an invalid or failed operation.</p>
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error code for an invalid or failed operation.</p>
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// <p>The error code for an invalid or failed operation.</p>
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    /// <p>The failure reason for the operation.</p>
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The failure reason for the operation.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason = input;
        self
    }
    /// <p>The failure reason for the operation.</p>
    pub fn get_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason
    }
    /// Consumes the builder and constructs a [`ErrorInfo`](crate::types::ErrorInfo).
    pub fn build(self) -> crate::types::ErrorInfo {
        crate::types::ErrorInfo {
            code: self.code,
            reason: self.reason,
        }
    }
}
