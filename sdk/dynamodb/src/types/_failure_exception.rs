// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a failure a contributor insights operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FailureException {
    /// <p>Exception name.</p>
    pub exception_name: ::std::option::Option<::std::string::String>,
    /// <p>Description of the failure.</p>
    pub exception_description: ::std::option::Option<::std::string::String>,
}
impl FailureException {
    /// <p>Exception name.</p>
    pub fn exception_name(&self) -> ::std::option::Option<&str> {
        self.exception_name.as_deref()
    }
    /// <p>Description of the failure.</p>
    pub fn exception_description(&self) -> ::std::option::Option<&str> {
        self.exception_description.as_deref()
    }
}
impl FailureException {
    /// Creates a new builder-style object to manufacture [`FailureException`](crate::types::FailureException).
    pub fn builder() -> crate::types::builders::FailureExceptionBuilder {
        crate::types::builders::FailureExceptionBuilder::default()
    }
}

/// A builder for [`FailureException`](crate::types::FailureException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FailureExceptionBuilder {
    pub(crate) exception_name: ::std::option::Option<::std::string::String>,
    pub(crate) exception_description: ::std::option::Option<::std::string::String>,
}
impl FailureExceptionBuilder {
    /// <p>Exception name.</p>
    pub fn exception_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.exception_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Exception name.</p>
    pub fn set_exception_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.exception_name = input;
        self
    }
    /// <p>Exception name.</p>
    pub fn get_exception_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.exception_name
    }
    /// <p>Description of the failure.</p>
    pub fn exception_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.exception_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Description of the failure.</p>
    pub fn set_exception_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.exception_description = input;
        self
    }
    /// <p>Description of the failure.</p>
    pub fn get_exception_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.exception_description
    }
    /// Consumes the builder and constructs a [`FailureException`](crate::types::FailureException).
    pub fn build(self) -> crate::types::FailureException {
        crate::types::FailureException {
            exception_name: self.exception_name,
            exception_description: self.exception_description,
        }
    }
}
