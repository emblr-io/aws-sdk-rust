// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Raised when an argument in a request is not supported.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IllegalArgumentException {
    /// <p>A detailed message describing the problem.</p>
    pub detailed_message: ::std::string::String,
    /// <p>The ID of the request in question.</p>
    pub request_id: ::std::string::String,
    /// <p>The HTTP status code returned with the exception.</p>
    pub code: ::std::string::String,
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl IllegalArgumentException {
    /// <p>A detailed message describing the problem.</p>
    pub fn detailed_message(&self) -> &str {
        use std::ops::Deref;
        self.detailed_message.deref()
    }
    /// <p>The ID of the request in question.</p>
    pub fn request_id(&self) -> &str {
        use std::ops::Deref;
        self.request_id.deref()
    }
    /// <p>The HTTP status code returned with the exception.</p>
    pub fn code(&self) -> &str {
        use std::ops::Deref;
        self.code.deref()
    }
}
impl IllegalArgumentException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for IllegalArgumentException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "IllegalArgumentException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for IllegalArgumentException {}
impl ::aws_types::request_id::RequestId for crate::types::error::IllegalArgumentException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for IllegalArgumentException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl IllegalArgumentException {
    /// Creates a new builder-style object to manufacture [`IllegalArgumentException`](crate::types::error::IllegalArgumentException).
    pub fn builder() -> crate::types::error::builders::IllegalArgumentExceptionBuilder {
        crate::types::error::builders::IllegalArgumentExceptionBuilder::default()
    }
}

/// A builder for [`IllegalArgumentException`](crate::types::error::IllegalArgumentException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IllegalArgumentExceptionBuilder {
    pub(crate) detailed_message: ::std::option::Option<::std::string::String>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl IllegalArgumentExceptionBuilder {
    /// <p>A detailed message describing the problem.</p>
    /// This field is required.
    pub fn detailed_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.detailed_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A detailed message describing the problem.</p>
    pub fn set_detailed_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.detailed_message = input;
        self
    }
    /// <p>A detailed message describing the problem.</p>
    pub fn get_detailed_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.detailed_message
    }
    /// <p>The ID of the request in question.</p>
    /// This field is required.
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the request in question.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The ID of the request in question.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The HTTP status code returned with the exception.</p>
    /// This field is required.
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HTTP status code returned with the exception.</p>
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// <p>The HTTP status code returned with the exception.</p>
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Sets error metadata
    pub fn meta(mut self, meta: ::aws_smithy_types::error::ErrorMetadata) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Sets error metadata
    pub fn set_meta(&mut self, meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>) -> &mut Self {
        self.meta = meta;
        self
    }
    /// Consumes the builder and constructs a [`IllegalArgumentException`](crate::types::error::IllegalArgumentException).
    /// This method will fail if any of the following fields are not set:
    /// - [`detailed_message`](crate::types::error::builders::IllegalArgumentExceptionBuilder::detailed_message)
    /// - [`request_id`](crate::types::error::builders::IllegalArgumentExceptionBuilder::request_id)
    /// - [`code`](crate::types::error::builders::IllegalArgumentExceptionBuilder::code)
    pub fn build(self) -> ::std::result::Result<crate::types::error::IllegalArgumentException, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::error::IllegalArgumentException {
            detailed_message: self.detailed_message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "detailed_message",
                    "detailed_message was not specified but it is required when building IllegalArgumentException",
                )
            })?,
            request_id: self.request_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "request_id",
                    "request_id was not specified but it is required when building IllegalArgumentException",
                )
            })?,
            code: self.code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "code",
                    "code was not specified but it is required when building IllegalArgumentException",
                )
            })?,
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        })
    }
}
