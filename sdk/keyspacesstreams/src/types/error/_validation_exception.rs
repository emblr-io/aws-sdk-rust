// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request validation failed because one or more input parameters failed validation.</p>
/// <p>This exception occurs when there are syntax errors in the request, field constraints are violated, or required parameters are missing. To help you fix the issue, the exception message provides details about which parameter failed and why.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ValidationException {
    /// <p>The input fails to satisfy the constraints specified by the service. Check the error details and modify your request.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>An error occurred validating your request. See the error message for details.</p>
    pub error_code: ::std::option::Option<crate::types::ValidationExceptionType>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl ValidationException {
    /// <p>An error occurred validating your request. See the error message for details.</p>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::ValidationExceptionType> {
        self.error_code.as_ref()
    }
}
impl ValidationException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for ValidationException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "ValidationException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for ValidationException {}
impl ::aws_types::request_id::RequestId for crate::types::error::ValidationException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for ValidationException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl ValidationException {
    /// Creates a new builder-style object to manufacture [`ValidationException`](crate::types::error::ValidationException).
    pub fn builder() -> crate::types::error::builders::ValidationExceptionBuilder {
        crate::types::error::builders::ValidationExceptionBuilder::default()
    }
}

/// A builder for [`ValidationException`](crate::types::error::ValidationException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ValidationExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<crate::types::ValidationExceptionType>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl ValidationExceptionBuilder {
    /// <p>The input fails to satisfy the constraints specified by the service. Check the error details and modify your request.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The input fails to satisfy the constraints specified by the service. Check the error details and modify your request.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The input fails to satisfy the constraints specified by the service. Check the error details and modify your request.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>An error occurred validating your request. See the error message for details.</p>
    pub fn error_code(mut self, input: crate::types::ValidationExceptionType) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>An error occurred validating your request. See the error message for details.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::ValidationExceptionType>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>An error occurred validating your request. See the error message for details.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::ValidationExceptionType> {
        &self.error_code
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
    /// Consumes the builder and constructs a [`ValidationException`](crate::types::error::ValidationException).
    pub fn build(self) -> crate::types::error::ValidationException {
        crate::types::error::ValidationException {
            message: self.message,
            error_code: self.error_code,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
