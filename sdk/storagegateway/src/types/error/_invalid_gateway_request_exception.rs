// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An exception occurred because an invalid gateway request was issued to the service. For more information, see the error and message fields.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InvalidGatewayRequestException {
    /// <p>A human-readable message describing the error that occurred.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>A <code>StorageGatewayError</code> that provides more detail about the cause of the error.</p>
    pub error: ::std::option::Option<crate::types::StorageGatewayError>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl InvalidGatewayRequestException {
    /// <p>A <code>StorageGatewayError</code> that provides more detail about the cause of the error.</p>
    pub fn error(&self) -> ::std::option::Option<&crate::types::StorageGatewayError> {
        self.error.as_ref()
    }
}
impl InvalidGatewayRequestException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for InvalidGatewayRequestException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "InvalidGatewayRequestException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for InvalidGatewayRequestException {}
impl ::aws_types::request_id::RequestId for crate::types::error::InvalidGatewayRequestException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for InvalidGatewayRequestException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl InvalidGatewayRequestException {
    /// Creates a new builder-style object to manufacture [`InvalidGatewayRequestException`](crate::types::error::InvalidGatewayRequestException).
    pub fn builder() -> crate::types::error::builders::InvalidGatewayRequestExceptionBuilder {
        crate::types::error::builders::InvalidGatewayRequestExceptionBuilder::default()
    }
}

/// A builder for [`InvalidGatewayRequestException`](crate::types::error::InvalidGatewayRequestException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InvalidGatewayRequestExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) error: ::std::option::Option<crate::types::StorageGatewayError>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl InvalidGatewayRequestExceptionBuilder {
    /// <p>A human-readable message describing the error that occurred.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A human-readable message describing the error that occurred.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A human-readable message describing the error that occurred.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>A <code>StorageGatewayError</code> that provides more detail about the cause of the error.</p>
    pub fn error(mut self, input: crate::types::StorageGatewayError) -> Self {
        self.error = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>StorageGatewayError</code> that provides more detail about the cause of the error.</p>
    pub fn set_error(mut self, input: ::std::option::Option<crate::types::StorageGatewayError>) -> Self {
        self.error = input;
        self
    }
    /// <p>A <code>StorageGatewayError</code> that provides more detail about the cause of the error.</p>
    pub fn get_error(&self) -> &::std::option::Option<crate::types::StorageGatewayError> {
        &self.error
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
    /// Consumes the builder and constructs a [`InvalidGatewayRequestException`](crate::types::error::InvalidGatewayRequestException).
    pub fn build(self) -> crate::types::error::InvalidGatewayRequestException {
        crate::types::error::InvalidGatewayRequestException {
            message: self.message,
            error: self.error,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
