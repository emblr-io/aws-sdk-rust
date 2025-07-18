// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A federation source failed, but the operation may be retried.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FederationSourceRetryableException {
    /// <p>A message describing the problem.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl FederationSourceRetryableException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for FederationSourceRetryableException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "FederationSourceRetryableException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for FederationSourceRetryableException {}
impl ::aws_types::request_id::RequestId for crate::types::error::FederationSourceRetryableException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for FederationSourceRetryableException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl FederationSourceRetryableException {
    /// Creates a new builder-style object to manufacture [`FederationSourceRetryableException`](crate::types::error::FederationSourceRetryableException).
    pub fn builder() -> crate::types::error::builders::FederationSourceRetryableExceptionBuilder {
        crate::types::error::builders::FederationSourceRetryableExceptionBuilder::default()
    }
}

/// A builder for [`FederationSourceRetryableException`](crate::types::error::FederationSourceRetryableException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FederationSourceRetryableExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl FederationSourceRetryableExceptionBuilder {
    /// <p>A message describing the problem.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message describing the problem.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message describing the problem.</p>
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
    /// Consumes the builder and constructs a [`FederationSourceRetryableException`](crate::types::error::FederationSourceRetryableException).
    pub fn build(self) -> crate::types::error::FederationSourceRetryableException {
        crate::types::error::FederationSourceRetryableException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
