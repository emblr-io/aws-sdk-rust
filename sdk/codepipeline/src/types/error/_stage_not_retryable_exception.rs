// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Unable to retry. The pipeline structure or stage state might have changed while actions awaited retry, or the stage contains no failed actions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StageNotRetryableException {
    /// <p>The message provided to the user in the event of an exception.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl StageNotRetryableException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for StageNotRetryableException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "StageNotRetryableException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for StageNotRetryableException {}
impl ::aws_types::request_id::RequestId for crate::types::error::StageNotRetryableException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for StageNotRetryableException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl StageNotRetryableException {
    /// Creates a new builder-style object to manufacture [`StageNotRetryableException`](crate::types::error::StageNotRetryableException).
    pub fn builder() -> crate::types::error::builders::StageNotRetryableExceptionBuilder {
        crate::types::error::builders::StageNotRetryableExceptionBuilder::default()
    }
}

/// A builder for [`StageNotRetryableException`](crate::types::error::StageNotRetryableException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StageNotRetryableExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl StageNotRetryableExceptionBuilder {
    /// <p>The message provided to the user in the event of an exception.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message provided to the user in the event of an exception.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The message provided to the user in the event of an exception.</p>
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
    /// Consumes the builder and constructs a [`StageNotRetryableException`](crate::types::error::StageNotRetryableException).
    pub fn build(self) -> crate::types::error::StageNotRetryableException {
        crate::types::error::StageNotRetryableException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
