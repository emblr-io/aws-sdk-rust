// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The specified combination of HTTP verb and URI is not supported.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MethodNotAllowedException {
    /// <p>The message for the exception.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl MethodNotAllowedException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for MethodNotAllowedException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "MethodNotAllowedException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for MethodNotAllowedException {}
impl ::aws_types::request_id::RequestId for crate::types::error::MethodNotAllowedException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for MethodNotAllowedException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl MethodNotAllowedException {
    /// Creates a new builder-style object to manufacture [`MethodNotAllowedException`](crate::types::error::MethodNotAllowedException).
    pub fn builder() -> crate::types::error::builders::MethodNotAllowedExceptionBuilder {
        crate::types::error::builders::MethodNotAllowedExceptionBuilder::default()
    }
}

/// A builder for [`MethodNotAllowedException`](crate::types::error::MethodNotAllowedException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MethodNotAllowedExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl MethodNotAllowedExceptionBuilder {
    /// <p>The message for the exception.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message for the exception.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The message for the exception.</p>
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
    /// Consumes the builder and constructs a [`MethodNotAllowedException`](crate::types::error::MethodNotAllowedException).
    pub fn build(self) -> crate::types::error::MethodNotAllowedException {
        crate::types::error::MethodNotAllowedException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
