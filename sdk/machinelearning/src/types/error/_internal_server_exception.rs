// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An error on the server occurred when trying to process a request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InternalServerException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub code: i32,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl InternalServerException {
    #[allow(missing_docs)] // documentation missing in model
    pub fn code(&self) -> i32 {
        self.code
    }
}
impl InternalServerException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for InternalServerException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "InternalServerException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for InternalServerException {}
impl ::aws_types::request_id::RequestId for crate::types::error::InternalServerException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for InternalServerException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl InternalServerException {
    /// Creates a new builder-style object to manufacture [`InternalServerException`](crate::types::error::InternalServerException).
    pub fn builder() -> crate::types::error::builders::InternalServerExceptionBuilder {
        crate::types::error::builders::InternalServerExceptionBuilder::default()
    }
}

/// A builder for [`InternalServerException`](crate::types::error::InternalServerException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InternalServerExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) code: ::std::option::Option<i32>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl InternalServerExceptionBuilder {
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
    #[allow(missing_docs)] // documentation missing in model
    pub fn code(mut self, input: i32) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_code(mut self, input: ::std::option::Option<i32>) -> Self {
        self.code = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_code(&self) -> &::std::option::Option<i32> {
        &self.code
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
    /// Consumes the builder and constructs a [`InternalServerException`](crate::types::error::InternalServerException).
    pub fn build(self) -> crate::types::error::InternalServerException {
        crate::types::error::InternalServerException {
            message: self.message,
            code: self.code.unwrap_or_default(),
            meta: self.meta.unwrap_or_default(),
        }
    }
}
