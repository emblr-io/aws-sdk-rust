// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The specified directory has already been shared with this Amazon Web Services account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DirectoryAlreadySharedException {
    /// <p>The descriptive message for the exception.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services request identifier.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl DirectoryAlreadySharedException {
    /// <p>The Amazon Web Services request identifier.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
}
impl DirectoryAlreadySharedException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for DirectoryAlreadySharedException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "DirectoryAlreadySharedException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for DirectoryAlreadySharedException {}
impl ::aws_types::request_id::RequestId for crate::types::error::DirectoryAlreadySharedException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for DirectoryAlreadySharedException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl DirectoryAlreadySharedException {
    /// Creates a new builder-style object to manufacture [`DirectoryAlreadySharedException`](crate::types::error::DirectoryAlreadySharedException).
    pub fn builder() -> crate::types::error::builders::DirectoryAlreadySharedExceptionBuilder {
        crate::types::error::builders::DirectoryAlreadySharedExceptionBuilder::default()
    }
}

/// A builder for [`DirectoryAlreadySharedException`](crate::types::error::DirectoryAlreadySharedException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DirectoryAlreadySharedExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl DirectoryAlreadySharedExceptionBuilder {
    /// <p>The descriptive message for the exception.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The descriptive message for the exception.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The descriptive message for the exception.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>The Amazon Web Services request identifier.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services request identifier.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The Amazon Web Services request identifier.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
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
    /// Consumes the builder and constructs a [`DirectoryAlreadySharedException`](crate::types::error::DirectoryAlreadySharedException).
    pub fn build(self) -> crate::types::error::DirectoryAlreadySharedException {
        crate::types::error::DirectoryAlreadySharedException {
            message: self.message,
            request_id: self.request_id,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
