// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The specified file does not exist. Verify that you have used the correct file name, full path, and extension.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FileDoesNotExistException {
    /// <p>Any message associated with the exception.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl FileDoesNotExistException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for FileDoesNotExistException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "FileDoesNotExistException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for FileDoesNotExistException {}
impl ::aws_types::request_id::RequestId for crate::types::error::FileDoesNotExistException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for FileDoesNotExistException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl FileDoesNotExistException {
    /// Creates a new builder-style object to manufacture [`FileDoesNotExistException`](crate::types::error::FileDoesNotExistException).
    pub fn builder() -> crate::types::error::builders::FileDoesNotExistExceptionBuilder {
        crate::types::error::builders::FileDoesNotExistExceptionBuilder::default()
    }
}

/// A builder for [`FileDoesNotExistException`](crate::types::error::FileDoesNotExistException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FileDoesNotExistExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl FileDoesNotExistExceptionBuilder {
    /// <p>Any message associated with the exception.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Any message associated with the exception.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>Any message associated with the exception.</p>
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
    /// Consumes the builder and constructs a [`FileDoesNotExistException`](crate::types::error::FileDoesNotExistException).
    pub fn build(self) -> crate::types::error::FileDoesNotExistException {
        crate::types::error::FileDoesNotExistException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
