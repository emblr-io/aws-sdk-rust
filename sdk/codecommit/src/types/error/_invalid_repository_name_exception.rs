// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A specified repository name is not valid.</p><note>
/// <p>This exception occurs only when a specified repository name is not valid. Other exceptions occur when a required repository parameter is missing, or when a specified repository does not exist.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InvalidRepositoryNameException {
    /// <p>Any message associated with the exception.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl InvalidRepositoryNameException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for InvalidRepositoryNameException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "InvalidRepositoryNameException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for InvalidRepositoryNameException {}
impl ::aws_types::request_id::RequestId for crate::types::error::InvalidRepositoryNameException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for InvalidRepositoryNameException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl InvalidRepositoryNameException {
    /// Creates a new builder-style object to manufacture [`InvalidRepositoryNameException`](crate::types::error::InvalidRepositoryNameException).
    pub fn builder() -> crate::types::error::builders::InvalidRepositoryNameExceptionBuilder {
        crate::types::error::builders::InvalidRepositoryNameExceptionBuilder::default()
    }
}

/// A builder for [`InvalidRepositoryNameException`](crate::types::error::InvalidRepositoryNameException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InvalidRepositoryNameExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl InvalidRepositoryNameExceptionBuilder {
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
    /// Consumes the builder and constructs a [`InvalidRepositoryNameException`](crate::types::error::InvalidRepositoryNameException).
    pub fn build(self) -> crate::types::error::InvalidRepositoryNameException {
        crate::types::error::InvalidRepositoryNameException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
