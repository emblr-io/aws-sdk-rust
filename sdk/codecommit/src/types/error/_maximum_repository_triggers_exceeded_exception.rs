// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The number of triggers allowed for the repository was exceeded.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MaximumRepositoryTriggersExceededException {
    /// <p>Any message associated with the exception.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl MaximumRepositoryTriggersExceededException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for MaximumRepositoryTriggersExceededException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "MaximumRepositoryTriggersExceededException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for MaximumRepositoryTriggersExceededException {}
impl ::aws_types::request_id::RequestId for crate::types::error::MaximumRepositoryTriggersExceededException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for MaximumRepositoryTriggersExceededException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl MaximumRepositoryTriggersExceededException {
    /// Creates a new builder-style object to manufacture [`MaximumRepositoryTriggersExceededException`](crate::types::error::MaximumRepositoryTriggersExceededException).
    pub fn builder() -> crate::types::error::builders::MaximumRepositoryTriggersExceededExceptionBuilder {
        crate::types::error::builders::MaximumRepositoryTriggersExceededExceptionBuilder::default()
    }
}

/// A builder for [`MaximumRepositoryTriggersExceededException`](crate::types::error::MaximumRepositoryTriggersExceededException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MaximumRepositoryTriggersExceededExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl MaximumRepositoryTriggersExceededExceptionBuilder {
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
    /// Consumes the builder and constructs a [`MaximumRepositoryTriggersExceededException`](crate::types::error::MaximumRepositoryTriggersExceededException).
    pub fn build(self) -> crate::types::error::MaximumRepositoryTriggersExceededException {
        crate::types::error::MaximumRepositoryTriggersExceededException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
