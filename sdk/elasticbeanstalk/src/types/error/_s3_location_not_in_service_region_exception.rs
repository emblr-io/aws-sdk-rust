// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The specified S3 bucket does not belong to the S3 region in which the service is running. The following regions are supported:</p>
/// <ul>
/// <li>
/// <p>IAD/us-east-1</p></li>
/// <li>
/// <p>PDX/us-west-2</p></li>
/// <li>
/// <p>DUB/eu-west-1</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3LocationNotInServiceRegionException {
    /// <p>The exception error message.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl S3LocationNotInServiceRegionException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for S3LocationNotInServiceRegionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "S3LocationNotInServiceRegionException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for S3LocationNotInServiceRegionException {}
impl ::aws_types::request_id::RequestId for crate::types::error::S3LocationNotInServiceRegionException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for S3LocationNotInServiceRegionException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl S3LocationNotInServiceRegionException {
    /// Creates a new builder-style object to manufacture [`S3LocationNotInServiceRegionException`](crate::types::error::S3LocationNotInServiceRegionException).
    pub fn builder() -> crate::types::error::builders::S3LocationNotInServiceRegionExceptionBuilder {
        crate::types::error::builders::S3LocationNotInServiceRegionExceptionBuilder::default()
    }
}

/// A builder for [`S3LocationNotInServiceRegionException`](crate::types::error::S3LocationNotInServiceRegionException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3LocationNotInServiceRegionExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl S3LocationNotInServiceRegionExceptionBuilder {
    /// <p>The exception error message.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The exception error message.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The exception error message.</p>
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
    /// Consumes the builder and constructs a [`S3LocationNotInServiceRegionException`](crate::types::error::S3LocationNotInServiceRegionException).
    pub fn build(self) -> crate::types::error::S3LocationNotInServiceRegionException {
        crate::types::error::S3LocationNotInServiceRegionException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
