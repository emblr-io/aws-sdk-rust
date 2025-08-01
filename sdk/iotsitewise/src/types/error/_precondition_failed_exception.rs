// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The precondition in one or more of the request-header fields evaluated to <code>FALSE</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PreconditionFailedException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::string::String,
    /// <p>The ID of the resource on which precondition failed with this operation.</p>
    pub resource_id: ::std::string::String,
    /// <p>The ARN of the resource on which precondition failed with this operation.</p>
    pub resource_arn: ::std::string::String,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl PreconditionFailedException {
    /// <p>The ID of the resource on which precondition failed with this operation.</p>
    pub fn resource_id(&self) -> &str {
        use std::ops::Deref;
        self.resource_id.deref()
    }
    /// <p>The ARN of the resource on which precondition failed with this operation.</p>
    pub fn resource_arn(&self) -> &str {
        use std::ops::Deref;
        self.resource_arn.deref()
    }
}
impl PreconditionFailedException {
    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl ::std::fmt::Display for PreconditionFailedException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "PreconditionFailedException")?;
        {
            ::std::write!(f, ": {}", &self.message)?;
        }
        Ok(())
    }
}
impl ::std::error::Error for PreconditionFailedException {}
impl ::aws_types::request_id::RequestId for crate::types::error::PreconditionFailedException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for PreconditionFailedException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl PreconditionFailedException {
    /// Creates a new builder-style object to manufacture [`PreconditionFailedException`](crate::types::error::PreconditionFailedException).
    pub fn builder() -> crate::types::error::builders::PreconditionFailedExceptionBuilder {
        crate::types::error::builders::PreconditionFailedExceptionBuilder::default()
    }
}

/// A builder for [`PreconditionFailedException`](crate::types::error::PreconditionFailedException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PreconditionFailedExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl PreconditionFailedExceptionBuilder {
    #[allow(missing_docs)] // documentation missing in model
    /// This field is required.
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
    /// <p>The ID of the resource on which precondition failed with this operation.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource on which precondition failed with this operation.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The ID of the resource on which precondition failed with this operation.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>The ARN of the resource on which precondition failed with this operation.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the resource on which precondition failed with this operation.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The ARN of the resource on which precondition failed with this operation.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
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
    /// Consumes the builder and constructs a [`PreconditionFailedException`](crate::types::error::PreconditionFailedException).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::error::builders::PreconditionFailedExceptionBuilder::message)
    /// - [`resource_id`](crate::types::error::builders::PreconditionFailedExceptionBuilder::resource_id)
    /// - [`resource_arn`](crate::types::error::builders::PreconditionFailedExceptionBuilder::resource_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::error::PreconditionFailedException, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::error::PreconditionFailedException {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building PreconditionFailedException",
                )
            })?,
            resource_id: self.resource_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_id",
                    "resource_id was not specified but it is required when building PreconditionFailedException",
                )
            })?,
            resource_arn: self.resource_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_arn",
                    "resource_arn was not specified but it is required when building PreconditionFailedException",
                )
            })?,
            meta: self.meta.unwrap_or_default(),
        })
    }
}
