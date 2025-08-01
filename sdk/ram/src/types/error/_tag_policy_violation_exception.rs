// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The operation failed because the specified tag key is a reserved word and can't be used.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagPolicyViolationException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::string::String,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl TagPolicyViolationException {
    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl ::std::fmt::Display for TagPolicyViolationException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "TagPolicyViolationException")?;
        {
            ::std::write!(f, ": {}", &self.message)?;
        }
        Ok(())
    }
}
impl ::std::error::Error for TagPolicyViolationException {}
impl ::aws_types::request_id::RequestId for crate::types::error::TagPolicyViolationException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for TagPolicyViolationException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl TagPolicyViolationException {
    /// Creates a new builder-style object to manufacture [`TagPolicyViolationException`](crate::types::error::TagPolicyViolationException).
    pub fn builder() -> crate::types::error::builders::TagPolicyViolationExceptionBuilder {
        crate::types::error::builders::TagPolicyViolationExceptionBuilder::default()
    }
}

/// A builder for [`TagPolicyViolationException`](crate::types::error::TagPolicyViolationException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagPolicyViolationExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl TagPolicyViolationExceptionBuilder {
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
    /// Consumes the builder and constructs a [`TagPolicyViolationException`](crate::types::error::TagPolicyViolationException).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::error::builders::TagPolicyViolationExceptionBuilder::message)
    pub fn build(self) -> ::std::result::Result<crate::types::error::TagPolicyViolationException, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::error::TagPolicyViolationException {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building TagPolicyViolationException",
                )
            })?,
            meta: self.meta.unwrap_or_default(),
        })
    }
}
