// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request cannot be processed due to known reasons. Eg. partition full.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnprocessableException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::string::String,
    /// <p>The reason for the unprocessable exception.</p>
    pub reason: crate::types::UnprocessableExceptionReason,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl UnprocessableException {
    /// <p>The reason for the unprocessable exception.</p>
    pub fn reason(&self) -> &crate::types::UnprocessableExceptionReason {
        &self.reason
    }
}
impl UnprocessableException {
    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl ::std::fmt::Display for UnprocessableException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "UnprocessableException")?;
        {
            ::std::write!(f, ": {}", &self.message)?;
        }
        Ok(())
    }
}
impl ::std::error::Error for UnprocessableException {}
impl ::aws_types::request_id::RequestId for crate::types::error::UnprocessableException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for UnprocessableException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl UnprocessableException {
    /// Creates a new builder-style object to manufacture [`UnprocessableException`](crate::types::error::UnprocessableException).
    pub fn builder() -> crate::types::error::builders::UnprocessableExceptionBuilder {
        crate::types::error::builders::UnprocessableExceptionBuilder::default()
    }
}

/// A builder for [`UnprocessableException`](crate::types::error::UnprocessableException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnprocessableExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<crate::types::UnprocessableExceptionReason>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl UnprocessableExceptionBuilder {
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
    /// <p>The reason for the unprocessable exception.</p>
    /// This field is required.
    pub fn reason(mut self, input: crate::types::UnprocessableExceptionReason) -> Self {
        self.reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason for the unprocessable exception.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<crate::types::UnprocessableExceptionReason>) -> Self {
        self.reason = input;
        self
    }
    /// <p>The reason for the unprocessable exception.</p>
    pub fn get_reason(&self) -> &::std::option::Option<crate::types::UnprocessableExceptionReason> {
        &self.reason
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
    /// Consumes the builder and constructs a [`UnprocessableException`](crate::types::error::UnprocessableException).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::error::builders::UnprocessableExceptionBuilder::message)
    /// - [`reason`](crate::types::error::builders::UnprocessableExceptionBuilder::reason)
    pub fn build(self) -> ::std::result::Result<crate::types::error::UnprocessableException, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::error::UnprocessableException {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building UnprocessableException",
                )
            })?,
            reason: self.reason.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "reason",
                    "reason was not specified but it is required when building UnprocessableException",
                )
            })?,
            meta: self.meta.unwrap_or_default(),
        })
    }
}
