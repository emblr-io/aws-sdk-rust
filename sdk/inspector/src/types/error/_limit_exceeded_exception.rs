// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request was rejected because it attempted to create resources beyond the current AWS account limits. The error code describes the limit exceeded.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LimitExceededException {
    /// <p>Details of the exception error.</p>
    pub message: ::std::string::String,
    /// <p>Code that indicates the type of error that is generated.</p>
    pub error_code: crate::types::LimitExceededErrorCode,
    /// <p>You can immediately retry your request.</p>
    pub can_retry: bool,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl LimitExceededException {
    /// <p>Code that indicates the type of error that is generated.</p>
    pub fn error_code(&self) -> &crate::types::LimitExceededErrorCode {
        &self.error_code
    }
    /// <p>You can immediately retry your request.</p>
    pub fn can_retry(&self) -> bool {
        self.can_retry
    }
}
impl LimitExceededException {
    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl ::std::fmt::Display for LimitExceededException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "LimitExceededException")?;
        {
            ::std::write!(f, ": {}", &self.message)?;
        }
        Ok(())
    }
}
impl ::std::error::Error for LimitExceededException {}
impl ::aws_types::request_id::RequestId for crate::types::error::LimitExceededException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for LimitExceededException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl LimitExceededException {
    /// Creates a new builder-style object to manufacture [`LimitExceededException`](crate::types::error::LimitExceededException).
    pub fn builder() -> crate::types::error::builders::LimitExceededExceptionBuilder {
        crate::types::error::builders::LimitExceededExceptionBuilder::default()
    }
}

/// A builder for [`LimitExceededException`](crate::types::error::LimitExceededException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LimitExceededExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<crate::types::LimitExceededErrorCode>,
    pub(crate) can_retry: ::std::option::Option<bool>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl LimitExceededExceptionBuilder {
    /// <p>Details of the exception error.</p>
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Details of the exception error.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>Details of the exception error.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>Code that indicates the type of error that is generated.</p>
    /// This field is required.
    pub fn error_code(mut self, input: crate::types::LimitExceededErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>Code that indicates the type of error that is generated.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::LimitExceededErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>Code that indicates the type of error that is generated.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::LimitExceededErrorCode> {
        &self.error_code
    }
    /// <p>You can immediately retry your request.</p>
    /// This field is required.
    pub fn can_retry(mut self, input: bool) -> Self {
        self.can_retry = ::std::option::Option::Some(input);
        self
    }
    /// <p>You can immediately retry your request.</p>
    pub fn set_can_retry(mut self, input: ::std::option::Option<bool>) -> Self {
        self.can_retry = input;
        self
    }
    /// <p>You can immediately retry your request.</p>
    pub fn get_can_retry(&self) -> &::std::option::Option<bool> {
        &self.can_retry
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
    /// Consumes the builder and constructs a [`LimitExceededException`](crate::types::error::LimitExceededException).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::error::builders::LimitExceededExceptionBuilder::message)
    /// - [`error_code`](crate::types::error::builders::LimitExceededExceptionBuilder::error_code)
    /// - [`can_retry`](crate::types::error::builders::LimitExceededExceptionBuilder::can_retry)
    pub fn build(self) -> ::std::result::Result<crate::types::error::LimitExceededException, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::error::LimitExceededException {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building LimitExceededException",
                )
            })?,
            error_code: self.error_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "error_code",
                    "error_code was not specified but it is required when building LimitExceededException",
                )
            })?,
            can_retry: self.can_retry.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "can_retry",
                    "can_retry was not specified but it is required when building LimitExceededException",
                )
            })?,
            meta: self.meta.unwrap_or_default(),
        })
    }
}
