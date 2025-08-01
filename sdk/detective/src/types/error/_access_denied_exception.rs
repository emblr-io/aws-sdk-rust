// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request issuer does not have permission to access this resource or perform this operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccessDeniedException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>The SDK default error code associated with the access denied exception.</p>
    pub error_code: ::std::option::Option<crate::types::ErrorCode>,
    /// <p>The SDK default explanation of why access was denied.</p>
    pub error_code_reason: ::std::option::Option<::std::string::String>,
    /// <p>The error code associated with the access denied exception.</p>
    pub sub_error_code: ::std::option::Option<crate::types::ErrorCode>,
    /// <p>An explanation of why access was denied.</p>
    pub sub_error_code_reason: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl AccessDeniedException {
    /// <p>The SDK default error code associated with the access denied exception.</p>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::ErrorCode> {
        self.error_code.as_ref()
    }
    /// <p>The SDK default explanation of why access was denied.</p>
    pub fn error_code_reason(&self) -> ::std::option::Option<&str> {
        self.error_code_reason.as_deref()
    }
    /// <p>The error code associated with the access denied exception.</p>
    pub fn sub_error_code(&self) -> ::std::option::Option<&crate::types::ErrorCode> {
        self.sub_error_code.as_ref()
    }
    /// <p>An explanation of why access was denied.</p>
    pub fn sub_error_code_reason(&self) -> ::std::option::Option<&str> {
        self.sub_error_code_reason.as_deref()
    }
}
impl AccessDeniedException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for AccessDeniedException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "AccessDeniedException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for AccessDeniedException {}
impl ::aws_types::request_id::RequestId for crate::types::error::AccessDeniedException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for AccessDeniedException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl AccessDeniedException {
    /// Creates a new builder-style object to manufacture [`AccessDeniedException`](crate::types::error::AccessDeniedException).
    pub fn builder() -> crate::types::error::builders::AccessDeniedExceptionBuilder {
        crate::types::error::builders::AccessDeniedExceptionBuilder::default()
    }
}

/// A builder for [`AccessDeniedException`](crate::types::error::AccessDeniedException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccessDeniedExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<crate::types::ErrorCode>,
    pub(crate) error_code_reason: ::std::option::Option<::std::string::String>,
    pub(crate) sub_error_code: ::std::option::Option<crate::types::ErrorCode>,
    pub(crate) sub_error_code_reason: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl AccessDeniedExceptionBuilder {
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
    /// <p>The SDK default error code associated with the access denied exception.</p>
    pub fn error_code(mut self, input: crate::types::ErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The SDK default error code associated with the access denied exception.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::ErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The SDK default error code associated with the access denied exception.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::ErrorCode> {
        &self.error_code
    }
    /// <p>The SDK default explanation of why access was denied.</p>
    pub fn error_code_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_code_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SDK default explanation of why access was denied.</p>
    pub fn set_error_code_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_code_reason = input;
        self
    }
    /// <p>The SDK default explanation of why access was denied.</p>
    pub fn get_error_code_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_code_reason
    }
    /// <p>The error code associated with the access denied exception.</p>
    pub fn sub_error_code(mut self, input: crate::types::ErrorCode) -> Self {
        self.sub_error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The error code associated with the access denied exception.</p>
    pub fn set_sub_error_code(mut self, input: ::std::option::Option<crate::types::ErrorCode>) -> Self {
        self.sub_error_code = input;
        self
    }
    /// <p>The error code associated with the access denied exception.</p>
    pub fn get_sub_error_code(&self) -> &::std::option::Option<crate::types::ErrorCode> {
        &self.sub_error_code
    }
    /// <p>An explanation of why access was denied.</p>
    pub fn sub_error_code_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sub_error_code_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An explanation of why access was denied.</p>
    pub fn set_sub_error_code_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sub_error_code_reason = input;
        self
    }
    /// <p>An explanation of why access was denied.</p>
    pub fn get_sub_error_code_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.sub_error_code_reason
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
    /// Consumes the builder and constructs a [`AccessDeniedException`](crate::types::error::AccessDeniedException).
    pub fn build(self) -> crate::types::error::AccessDeniedException {
        crate::types::error::AccessDeniedException {
            message: self.message,
            error_code: self.error_code,
            error_code_reason: self.error_code_reason,
            sub_error_code: self.sub_error_code,
            sub_error_code_reason: self.sub_error_code_reason,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
