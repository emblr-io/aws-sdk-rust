// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An error occurred while streaming the response body. This error can have the following error codes:</p>
/// <dl>
/// <dt>
/// ModelInvocationTimeExceeded
/// </dt>
/// <dd>
/// <p>The model failed to finish sending the response within the timeout period allowed by Amazon SageMaker.</p>
/// </dd>
/// <dt>
/// StreamBroken
/// </dt>
/// <dd>
/// <p>The Transmission Control Protocol (TCP) connection between the client and the model was reset or closed.</p>
/// </dd>
/// </dl>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModelStreamError {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>This error can have the following error codes:</p>
    /// <dl>
    /// <dt>
    /// ModelInvocationTimeExceeded
    /// </dt>
    /// <dd>
    /// <p>The model failed to finish sending the response within the timeout period allowed by Amazon SageMaker.</p>
    /// </dd>
    /// <dt>
    /// StreamBroken
    /// </dt>
    /// <dd>
    /// <p>The Transmission Control Protocol (TCP) connection between the client and the model was reset or closed.</p>
    /// </dd>
    /// </dl>
    pub error_code: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl ModelStreamError {
    /// <p>This error can have the following error codes:</p>
    /// <dl>
    /// <dt>
    /// ModelInvocationTimeExceeded
    /// </dt>
    /// <dd>
    /// <p>The model failed to finish sending the response within the timeout period allowed by Amazon SageMaker.</p>
    /// </dd>
    /// <dt>
    /// StreamBroken
    /// </dt>
    /// <dd>
    /// <p>The Transmission Control Protocol (TCP) connection between the client and the model was reset or closed.</p>
    /// </dd>
    /// </dl>
    pub fn error_code(&self) -> ::std::option::Option<&str> {
        self.error_code.as_deref()
    }
}
impl ModelStreamError {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for ModelStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "ModelStreamError")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for ModelStreamError {}
impl ::aws_types::request_id::RequestId for crate::types::error::ModelStreamError {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for ModelStreamError {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl ModelStreamError {
    /// Creates a new builder-style object to manufacture [`ModelStreamError`](crate::types::error::ModelStreamError).
    pub fn builder() -> crate::types::error::builders::ModelStreamErrorBuilder {
        crate::types::error::builders::ModelStreamErrorBuilder::default()
    }
}

/// A builder for [`ModelStreamError`](crate::types::error::ModelStreamError).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModelStreamErrorBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl ModelStreamErrorBuilder {
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
    /// <p>This error can have the following error codes:</p>
    /// <dl>
    /// <dt>
    /// ModelInvocationTimeExceeded
    /// </dt>
    /// <dd>
    /// <p>The model failed to finish sending the response within the timeout period allowed by Amazon SageMaker.</p>
    /// </dd>
    /// <dt>
    /// StreamBroken
    /// </dt>
    /// <dd>
    /// <p>The Transmission Control Protocol (TCP) connection between the client and the model was reset or closed.</p>
    /// </dd>
    /// </dl>
    pub fn error_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This error can have the following error codes:</p>
    /// <dl>
    /// <dt>
    /// ModelInvocationTimeExceeded
    /// </dt>
    /// <dd>
    /// <p>The model failed to finish sending the response within the timeout period allowed by Amazon SageMaker.</p>
    /// </dd>
    /// <dt>
    /// StreamBroken
    /// </dt>
    /// <dd>
    /// <p>The Transmission Control Protocol (TCP) connection between the client and the model was reset or closed.</p>
    /// </dd>
    /// </dl>
    pub fn set_error_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>This error can have the following error codes:</p>
    /// <dl>
    /// <dt>
    /// ModelInvocationTimeExceeded
    /// </dt>
    /// <dd>
    /// <p>The model failed to finish sending the response within the timeout period allowed by Amazon SageMaker.</p>
    /// </dd>
    /// <dt>
    /// StreamBroken
    /// </dt>
    /// <dd>
    /// <p>The Transmission Control Protocol (TCP) connection between the client and the model was reset or closed.</p>
    /// </dd>
    /// </dl>
    pub fn get_error_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_code
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
    /// Consumes the builder and constructs a [`ModelStreamError`](crate::types::error::ModelStreamError).
    pub fn build(self) -> crate::types::error::ModelStreamError {
        crate::types::error::ModelStreamError {
            message: self.message,
            error_code: self.error_code,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
