// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates that the provided Amazon Web Services Lambda function is invalid, or that Amazon SES could not execute the provided function, possibly due to permissions issues. For information about giving permissions, see the <a href="https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html">Amazon SES Developer Guide</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InvalidLambdaFunctionException {
    /// <p>Indicates that the ARN of the function was not found.</p>
    pub function_arn: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl InvalidLambdaFunctionException {
    /// <p>Indicates that the ARN of the function was not found.</p>
    pub fn function_arn(&self) -> ::std::option::Option<&str> {
        self.function_arn.as_deref()
    }
}
impl InvalidLambdaFunctionException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for InvalidLambdaFunctionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "InvalidLambdaFunctionException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for InvalidLambdaFunctionException {}
impl ::aws_types::request_id::RequestId for crate::types::error::InvalidLambdaFunctionException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for InvalidLambdaFunctionException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl InvalidLambdaFunctionException {
    /// Creates a new builder-style object to manufacture [`InvalidLambdaFunctionException`](crate::types::error::InvalidLambdaFunctionException).
    pub fn builder() -> crate::types::error::builders::InvalidLambdaFunctionExceptionBuilder {
        crate::types::error::builders::InvalidLambdaFunctionExceptionBuilder::default()
    }
}

/// A builder for [`InvalidLambdaFunctionException`](crate::types::error::InvalidLambdaFunctionException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InvalidLambdaFunctionExceptionBuilder {
    pub(crate) function_arn: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl InvalidLambdaFunctionExceptionBuilder {
    /// <p>Indicates that the ARN of the function was not found.</p>
    pub fn function_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.function_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates that the ARN of the function was not found.</p>
    pub fn set_function_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.function_arn = input;
        self
    }
    /// <p>Indicates that the ARN of the function was not found.</p>
    pub fn get_function_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.function_arn
    }
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
    /// Consumes the builder and constructs a [`InvalidLambdaFunctionException`](crate::types::error::InvalidLambdaFunctionException).
    pub fn build(self) -> crate::types::error::InvalidLambdaFunctionException {
        crate::types::error::InvalidLambdaFunctionException {
            function_arn: self.function_arn,
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
