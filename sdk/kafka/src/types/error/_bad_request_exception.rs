// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returns information about an error.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BadRequestException {
    /// <p>The parameter that caused the error.</p>
    pub invalid_parameter: ::std::option::Option<::std::string::String>,
    /// <p>The description of the error.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl BadRequestException {
    /// <p>The parameter that caused the error.</p>
    pub fn invalid_parameter(&self) -> ::std::option::Option<&str> {
        self.invalid_parameter.as_deref()
    }
}
impl BadRequestException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for BadRequestException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "BadRequestException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for BadRequestException {}
impl ::aws_types::request_id::RequestId for crate::types::error::BadRequestException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for BadRequestException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl BadRequestException {
    /// Creates a new builder-style object to manufacture [`BadRequestException`](crate::types::error::BadRequestException).
    pub fn builder() -> crate::types::error::builders::BadRequestExceptionBuilder {
        crate::types::error::builders::BadRequestExceptionBuilder::default()
    }
}

/// A builder for [`BadRequestException`](crate::types::error::BadRequestException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BadRequestExceptionBuilder {
    pub(crate) invalid_parameter: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl BadRequestExceptionBuilder {
    /// <p>The parameter that caused the error.</p>
    pub fn invalid_parameter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.invalid_parameter = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The parameter that caused the error.</p>
    pub fn set_invalid_parameter(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.invalid_parameter = input;
        self
    }
    /// <p>The parameter that caused the error.</p>
    pub fn get_invalid_parameter(&self) -> &::std::option::Option<::std::string::String> {
        &self.invalid_parameter
    }
    /// <p>The description of the error.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the error.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The description of the error.</p>
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
    /// Consumes the builder and constructs a [`BadRequestException`](crate::types::error::BadRequestException).
    pub fn build(self) -> crate::types::error::BadRequestException {
        crate::types::error::BadRequestException {
            invalid_parameter: self.invalid_parameter,
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
