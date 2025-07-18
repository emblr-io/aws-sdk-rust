// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The operation failed because the client token input parameter matched one that was used with a previous call to the operation, but at least one of the other input parameters is different from the previous call.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IdempotentParameterMismatchException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::string::String,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl IdempotentParameterMismatchException {
    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl ::std::fmt::Display for IdempotentParameterMismatchException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "IdempotentParameterMismatchException")?;
        {
            ::std::write!(f, ": {}", &self.message)?;
        }
        Ok(())
    }
}
impl ::std::error::Error for IdempotentParameterMismatchException {}
impl ::aws_types::request_id::RequestId for crate::types::error::IdempotentParameterMismatchException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for IdempotentParameterMismatchException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl IdempotentParameterMismatchException {
    /// Creates a new builder-style object to manufacture [`IdempotentParameterMismatchException`](crate::types::error::IdempotentParameterMismatchException).
    pub fn builder() -> crate::types::error::builders::IdempotentParameterMismatchExceptionBuilder {
        crate::types::error::builders::IdempotentParameterMismatchExceptionBuilder::default()
    }
}

/// A builder for [`IdempotentParameterMismatchException`](crate::types::error::IdempotentParameterMismatchException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IdempotentParameterMismatchExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl IdempotentParameterMismatchExceptionBuilder {
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
    /// Consumes the builder and constructs a [`IdempotentParameterMismatchException`](crate::types::error::IdempotentParameterMismatchException).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::error::builders::IdempotentParameterMismatchExceptionBuilder::message)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::error::IdempotentParameterMismatchException, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::error::IdempotentParameterMismatchException {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building IdempotentParameterMismatchException",
                )
            })?,
            meta: self.meta.unwrap_or_default(),
        })
    }
}
