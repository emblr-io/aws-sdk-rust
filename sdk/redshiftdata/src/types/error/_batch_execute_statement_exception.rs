// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An SQL statement encountered an environmental error while running.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchExecuteStatementException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::string::String,
    /// <p>Statement identifier of the exception.</p>
    pub statement_id: ::std::string::String,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl BatchExecuteStatementException {
    /// <p>Statement identifier of the exception.</p>
    pub fn statement_id(&self) -> &str {
        use std::ops::Deref;
        self.statement_id.deref()
    }
}
impl BatchExecuteStatementException {
    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl ::std::fmt::Display for BatchExecuteStatementException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "BatchExecuteStatementException")?;
        {
            ::std::write!(f, ": {}", &self.message)?;
        }
        Ok(())
    }
}
impl ::std::error::Error for BatchExecuteStatementException {}
impl ::aws_types::request_id::RequestId for crate::types::error::BatchExecuteStatementException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for BatchExecuteStatementException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl BatchExecuteStatementException {
    /// Creates a new builder-style object to manufacture [`BatchExecuteStatementException`](crate::types::error::BatchExecuteStatementException).
    pub fn builder() -> crate::types::error::builders::BatchExecuteStatementExceptionBuilder {
        crate::types::error::builders::BatchExecuteStatementExceptionBuilder::default()
    }
}

/// A builder for [`BatchExecuteStatementException`](crate::types::error::BatchExecuteStatementException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchExecuteStatementExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) statement_id: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl BatchExecuteStatementExceptionBuilder {
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
    /// <p>Statement identifier of the exception.</p>
    /// This field is required.
    pub fn statement_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.statement_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Statement identifier of the exception.</p>
    pub fn set_statement_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.statement_id = input;
        self
    }
    /// <p>Statement identifier of the exception.</p>
    pub fn get_statement_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.statement_id
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
    /// Consumes the builder and constructs a [`BatchExecuteStatementException`](crate::types::error::BatchExecuteStatementException).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::error::builders::BatchExecuteStatementExceptionBuilder::message)
    /// - [`statement_id`](crate::types::error::builders::BatchExecuteStatementExceptionBuilder::statement_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::error::BatchExecuteStatementException, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::error::BatchExecuteStatementException {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building BatchExecuteStatementException",
                )
            })?,
            statement_id: self.statement_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "statement_id",
                    "statement_id was not specified but it is required when building BatchExecuteStatementException",
                )
            })?,
            meta: self.meta.unwrap_or_default(),
        })
    }
}
