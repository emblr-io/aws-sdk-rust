// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The event was already logged.</p><important>
/// <p><code>PutLogEvents</code> actions are now always accepted and never return <code>DataAlreadyAcceptedException</code> regardless of whether a given batch of log events has already been accepted.</p>
/// </important>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataAlreadyAcceptedException {
    #[allow(missing_docs)] // documentation missing in model
    pub expected_sequence_token: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl DataAlreadyAcceptedException {
    #[allow(missing_docs)] // documentation missing in model
    pub fn expected_sequence_token(&self) -> ::std::option::Option<&str> {
        self.expected_sequence_token.as_deref()
    }
}
impl DataAlreadyAcceptedException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for DataAlreadyAcceptedException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "DataAlreadyAcceptedException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for DataAlreadyAcceptedException {}
impl ::aws_types::request_id::RequestId for crate::types::error::DataAlreadyAcceptedException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for DataAlreadyAcceptedException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl DataAlreadyAcceptedException {
    /// Creates a new builder-style object to manufacture [`DataAlreadyAcceptedException`](crate::types::error::DataAlreadyAcceptedException).
    pub fn builder() -> crate::types::error::builders::DataAlreadyAcceptedExceptionBuilder {
        crate::types::error::builders::DataAlreadyAcceptedExceptionBuilder::default()
    }
}

/// A builder for [`DataAlreadyAcceptedException`](crate::types::error::DataAlreadyAcceptedException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataAlreadyAcceptedExceptionBuilder {
    pub(crate) expected_sequence_token: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl DataAlreadyAcceptedExceptionBuilder {
    #[allow(missing_docs)] // documentation missing in model
    pub fn expected_sequence_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expected_sequence_token = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_expected_sequence_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expected_sequence_token = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_expected_sequence_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.expected_sequence_token
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
    /// Consumes the builder and constructs a [`DataAlreadyAcceptedException`](crate::types::error::DataAlreadyAcceptedException).
    pub fn build(self) -> crate::types::error::DataAlreadyAcceptedException {
        crate::types::error::DataAlreadyAcceptedException {
            expected_sequence_token: self.expected_sequence_token,
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
