// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents an error that occurred during a batch create operation for bill scenario commitment modifications.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchCreateBillScenarioCommitmentModificationError {
    /// <p>The key of the entry that caused the error.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p>A descriptive message for the error that occurred.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>The error code associated with the failed operation.</p>
    pub error_code: ::std::option::Option<crate::types::BatchCreateBillScenarioCommitmentModificationErrorCode>,
}
impl BatchCreateBillScenarioCommitmentModificationError {
    /// <p>The key of the entry that caused the error.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p>A descriptive message for the error that occurred.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>The error code associated with the failed operation.</p>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::BatchCreateBillScenarioCommitmentModificationErrorCode> {
        self.error_code.as_ref()
    }
}
impl BatchCreateBillScenarioCommitmentModificationError {
    /// Creates a new builder-style object to manufacture [`BatchCreateBillScenarioCommitmentModificationError`](crate::types::BatchCreateBillScenarioCommitmentModificationError).
    pub fn builder() -> crate::types::builders::BatchCreateBillScenarioCommitmentModificationErrorBuilder {
        crate::types::builders::BatchCreateBillScenarioCommitmentModificationErrorBuilder::default()
    }
}

/// A builder for [`BatchCreateBillScenarioCommitmentModificationError`](crate::types::BatchCreateBillScenarioCommitmentModificationError).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchCreateBillScenarioCommitmentModificationErrorBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<crate::types::BatchCreateBillScenarioCommitmentModificationErrorCode>,
}
impl BatchCreateBillScenarioCommitmentModificationErrorBuilder {
    /// <p>The key of the entry that caused the error.</p>
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key of the entry that caused the error.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The key of the entry that caused the error.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>A descriptive message for the error that occurred.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A descriptive message for the error that occurred.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>A descriptive message for the error that occurred.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// <p>The error code associated with the failed operation.</p>
    pub fn error_code(mut self, input: crate::types::BatchCreateBillScenarioCommitmentModificationErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The error code associated with the failed operation.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::BatchCreateBillScenarioCommitmentModificationErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The error code associated with the failed operation.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::BatchCreateBillScenarioCommitmentModificationErrorCode> {
        &self.error_code
    }
    /// Consumes the builder and constructs a [`BatchCreateBillScenarioCommitmentModificationError`](crate::types::BatchCreateBillScenarioCommitmentModificationError).
    pub fn build(self) -> crate::types::BatchCreateBillScenarioCommitmentModificationError {
        crate::types::BatchCreateBillScenarioCommitmentModificationError {
            key: self.key,
            error_message: self.error_message,
            error_code: self.error_code,
        }
    }
}
