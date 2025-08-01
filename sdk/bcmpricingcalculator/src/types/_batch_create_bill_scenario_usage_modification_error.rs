// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents an error that occurred during a batch create operation for bill scenario usage modifications.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchCreateBillScenarioUsageModificationError {
    /// <p>The key of the entry that caused the error.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p>A descriptive message for the error that occurred.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>The error code associated with the failed operation.</p>
    pub error_code: ::std::option::Option<crate::types::BatchCreateBillScenarioUsageModificationErrorCode>,
}
impl BatchCreateBillScenarioUsageModificationError {
    /// <p>The key of the entry that caused the error.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p>A descriptive message for the error that occurred.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>The error code associated with the failed operation.</p>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::BatchCreateBillScenarioUsageModificationErrorCode> {
        self.error_code.as_ref()
    }
}
impl BatchCreateBillScenarioUsageModificationError {
    /// Creates a new builder-style object to manufacture [`BatchCreateBillScenarioUsageModificationError`](crate::types::BatchCreateBillScenarioUsageModificationError).
    pub fn builder() -> crate::types::builders::BatchCreateBillScenarioUsageModificationErrorBuilder {
        crate::types::builders::BatchCreateBillScenarioUsageModificationErrorBuilder::default()
    }
}

/// A builder for [`BatchCreateBillScenarioUsageModificationError`](crate::types::BatchCreateBillScenarioUsageModificationError).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchCreateBillScenarioUsageModificationErrorBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<crate::types::BatchCreateBillScenarioUsageModificationErrorCode>,
}
impl BatchCreateBillScenarioUsageModificationErrorBuilder {
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
    pub fn error_code(mut self, input: crate::types::BatchCreateBillScenarioUsageModificationErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The error code associated with the failed operation.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::BatchCreateBillScenarioUsageModificationErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The error code associated with the failed operation.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::BatchCreateBillScenarioUsageModificationErrorCode> {
        &self.error_code
    }
    /// Consumes the builder and constructs a [`BatchCreateBillScenarioUsageModificationError`](crate::types::BatchCreateBillScenarioUsageModificationError).
    pub fn build(self) -> crate::types::BatchCreateBillScenarioUsageModificationError {
        crate::types::BatchCreateBillScenarioUsageModificationError {
            key: self.key,
            error_message: self.error_message,
            error_code: self.error_code,
        }
    }
}
