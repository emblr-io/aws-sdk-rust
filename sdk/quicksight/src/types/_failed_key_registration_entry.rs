// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An entry that appears when a <code>KeyRegistration</code> update to Amazon QuickSight fails.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FailedKeyRegistrationEntry {
    /// <p>The ARN of the KMS key that failed to update.</p>
    pub key_arn: ::std::option::Option<::std::string::String>,
    /// <p>A message that provides information about why a <code>FailedKeyRegistrationEntry</code> error occurred.</p>
    pub message: ::std::string::String,
    /// <p>The HTTP status of a <code>FailedKeyRegistrationEntry</code> error.</p>
    pub status_code: i32,
    /// <p>A boolean that indicates whether a <code>FailedKeyRegistrationEntry</code> resulted from user error. If the value of this property is <code>True</code>, the error was caused by user error. If the value of this property is <code>False</code>, the error occurred on the backend. If your job continues fail and with a <code>False</code> <code>SenderFault</code> value, contact Amazon Web ServicesSupport.</p>
    pub sender_fault: bool,
}
impl FailedKeyRegistrationEntry {
    /// <p>The ARN of the KMS key that failed to update.</p>
    pub fn key_arn(&self) -> ::std::option::Option<&str> {
        self.key_arn.as_deref()
    }
    /// <p>A message that provides information about why a <code>FailedKeyRegistrationEntry</code> error occurred.</p>
    pub fn message(&self) -> &str {
        use std::ops::Deref;
        self.message.deref()
    }
    /// <p>The HTTP status of a <code>FailedKeyRegistrationEntry</code> error.</p>
    pub fn status_code(&self) -> i32 {
        self.status_code
    }
    /// <p>A boolean that indicates whether a <code>FailedKeyRegistrationEntry</code> resulted from user error. If the value of this property is <code>True</code>, the error was caused by user error. If the value of this property is <code>False</code>, the error occurred on the backend. If your job continues fail and with a <code>False</code> <code>SenderFault</code> value, contact Amazon Web ServicesSupport.</p>
    pub fn sender_fault(&self) -> bool {
        self.sender_fault
    }
}
impl FailedKeyRegistrationEntry {
    /// Creates a new builder-style object to manufacture [`FailedKeyRegistrationEntry`](crate::types::FailedKeyRegistrationEntry).
    pub fn builder() -> crate::types::builders::FailedKeyRegistrationEntryBuilder {
        crate::types::builders::FailedKeyRegistrationEntryBuilder::default()
    }
}

/// A builder for [`FailedKeyRegistrationEntry`](crate::types::FailedKeyRegistrationEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FailedKeyRegistrationEntryBuilder {
    pub(crate) key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) status_code: ::std::option::Option<i32>,
    pub(crate) sender_fault: ::std::option::Option<bool>,
}
impl FailedKeyRegistrationEntryBuilder {
    /// <p>The ARN of the KMS key that failed to update.</p>
    pub fn key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the KMS key that failed to update.</p>
    pub fn set_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_arn = input;
        self
    }
    /// <p>The ARN of the KMS key that failed to update.</p>
    pub fn get_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_arn
    }
    /// <p>A message that provides information about why a <code>FailedKeyRegistrationEntry</code> error occurred.</p>
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message that provides information about why a <code>FailedKeyRegistrationEntry</code> error occurred.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message that provides information about why a <code>FailedKeyRegistrationEntry</code> error occurred.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>The HTTP status of a <code>FailedKeyRegistrationEntry</code> error.</p>
    /// This field is required.
    pub fn status_code(mut self, input: i32) -> Self {
        self.status_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The HTTP status of a <code>FailedKeyRegistrationEntry</code> error.</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<i32>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>The HTTP status of a <code>FailedKeyRegistrationEntry</code> error.</p>
    pub fn get_status_code(&self) -> &::std::option::Option<i32> {
        &self.status_code
    }
    /// <p>A boolean that indicates whether a <code>FailedKeyRegistrationEntry</code> resulted from user error. If the value of this property is <code>True</code>, the error was caused by user error. If the value of this property is <code>False</code>, the error occurred on the backend. If your job continues fail and with a <code>False</code> <code>SenderFault</code> value, contact Amazon Web ServicesSupport.</p>
    /// This field is required.
    pub fn sender_fault(mut self, input: bool) -> Self {
        self.sender_fault = ::std::option::Option::Some(input);
        self
    }
    /// <p>A boolean that indicates whether a <code>FailedKeyRegistrationEntry</code> resulted from user error. If the value of this property is <code>True</code>, the error was caused by user error. If the value of this property is <code>False</code>, the error occurred on the backend. If your job continues fail and with a <code>False</code> <code>SenderFault</code> value, contact Amazon Web ServicesSupport.</p>
    pub fn set_sender_fault(mut self, input: ::std::option::Option<bool>) -> Self {
        self.sender_fault = input;
        self
    }
    /// <p>A boolean that indicates whether a <code>FailedKeyRegistrationEntry</code> resulted from user error. If the value of this property is <code>True</code>, the error was caused by user error. If the value of this property is <code>False</code>, the error occurred on the backend. If your job continues fail and with a <code>False</code> <code>SenderFault</code> value, contact Amazon Web ServicesSupport.</p>
    pub fn get_sender_fault(&self) -> &::std::option::Option<bool> {
        &self.sender_fault
    }
    /// Consumes the builder and constructs a [`FailedKeyRegistrationEntry`](crate::types::FailedKeyRegistrationEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::builders::FailedKeyRegistrationEntryBuilder::message)
    pub fn build(self) -> ::std::result::Result<crate::types::FailedKeyRegistrationEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FailedKeyRegistrationEntry {
            key_arn: self.key_arn,
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building FailedKeyRegistrationEntry",
                )
            })?,
            status_code: self.status_code.unwrap_or_default(),
            sender_fault: self.sender_fault.unwrap_or_default(),
        })
    }
}
