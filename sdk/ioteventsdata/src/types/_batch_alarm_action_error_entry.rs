// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains error messages associated with one of the following requests:</p>
/// <ul>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/iotevents/latest/apireference/API_iotevents-data_BatchAcknowledgeAlarm.html">BatchAcknowledgeAlarm</a></p></li>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/iotevents/latest/apireference/API_iotevents-data_BatchDisableAlarm.html">BatchDisableAlarm</a></p></li>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/iotevents/latest/apireference/API_iotevents-data_BatchEnableAlarm.html">BatchEnableAlarm</a></p></li>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/iotevents/latest/apireference/API_iotevents-data_BatchResetAlarm.html">BatchResetAlarm</a></p></li>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/iotevents/latest/apireference/API_iotevents-data_BatchSnoozeAlarm.html">BatchSnoozeAlarm</a></p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchAlarmActionErrorEntry {
    /// <p>The request ID. Each ID must be unique within each batch.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The error code.</p>
    pub error_code: ::std::option::Option<crate::types::ErrorCode>,
    /// <p>A message that describes the error.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
}
impl BatchAlarmActionErrorEntry {
    /// <p>The request ID. Each ID must be unique within each batch.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The error code.</p>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::ErrorCode> {
        self.error_code.as_ref()
    }
    /// <p>A message that describes the error.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
}
impl BatchAlarmActionErrorEntry {
    /// Creates a new builder-style object to manufacture [`BatchAlarmActionErrorEntry`](crate::types::BatchAlarmActionErrorEntry).
    pub fn builder() -> crate::types::builders::BatchAlarmActionErrorEntryBuilder {
        crate::types::builders::BatchAlarmActionErrorEntryBuilder::default()
    }
}

/// A builder for [`BatchAlarmActionErrorEntry`](crate::types::BatchAlarmActionErrorEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchAlarmActionErrorEntryBuilder {
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<crate::types::ErrorCode>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
}
impl BatchAlarmActionErrorEntryBuilder {
    /// <p>The request ID. Each ID must be unique within each batch.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The request ID. Each ID must be unique within each batch.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The request ID. Each ID must be unique within each batch.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The error code.</p>
    pub fn error_code(mut self, input: crate::types::ErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The error code.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::ErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The error code.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::ErrorCode> {
        &self.error_code
    }
    /// <p>A message that describes the error.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message that describes the error.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>A message that describes the error.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// Consumes the builder and constructs a [`BatchAlarmActionErrorEntry`](crate::types::BatchAlarmActionErrorEntry).
    pub fn build(self) -> crate::types::BatchAlarmActionErrorEntry {
        crate::types::BatchAlarmActionErrorEntry {
            request_id: self.request_id,
            error_code: self.error_code,
            error_message: self.error_message,
        }
    }
}
