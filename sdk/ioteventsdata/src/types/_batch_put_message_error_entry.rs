// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the errors encountered.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchPutMessageErrorEntry {
    /// <p>The ID of the message that caused the error. (See the value corresponding to the <code>"messageId"</code> key in the <code>"message"</code> object.)</p>
    pub message_id: ::std::option::Option<::std::string::String>,
    /// <p>The error code.</p>
    pub error_code: ::std::option::Option<crate::types::ErrorCode>,
    /// <p>A message that describes the error.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
}
impl BatchPutMessageErrorEntry {
    /// <p>The ID of the message that caused the error. (See the value corresponding to the <code>"messageId"</code> key in the <code>"message"</code> object.)</p>
    pub fn message_id(&self) -> ::std::option::Option<&str> {
        self.message_id.as_deref()
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
impl BatchPutMessageErrorEntry {
    /// Creates a new builder-style object to manufacture [`BatchPutMessageErrorEntry`](crate::types::BatchPutMessageErrorEntry).
    pub fn builder() -> crate::types::builders::BatchPutMessageErrorEntryBuilder {
        crate::types::builders::BatchPutMessageErrorEntryBuilder::default()
    }
}

/// A builder for [`BatchPutMessageErrorEntry`](crate::types::BatchPutMessageErrorEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchPutMessageErrorEntryBuilder {
    pub(crate) message_id: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<crate::types::ErrorCode>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
}
impl BatchPutMessageErrorEntryBuilder {
    /// <p>The ID of the message that caused the error. (See the value corresponding to the <code>"messageId"</code> key in the <code>"message"</code> object.)</p>
    pub fn message_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the message that caused the error. (See the value corresponding to the <code>"messageId"</code> key in the <code>"message"</code> object.)</p>
    pub fn set_message_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_id = input;
        self
    }
    /// <p>The ID of the message that caused the error. (See the value corresponding to the <code>"messageId"</code> key in the <code>"message"</code> object.)</p>
    pub fn get_message_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.message_id
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
    /// Consumes the builder and constructs a [`BatchPutMessageErrorEntry`](crate::types::BatchPutMessageErrorEntry).
    pub fn build(self) -> crate::types::BatchPutMessageErrorEntry {
        crate::types::BatchPutMessageErrorEntry {
            message_id: self.message_id,
            error_code: self.error_code,
            error_message: self.error_message,
        }
    }
}
