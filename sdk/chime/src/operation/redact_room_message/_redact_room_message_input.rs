// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RedactRoomMessageInput {
    /// <p>The Amazon Chime account ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The room ID.</p>
    pub room_id: ::std::option::Option<::std::string::String>,
    /// <p>The message ID.</p>
    pub message_id: ::std::option::Option<::std::string::String>,
}
impl RedactRoomMessageInput {
    /// <p>The Amazon Chime account ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The room ID.</p>
    pub fn room_id(&self) -> ::std::option::Option<&str> {
        self.room_id.as_deref()
    }
    /// <p>The message ID.</p>
    pub fn message_id(&self) -> ::std::option::Option<&str> {
        self.message_id.as_deref()
    }
}
impl RedactRoomMessageInput {
    /// Creates a new builder-style object to manufacture [`RedactRoomMessageInput`](crate::operation::redact_room_message::RedactRoomMessageInput).
    pub fn builder() -> crate::operation::redact_room_message::builders::RedactRoomMessageInputBuilder {
        crate::operation::redact_room_message::builders::RedactRoomMessageInputBuilder::default()
    }
}

/// A builder for [`RedactRoomMessageInput`](crate::operation::redact_room_message::RedactRoomMessageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RedactRoomMessageInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) room_id: ::std::option::Option<::std::string::String>,
    pub(crate) message_id: ::std::option::Option<::std::string::String>,
}
impl RedactRoomMessageInputBuilder {
    /// <p>The Amazon Chime account ID.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Chime account ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Chime account ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The room ID.</p>
    /// This field is required.
    pub fn room_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.room_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The room ID.</p>
    pub fn set_room_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.room_id = input;
        self
    }
    /// <p>The room ID.</p>
    pub fn get_room_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.room_id
    }
    /// <p>The message ID.</p>
    /// This field is required.
    pub fn message_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message ID.</p>
    pub fn set_message_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_id = input;
        self
    }
    /// <p>The message ID.</p>
    pub fn get_message_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.message_id
    }
    /// Consumes the builder and constructs a [`RedactRoomMessageInput`](crate::operation::redact_room_message::RedactRoomMessageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::redact_room_message::RedactRoomMessageInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::redact_room_message::RedactRoomMessageInput {
            account_id: self.account_id,
            room_id: self.room_id,
            message_id: self.message_id,
        })
    }
}
