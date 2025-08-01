// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateChatTokenInput {
    /// <p>Identifier of the room that the client is trying to access. Currently this must be an ARN.</p>
    pub room_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Application-provided ID that uniquely identifies the user associated with this token. This can be any UTF-8 encoded text.</p>
    pub user_id: ::std::option::Option<::std::string::String>,
    /// <p>Set of capabilities that the user is allowed to perform in the room. Default: None (the capability to view messages is implicitly included in all requests).</p>
    pub capabilities: ::std::option::Option<::std::vec::Vec<crate::types::ChatTokenCapability>>,
    /// <p>Session duration (in minutes), after which the session expires. Default: 60 (1 hour).</p>
    pub session_duration_in_minutes: ::std::option::Option<i32>,
    /// <p>Application-provided attributes to encode into the token and attach to a chat session. Map keys and values can contain UTF-8 encoded text. The maximum length of this field is 1 KB total.</p>
    pub attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateChatTokenInput {
    /// <p>Identifier of the room that the client is trying to access. Currently this must be an ARN.</p>
    pub fn room_identifier(&self) -> ::std::option::Option<&str> {
        self.room_identifier.as_deref()
    }
    /// <p>Application-provided ID that uniquely identifies the user associated with this token. This can be any UTF-8 encoded text.</p>
    pub fn user_id(&self) -> ::std::option::Option<&str> {
        self.user_id.as_deref()
    }
    /// <p>Set of capabilities that the user is allowed to perform in the room. Default: None (the capability to view messages is implicitly included in all requests).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.capabilities.is_none()`.
    pub fn capabilities(&self) -> &[crate::types::ChatTokenCapability] {
        self.capabilities.as_deref().unwrap_or_default()
    }
    /// <p>Session duration (in minutes), after which the session expires. Default: 60 (1 hour).</p>
    pub fn session_duration_in_minutes(&self) -> ::std::option::Option<i32> {
        self.session_duration_in_minutes
    }
    /// <p>Application-provided attributes to encode into the token and attach to a chat session. Map keys and values can contain UTF-8 encoded text. The maximum length of this field is 1 KB total.</p>
    pub fn attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.attributes.as_ref()
    }
}
impl ::std::fmt::Debug for CreateChatTokenInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateChatTokenInput");
        formatter.field("room_identifier", &self.room_identifier);
        formatter.field("user_id", &"*** Sensitive Data Redacted ***");
        formatter.field("capabilities", &self.capabilities);
        formatter.field("session_duration_in_minutes", &self.session_duration_in_minutes);
        formatter.field("attributes", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl CreateChatTokenInput {
    /// Creates a new builder-style object to manufacture [`CreateChatTokenInput`](crate::operation::create_chat_token::CreateChatTokenInput).
    pub fn builder() -> crate::operation::create_chat_token::builders::CreateChatTokenInputBuilder {
        crate::operation::create_chat_token::builders::CreateChatTokenInputBuilder::default()
    }
}

/// A builder for [`CreateChatTokenInput`](crate::operation::create_chat_token::CreateChatTokenInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateChatTokenInputBuilder {
    pub(crate) room_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) user_id: ::std::option::Option<::std::string::String>,
    pub(crate) capabilities: ::std::option::Option<::std::vec::Vec<crate::types::ChatTokenCapability>>,
    pub(crate) session_duration_in_minutes: ::std::option::Option<i32>,
    pub(crate) attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateChatTokenInputBuilder {
    /// <p>Identifier of the room that the client is trying to access. Currently this must be an ARN.</p>
    /// This field is required.
    pub fn room_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.room_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier of the room that the client is trying to access. Currently this must be an ARN.</p>
    pub fn set_room_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.room_identifier = input;
        self
    }
    /// <p>Identifier of the room that the client is trying to access. Currently this must be an ARN.</p>
    pub fn get_room_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.room_identifier
    }
    /// <p>Application-provided ID that uniquely identifies the user associated with this token. This can be any UTF-8 encoded text.</p>
    /// This field is required.
    pub fn user_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Application-provided ID that uniquely identifies the user associated with this token. This can be any UTF-8 encoded text.</p>
    pub fn set_user_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_id = input;
        self
    }
    /// <p>Application-provided ID that uniquely identifies the user associated with this token. This can be any UTF-8 encoded text.</p>
    pub fn get_user_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_id
    }
    /// Appends an item to `capabilities`.
    ///
    /// To override the contents of this collection use [`set_capabilities`](Self::set_capabilities).
    ///
    /// <p>Set of capabilities that the user is allowed to perform in the room. Default: None (the capability to view messages is implicitly included in all requests).</p>
    pub fn capabilities(mut self, input: crate::types::ChatTokenCapability) -> Self {
        let mut v = self.capabilities.unwrap_or_default();
        v.push(input);
        self.capabilities = ::std::option::Option::Some(v);
        self
    }
    /// <p>Set of capabilities that the user is allowed to perform in the room. Default: None (the capability to view messages is implicitly included in all requests).</p>
    pub fn set_capabilities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ChatTokenCapability>>) -> Self {
        self.capabilities = input;
        self
    }
    /// <p>Set of capabilities that the user is allowed to perform in the room. Default: None (the capability to view messages is implicitly included in all requests).</p>
    pub fn get_capabilities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ChatTokenCapability>> {
        &self.capabilities
    }
    /// <p>Session duration (in minutes), after which the session expires. Default: 60 (1 hour).</p>
    pub fn session_duration_in_minutes(mut self, input: i32) -> Self {
        self.session_duration_in_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Session duration (in minutes), after which the session expires. Default: 60 (1 hour).</p>
    pub fn set_session_duration_in_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.session_duration_in_minutes = input;
        self
    }
    /// <p>Session duration (in minutes), after which the session expires. Default: 60 (1 hour).</p>
    pub fn get_session_duration_in_minutes(&self) -> &::std::option::Option<i32> {
        &self.session_duration_in_minutes
    }
    /// Adds a key-value pair to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>Application-provided attributes to encode into the token and attach to a chat session. Map keys and values can contain UTF-8 encoded text. The maximum length of this field is 1 KB total.</p>
    pub fn attributes(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Application-provided attributes to encode into the token and attach to a chat session. Map keys and values can contain UTF-8 encoded text. The maximum length of this field is 1 KB total.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>Application-provided attributes to encode into the token and attach to a chat session. Map keys and values can contain UTF-8 encoded text. The maximum length of this field is 1 KB total.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.attributes
    }
    /// Consumes the builder and constructs a [`CreateChatTokenInput`](crate::operation::create_chat_token::CreateChatTokenInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_chat_token::CreateChatTokenInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_chat_token::CreateChatTokenInput {
            room_identifier: self.room_identifier,
            user_id: self.user_id,
            capabilities: self.capabilities,
            session_duration_in_minutes: self.session_duration_in_minutes,
            attributes: self.attributes,
        })
    }
}
impl ::std::fmt::Debug for CreateChatTokenInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateChatTokenInputBuilder");
        formatter.field("room_identifier", &self.room_identifier);
        formatter.field("user_id", &"*** Sensitive Data Redacted ***");
        formatter.field("capabilities", &self.capabilities);
        formatter.field("session_duration_in_minutes", &self.session_duration_in_minutes);
        formatter.field("attributes", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
