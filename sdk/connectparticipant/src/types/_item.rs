// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An item - message or event - that has been sent.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Item {
    /// <p>The time when the message or event was sent.</p>
    /// <p>It's specified in ISO 8601 format: yyyy-MM-ddThh:mm:ss.SSSZ. For example, 2019-11-08T02:41:28.172Z.</p>
    pub absolute_time: ::std::option::Option<::std::string::String>,
    /// <p>The content of the message or event.</p>
    pub content: ::std::option::Option<::std::string::String>,
    /// <p>The type of content of the item.</p>
    pub content_type: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the item.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>Type of the item: message or event.</p>
    pub r#type: ::std::option::Option<crate::types::ChatItemType>,
    /// <p>The ID of the sender in the session.</p>
    pub participant_id: ::std::option::Option<::std::string::String>,
    /// <p>The chat display name of the sender.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>The role of the sender. For example, is it a customer, agent, or system.</p>
    pub participant_role: ::std::option::Option<crate::types::ParticipantRole>,
    /// <p>Provides information about the attachments.</p>
    pub attachments: ::std::option::Option<::std::vec::Vec<crate::types::AttachmentItem>>,
    /// <p>The metadata related to the message. Currently this supports only information related to message receipts.</p>
    pub message_metadata: ::std::option::Option<crate::types::MessageMetadata>,
    /// <p>The contactId on which the transcript item was originally sent. This field is only populated for persistent chats when the transcript item is from the past chat session. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/chat-persistence.html">Enable persistent chat</a>.</p>
    pub related_contact_id: ::std::option::Option<::std::string::String>,
    /// <p>The contactId on which the transcript item was originally sent. This field is populated only when the transcript item is from the current chat session.</p>
    pub contact_id: ::std::option::Option<::std::string::String>,
}
impl Item {
    /// <p>The time when the message or event was sent.</p>
    /// <p>It's specified in ISO 8601 format: yyyy-MM-ddThh:mm:ss.SSSZ. For example, 2019-11-08T02:41:28.172Z.</p>
    pub fn absolute_time(&self) -> ::std::option::Option<&str> {
        self.absolute_time.as_deref()
    }
    /// <p>The content of the message or event.</p>
    pub fn content(&self) -> ::std::option::Option<&str> {
        self.content.as_deref()
    }
    /// <p>The type of content of the item.</p>
    pub fn content_type(&self) -> ::std::option::Option<&str> {
        self.content_type.as_deref()
    }
    /// <p>The ID of the item.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>Type of the item: message or event.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ChatItemType> {
        self.r#type.as_ref()
    }
    /// <p>The ID of the sender in the session.</p>
    pub fn participant_id(&self) -> ::std::option::Option<&str> {
        self.participant_id.as_deref()
    }
    /// <p>The chat display name of the sender.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>The role of the sender. For example, is it a customer, agent, or system.</p>
    pub fn participant_role(&self) -> ::std::option::Option<&crate::types::ParticipantRole> {
        self.participant_role.as_ref()
    }
    /// <p>Provides information about the attachments.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attachments.is_none()`.
    pub fn attachments(&self) -> &[crate::types::AttachmentItem] {
        self.attachments.as_deref().unwrap_or_default()
    }
    /// <p>The metadata related to the message. Currently this supports only information related to message receipts.</p>
    pub fn message_metadata(&self) -> ::std::option::Option<&crate::types::MessageMetadata> {
        self.message_metadata.as_ref()
    }
    /// <p>The contactId on which the transcript item was originally sent. This field is only populated for persistent chats when the transcript item is from the past chat session. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/chat-persistence.html">Enable persistent chat</a>.</p>
    pub fn related_contact_id(&self) -> ::std::option::Option<&str> {
        self.related_contact_id.as_deref()
    }
    /// <p>The contactId on which the transcript item was originally sent. This field is populated only when the transcript item is from the current chat session.</p>
    pub fn contact_id(&self) -> ::std::option::Option<&str> {
        self.contact_id.as_deref()
    }
}
impl Item {
    /// Creates a new builder-style object to manufacture [`Item`](crate::types::Item).
    pub fn builder() -> crate::types::builders::ItemBuilder {
        crate::types::builders::ItemBuilder::default()
    }
}

/// A builder for [`Item`](crate::types::Item).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ItemBuilder {
    pub(crate) absolute_time: ::std::option::Option<::std::string::String>,
    pub(crate) content: ::std::option::Option<::std::string::String>,
    pub(crate) content_type: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::ChatItemType>,
    pub(crate) participant_id: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) participant_role: ::std::option::Option<crate::types::ParticipantRole>,
    pub(crate) attachments: ::std::option::Option<::std::vec::Vec<crate::types::AttachmentItem>>,
    pub(crate) message_metadata: ::std::option::Option<crate::types::MessageMetadata>,
    pub(crate) related_contact_id: ::std::option::Option<::std::string::String>,
    pub(crate) contact_id: ::std::option::Option<::std::string::String>,
}
impl ItemBuilder {
    /// <p>The time when the message or event was sent.</p>
    /// <p>It's specified in ISO 8601 format: yyyy-MM-ddThh:mm:ss.SSSZ. For example, 2019-11-08T02:41:28.172Z.</p>
    pub fn absolute_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.absolute_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time when the message or event was sent.</p>
    /// <p>It's specified in ISO 8601 format: yyyy-MM-ddThh:mm:ss.SSSZ. For example, 2019-11-08T02:41:28.172Z.</p>
    pub fn set_absolute_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.absolute_time = input;
        self
    }
    /// <p>The time when the message or event was sent.</p>
    /// <p>It's specified in ISO 8601 format: yyyy-MM-ddThh:mm:ss.SSSZ. For example, 2019-11-08T02:41:28.172Z.</p>
    pub fn get_absolute_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.absolute_time
    }
    /// <p>The content of the message or event.</p>
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content of the message or event.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    /// <p>The content of the message or event.</p>
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    /// <p>The type of content of the item.</p>
    pub fn content_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of content of the item.</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>The type of content of the item.</p>
    pub fn get_content_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_type
    }
    /// <p>The ID of the item.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the item.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the item.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Type of the item: message or event.</p>
    pub fn r#type(mut self, input: crate::types::ChatItemType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Type of the item: message or event.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ChatItemType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Type of the item: message or event.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ChatItemType> {
        &self.r#type
    }
    /// <p>The ID of the sender in the session.</p>
    pub fn participant_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.participant_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the sender in the session.</p>
    pub fn set_participant_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.participant_id = input;
        self
    }
    /// <p>The ID of the sender in the session.</p>
    pub fn get_participant_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.participant_id
    }
    /// <p>The chat display name of the sender.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The chat display name of the sender.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The chat display name of the sender.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>The role of the sender. For example, is it a customer, agent, or system.</p>
    pub fn participant_role(mut self, input: crate::types::ParticipantRole) -> Self {
        self.participant_role = ::std::option::Option::Some(input);
        self
    }
    /// <p>The role of the sender. For example, is it a customer, agent, or system.</p>
    pub fn set_participant_role(mut self, input: ::std::option::Option<crate::types::ParticipantRole>) -> Self {
        self.participant_role = input;
        self
    }
    /// <p>The role of the sender. For example, is it a customer, agent, or system.</p>
    pub fn get_participant_role(&self) -> &::std::option::Option<crate::types::ParticipantRole> {
        &self.participant_role
    }
    /// Appends an item to `attachments`.
    ///
    /// To override the contents of this collection use [`set_attachments`](Self::set_attachments).
    ///
    /// <p>Provides information about the attachments.</p>
    pub fn attachments(mut self, input: crate::types::AttachmentItem) -> Self {
        let mut v = self.attachments.unwrap_or_default();
        v.push(input);
        self.attachments = ::std::option::Option::Some(v);
        self
    }
    /// <p>Provides information about the attachments.</p>
    pub fn set_attachments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AttachmentItem>>) -> Self {
        self.attachments = input;
        self
    }
    /// <p>Provides information about the attachments.</p>
    pub fn get_attachments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AttachmentItem>> {
        &self.attachments
    }
    /// <p>The metadata related to the message. Currently this supports only information related to message receipts.</p>
    pub fn message_metadata(mut self, input: crate::types::MessageMetadata) -> Self {
        self.message_metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metadata related to the message. Currently this supports only information related to message receipts.</p>
    pub fn set_message_metadata(mut self, input: ::std::option::Option<crate::types::MessageMetadata>) -> Self {
        self.message_metadata = input;
        self
    }
    /// <p>The metadata related to the message. Currently this supports only information related to message receipts.</p>
    pub fn get_message_metadata(&self) -> &::std::option::Option<crate::types::MessageMetadata> {
        &self.message_metadata
    }
    /// <p>The contactId on which the transcript item was originally sent. This field is only populated for persistent chats when the transcript item is from the past chat session. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/chat-persistence.html">Enable persistent chat</a>.</p>
    pub fn related_contact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.related_contact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The contactId on which the transcript item was originally sent. This field is only populated for persistent chats when the transcript item is from the past chat session. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/chat-persistence.html">Enable persistent chat</a>.</p>
    pub fn set_related_contact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.related_contact_id = input;
        self
    }
    /// <p>The contactId on which the transcript item was originally sent. This field is only populated for persistent chats when the transcript item is from the past chat session. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/chat-persistence.html">Enable persistent chat</a>.</p>
    pub fn get_related_contact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.related_contact_id
    }
    /// <p>The contactId on which the transcript item was originally sent. This field is populated only when the transcript item is from the current chat session.</p>
    pub fn contact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.contact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The contactId on which the transcript item was originally sent. This field is populated only when the transcript item is from the current chat session.</p>
    pub fn set_contact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.contact_id = input;
        self
    }
    /// <p>The contactId on which the transcript item was originally sent. This field is populated only when the transcript item is from the current chat session.</p>
    pub fn get_contact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.contact_id
    }
    /// Consumes the builder and constructs a [`Item`](crate::types::Item).
    pub fn build(self) -> crate::types::Item {
        crate::types::Item {
            absolute_time: self.absolute_time,
            content: self.content,
            content_type: self.content_type,
            id: self.id,
            r#type: self.r#type,
            participant_id: self.participant_id,
            display_name: self.display_name,
            participant_role: self.participant_role,
            attachments: self.attachments,
            message_metadata: self.message_metadata,
            related_contact_id: self.related_contact_id,
            contact_id: self.contact_id,
        }
    }
}
