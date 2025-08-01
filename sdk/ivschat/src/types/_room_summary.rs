// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information about a room.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RoomSummary {
    /// <p>Room ARN.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>Room ID, generated by the system. This is a relative identifier, the part of the ARN that uniquely identifies the room.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>Room name. The value does not need to be unique.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Configuration information for optional review of messages.</p>
    pub message_review_handler: ::std::option::Option<crate::types::MessageReviewHandler>,
    /// <p>Time when the room was created. This is an ISO 8601 timestamp; <i>note that this is returned as a string</i>.</p>
    pub create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Time of the room’s last update. This is an ISO 8601 timestamp; <i>note that this is returned as a string</i>.</p>
    pub update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Tags attached to the resource. Array of maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS Chat has no constraints beyond what is documented there.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>List of logging-configuration identifiers attached to the room.</p>
    pub logging_configuration_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RoomSummary {
    /// <p>Room ARN.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>Room ID, generated by the system. This is a relative identifier, the part of the ARN that uniquely identifies the room.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>Room name. The value does not need to be unique.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Configuration information for optional review of messages.</p>
    pub fn message_review_handler(&self) -> ::std::option::Option<&crate::types::MessageReviewHandler> {
        self.message_review_handler.as_ref()
    }
    /// <p>Time when the room was created. This is an ISO 8601 timestamp; <i>note that this is returned as a string</i>.</p>
    pub fn create_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_time.as_ref()
    }
    /// <p>Time of the room’s last update. This is an ISO 8601 timestamp; <i>note that this is returned as a string</i>.</p>
    pub fn update_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.update_time.as_ref()
    }
    /// <p>Tags attached to the resource. Array of maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS Chat has no constraints beyond what is documented there.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>List of logging-configuration identifiers attached to the room.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.logging_configuration_identifiers.is_none()`.
    pub fn logging_configuration_identifiers(&self) -> &[::std::string::String] {
        self.logging_configuration_identifiers.as_deref().unwrap_or_default()
    }
}
impl RoomSummary {
    /// Creates a new builder-style object to manufacture [`RoomSummary`](crate::types::RoomSummary).
    pub fn builder() -> crate::types::builders::RoomSummaryBuilder {
        crate::types::builders::RoomSummaryBuilder::default()
    }
}

/// A builder for [`RoomSummary`](crate::types::RoomSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RoomSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) message_review_handler: ::std::option::Option<crate::types::MessageReviewHandler>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) logging_configuration_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RoomSummaryBuilder {
    /// <p>Room ARN.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Room ARN.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>Room ARN.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>Room ID, generated by the system. This is a relative identifier, the part of the ARN that uniquely identifies the room.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Room ID, generated by the system. This is a relative identifier, the part of the ARN that uniquely identifies the room.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>Room ID, generated by the system. This is a relative identifier, the part of the ARN that uniquely identifies the room.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Room name. The value does not need to be unique.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Room name. The value does not need to be unique.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Room name. The value does not need to be unique.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Configuration information for optional review of messages.</p>
    pub fn message_review_handler(mut self, input: crate::types::MessageReviewHandler) -> Self {
        self.message_review_handler = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration information for optional review of messages.</p>
    pub fn set_message_review_handler(mut self, input: ::std::option::Option<crate::types::MessageReviewHandler>) -> Self {
        self.message_review_handler = input;
        self
    }
    /// <p>Configuration information for optional review of messages.</p>
    pub fn get_message_review_handler(&self) -> &::std::option::Option<crate::types::MessageReviewHandler> {
        &self.message_review_handler
    }
    /// <p>Time when the room was created. This is an ISO 8601 timestamp; <i>note that this is returned as a string</i>.</p>
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Time when the room was created. This is an ISO 8601 timestamp; <i>note that this is returned as a string</i>.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>Time when the room was created. This is an ISO 8601 timestamp; <i>note that this is returned as a string</i>.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>Time of the room’s last update. This is an ISO 8601 timestamp; <i>note that this is returned as a string</i>.</p>
    pub fn update_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.update_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Time of the room’s last update. This is an ISO 8601 timestamp; <i>note that this is returned as a string</i>.</p>
    pub fn set_update_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.update_time = input;
        self
    }
    /// <p>Time of the room’s last update. This is an ISO 8601 timestamp; <i>note that this is returned as a string</i>.</p>
    pub fn get_update_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.update_time
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags attached to the resource. Array of maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS Chat has no constraints beyond what is documented there.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tags attached to the resource. Array of maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS Chat has no constraints beyond what is documented there.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags attached to the resource. Array of maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS Chat has no constraints beyond what is documented there.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Appends an item to `logging_configuration_identifiers`.
    ///
    /// To override the contents of this collection use [`set_logging_configuration_identifiers`](Self::set_logging_configuration_identifiers).
    ///
    /// <p>List of logging-configuration identifiers attached to the room.</p>
    pub fn logging_configuration_identifiers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.logging_configuration_identifiers.unwrap_or_default();
        v.push(input.into());
        self.logging_configuration_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of logging-configuration identifiers attached to the room.</p>
    pub fn set_logging_configuration_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.logging_configuration_identifiers = input;
        self
    }
    /// <p>List of logging-configuration identifiers attached to the room.</p>
    pub fn get_logging_configuration_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.logging_configuration_identifiers
    }
    /// Consumes the builder and constructs a [`RoomSummary`](crate::types::RoomSummary).
    pub fn build(self) -> crate::types::RoomSummary {
        crate::types::RoomSummary {
            arn: self.arn,
            id: self.id,
            name: self.name,
            message_review_handler: self.message_review_handler,
            create_time: self.create_time,
            update_time: self.update_time,
            tags: self.tags,
            logging_configuration_identifiers: self.logging_configuration_identifiers,
        }
    }
}
