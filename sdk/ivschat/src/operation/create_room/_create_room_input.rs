// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRoomInput {
    /// <p>Room name. The value does not need to be unique.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of messages per second that can be sent to the room (by all clients). Default: 10.</p>
    pub maximum_message_rate_per_second: ::std::option::Option<i32>,
    /// <p>Maximum number of characters in a single message. Messages are expected to be UTF-8 encoded and this limit applies specifically to rune/code-point count, not number of bytes. Default: 500.</p>
    pub maximum_message_length: ::std::option::Option<i32>,
    /// <p>Configuration information for optional review of messages.</p>
    pub message_review_handler: ::std::option::Option<crate::types::MessageReviewHandler>,
    /// <p>Tags to attach to the resource. Array of maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS Chat has no constraints beyond what is documented there.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Array of logging-configuration identifiers attached to the room.</p>
    pub logging_configuration_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CreateRoomInput {
    /// <p>Room name. The value does not need to be unique.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Maximum number of messages per second that can be sent to the room (by all clients). Default: 10.</p>
    pub fn maximum_message_rate_per_second(&self) -> ::std::option::Option<i32> {
        self.maximum_message_rate_per_second
    }
    /// <p>Maximum number of characters in a single message. Messages are expected to be UTF-8 encoded and this limit applies specifically to rune/code-point count, not number of bytes. Default: 500.</p>
    pub fn maximum_message_length(&self) -> ::std::option::Option<i32> {
        self.maximum_message_length
    }
    /// <p>Configuration information for optional review of messages.</p>
    pub fn message_review_handler(&self) -> ::std::option::Option<&crate::types::MessageReviewHandler> {
        self.message_review_handler.as_ref()
    }
    /// <p>Tags to attach to the resource. Array of maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS Chat has no constraints beyond what is documented there.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>Array of logging-configuration identifiers attached to the room.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.logging_configuration_identifiers.is_none()`.
    pub fn logging_configuration_identifiers(&self) -> &[::std::string::String] {
        self.logging_configuration_identifiers.as_deref().unwrap_or_default()
    }
}
impl CreateRoomInput {
    /// Creates a new builder-style object to manufacture [`CreateRoomInput`](crate::operation::create_room::CreateRoomInput).
    pub fn builder() -> crate::operation::create_room::builders::CreateRoomInputBuilder {
        crate::operation::create_room::builders::CreateRoomInputBuilder::default()
    }
}

/// A builder for [`CreateRoomInput`](crate::operation::create_room::CreateRoomInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRoomInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) maximum_message_rate_per_second: ::std::option::Option<i32>,
    pub(crate) maximum_message_length: ::std::option::Option<i32>,
    pub(crate) message_review_handler: ::std::option::Option<crate::types::MessageReviewHandler>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) logging_configuration_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CreateRoomInputBuilder {
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
    /// <p>Maximum number of messages per second that can be sent to the room (by all clients). Default: 10.</p>
    pub fn maximum_message_rate_per_second(mut self, input: i32) -> Self {
        self.maximum_message_rate_per_second = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of messages per second that can be sent to the room (by all clients). Default: 10.</p>
    pub fn set_maximum_message_rate_per_second(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_message_rate_per_second = input;
        self
    }
    /// <p>Maximum number of messages per second that can be sent to the room (by all clients). Default: 10.</p>
    pub fn get_maximum_message_rate_per_second(&self) -> &::std::option::Option<i32> {
        &self.maximum_message_rate_per_second
    }
    /// <p>Maximum number of characters in a single message. Messages are expected to be UTF-8 encoded and this limit applies specifically to rune/code-point count, not number of bytes. Default: 500.</p>
    pub fn maximum_message_length(mut self, input: i32) -> Self {
        self.maximum_message_length = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of characters in a single message. Messages are expected to be UTF-8 encoded and this limit applies specifically to rune/code-point count, not number of bytes. Default: 500.</p>
    pub fn set_maximum_message_length(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_message_length = input;
        self
    }
    /// <p>Maximum number of characters in a single message. Messages are expected to be UTF-8 encoded and this limit applies specifically to rune/code-point count, not number of bytes. Default: 500.</p>
    pub fn get_maximum_message_length(&self) -> &::std::option::Option<i32> {
        &self.maximum_message_length
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
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags to attach to the resource. Array of maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS Chat has no constraints beyond what is documented there.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tags to attach to the resource. Array of maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS Chat has no constraints beyond what is documented there.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags to attach to the resource. Array of maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS Chat has no constraints beyond what is documented there.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Appends an item to `logging_configuration_identifiers`.
    ///
    /// To override the contents of this collection use [`set_logging_configuration_identifiers`](Self::set_logging_configuration_identifiers).
    ///
    /// <p>Array of logging-configuration identifiers attached to the room.</p>
    pub fn logging_configuration_identifiers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.logging_configuration_identifiers.unwrap_or_default();
        v.push(input.into());
        self.logging_configuration_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>Array of logging-configuration identifiers attached to the room.</p>
    pub fn set_logging_configuration_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.logging_configuration_identifiers = input;
        self
    }
    /// <p>Array of logging-configuration identifiers attached to the room.</p>
    pub fn get_logging_configuration_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.logging_configuration_identifiers
    }
    /// Consumes the builder and constructs a [`CreateRoomInput`](crate::operation::create_room::CreateRoomInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_room::CreateRoomInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_room::CreateRoomInput {
            name: self.name,
            maximum_message_rate_per_second: self.maximum_message_rate_per_second,
            maximum_message_length: self.maximum_message_length,
            message_review_handler: self.message_review_handler,
            tags: self.tags,
            logging_configuration_identifiers: self.logging_configuration_identifiers,
        })
    }
}
