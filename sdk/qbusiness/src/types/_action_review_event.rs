// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An output event that Amazon Q Business returns to an user who wants to perform a plugin action during a streaming chat conversation. It contains information about the selected action with a list of possible user input fields, some pre-populated by Amazon Q Business.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActionReviewEvent {
    /// <p>The identifier of the conversation with which the action review event is associated.</p>
    pub conversation_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the conversation with which the plugin action is associated.</p>
    pub user_message_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of an Amazon Q Business AI generated associated with the action review event.</p>
    pub system_message_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the plugin associated with the action review event.</p>
    pub plugin_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of plugin.</p>
    pub plugin_type: ::std::option::Option<crate::types::PluginType>,
    /// <p>Field values that an end user needs to provide to Amazon Q Business for Amazon Q Business to perform the requested plugin action.</p>
    pub payload: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionReviewPayloadField>>,
    /// <p>A string used to retain information about the hierarchical contexts within an action review event payload.</p>
    pub payload_field_name_separator: ::std::option::Option<::std::string::String>,
}
impl ActionReviewEvent {
    /// <p>The identifier of the conversation with which the action review event is associated.</p>
    pub fn conversation_id(&self) -> ::std::option::Option<&str> {
        self.conversation_id.as_deref()
    }
    /// <p>The identifier of the conversation with which the plugin action is associated.</p>
    pub fn user_message_id(&self) -> ::std::option::Option<&str> {
        self.user_message_id.as_deref()
    }
    /// <p>The identifier of an Amazon Q Business AI generated associated with the action review event.</p>
    pub fn system_message_id(&self) -> ::std::option::Option<&str> {
        self.system_message_id.as_deref()
    }
    /// <p>The identifier of the plugin associated with the action review event.</p>
    pub fn plugin_id(&self) -> ::std::option::Option<&str> {
        self.plugin_id.as_deref()
    }
    /// <p>The type of plugin.</p>
    pub fn plugin_type(&self) -> ::std::option::Option<&crate::types::PluginType> {
        self.plugin_type.as_ref()
    }
    /// <p>Field values that an end user needs to provide to Amazon Q Business for Amazon Q Business to perform the requested plugin action.</p>
    pub fn payload(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::ActionReviewPayloadField>> {
        self.payload.as_ref()
    }
    /// <p>A string used to retain information about the hierarchical contexts within an action review event payload.</p>
    pub fn payload_field_name_separator(&self) -> ::std::option::Option<&str> {
        self.payload_field_name_separator.as_deref()
    }
}
impl ActionReviewEvent {
    /// Creates a new builder-style object to manufacture [`ActionReviewEvent`](crate::types::ActionReviewEvent).
    pub fn builder() -> crate::types::builders::ActionReviewEventBuilder {
        crate::types::builders::ActionReviewEventBuilder::default()
    }
}

/// A builder for [`ActionReviewEvent`](crate::types::ActionReviewEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActionReviewEventBuilder {
    pub(crate) conversation_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_message_id: ::std::option::Option<::std::string::String>,
    pub(crate) system_message_id: ::std::option::Option<::std::string::String>,
    pub(crate) plugin_id: ::std::option::Option<::std::string::String>,
    pub(crate) plugin_type: ::std::option::Option<crate::types::PluginType>,
    pub(crate) payload: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionReviewPayloadField>>,
    pub(crate) payload_field_name_separator: ::std::option::Option<::std::string::String>,
}
impl ActionReviewEventBuilder {
    /// <p>The identifier of the conversation with which the action review event is associated.</p>
    pub fn conversation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conversation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the conversation with which the action review event is associated.</p>
    pub fn set_conversation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conversation_id = input;
        self
    }
    /// <p>The identifier of the conversation with which the action review event is associated.</p>
    pub fn get_conversation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.conversation_id
    }
    /// <p>The identifier of the conversation with which the plugin action is associated.</p>
    pub fn user_message_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_message_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the conversation with which the plugin action is associated.</p>
    pub fn set_user_message_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_message_id = input;
        self
    }
    /// <p>The identifier of the conversation with which the plugin action is associated.</p>
    pub fn get_user_message_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_message_id
    }
    /// <p>The identifier of an Amazon Q Business AI generated associated with the action review event.</p>
    pub fn system_message_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.system_message_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of an Amazon Q Business AI generated associated with the action review event.</p>
    pub fn set_system_message_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.system_message_id = input;
        self
    }
    /// <p>The identifier of an Amazon Q Business AI generated associated with the action review event.</p>
    pub fn get_system_message_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.system_message_id
    }
    /// <p>The identifier of the plugin associated with the action review event.</p>
    pub fn plugin_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.plugin_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the plugin associated with the action review event.</p>
    pub fn set_plugin_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.plugin_id = input;
        self
    }
    /// <p>The identifier of the plugin associated with the action review event.</p>
    pub fn get_plugin_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.plugin_id
    }
    /// <p>The type of plugin.</p>
    pub fn plugin_type(mut self, input: crate::types::PluginType) -> Self {
        self.plugin_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of plugin.</p>
    pub fn set_plugin_type(mut self, input: ::std::option::Option<crate::types::PluginType>) -> Self {
        self.plugin_type = input;
        self
    }
    /// <p>The type of plugin.</p>
    pub fn get_plugin_type(&self) -> &::std::option::Option<crate::types::PluginType> {
        &self.plugin_type
    }
    /// Adds a key-value pair to `payload`.
    ///
    /// To override the contents of this collection use [`set_payload`](Self::set_payload).
    ///
    /// <p>Field values that an end user needs to provide to Amazon Q Business for Amazon Q Business to perform the requested plugin action.</p>
    pub fn payload(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::ActionReviewPayloadField) -> Self {
        let mut hash_map = self.payload.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.payload = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Field values that an end user needs to provide to Amazon Q Business for Amazon Q Business to perform the requested plugin action.</p>
    pub fn set_payload(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionReviewPayloadField>>,
    ) -> Self {
        self.payload = input;
        self
    }
    /// <p>Field values that an end user needs to provide to Amazon Q Business for Amazon Q Business to perform the requested plugin action.</p>
    pub fn get_payload(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionReviewPayloadField>> {
        &self.payload
    }
    /// <p>A string used to retain information about the hierarchical contexts within an action review event payload.</p>
    pub fn payload_field_name_separator(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.payload_field_name_separator = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string used to retain information about the hierarchical contexts within an action review event payload.</p>
    pub fn set_payload_field_name_separator(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.payload_field_name_separator = input;
        self
    }
    /// <p>A string used to retain information about the hierarchical contexts within an action review event payload.</p>
    pub fn get_payload_field_name_separator(&self) -> &::std::option::Option<::std::string::String> {
        &self.payload_field_name_separator
    }
    /// Consumes the builder and constructs a [`ActionReviewEvent`](crate::types::ActionReviewEvent).
    pub fn build(self) -> crate::types::ActionReviewEvent {
        crate::types::ActionReviewEvent {
            conversation_id: self.conversation_id,
            user_message_id: self.user_message_id,
            system_message_id: self.system_message_id,
            plugin_id: self.plugin_id,
            plugin_type: self.plugin_type,
            payload: self.payload,
            payload_field_name_separator: self.payload_field_name_separator,
        }
    }
}
