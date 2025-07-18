// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a channel namespace associated with an <code>Api</code>. The <code>ChannelNamespace</code> contains the definitions for code handlers for the <code>Api</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChannelNamespace {
    /// <p>The <code>Api</code> ID.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the channel namespace. This name must be unique within the <code>Api</code>.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The authorization mode to use for subscribing to messages on the channel namespace. This configuration overrides the default <code>Api</code>authorization configuration.</p>
    pub subscribe_auth_modes: ::std::option::Option<::std::vec::Vec<crate::types::AuthMode>>,
    /// <p>The authorization mode to use for publishing messages on the channel namespace. This configuration overrides the default <code>Api</code>authorization configuration.</p>
    pub publish_auth_modes: ::std::option::Option<::std::vec::Vec<crate::types::AuthMode>>,
    /// <p>The event handler functions that run custom business logic to process published events and subscribe requests.</p>
    pub code_handlers: ::std::option::Option<::std::string::String>,
    /// <p>A map with keys of <code>TagKey</code> objects and values of <code>TagValue</code> objects.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The Amazon Resource Name (ARN) for the <code>ChannelNamespace</code>.</p>
    pub channel_namespace_arn: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the <code>ChannelNamespace</code> was created.</p>
    pub created: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the <code>ChannelNamespace</code> was last changed.</p>
    pub last_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The configuration for the <code>OnPublish</code> and <code>OnSubscribe</code> handlers.</p>
    pub handler_configs: ::std::option::Option<crate::types::HandlerConfigs>,
}
impl ChannelNamespace {
    /// <p>The <code>Api</code> ID.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
    /// <p>The name of the channel namespace. This name must be unique within the <code>Api</code>.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The authorization mode to use for subscribing to messages on the channel namespace. This configuration overrides the default <code>Api</code>authorization configuration.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subscribe_auth_modes.is_none()`.
    pub fn subscribe_auth_modes(&self) -> &[crate::types::AuthMode] {
        self.subscribe_auth_modes.as_deref().unwrap_or_default()
    }
    /// <p>The authorization mode to use for publishing messages on the channel namespace. This configuration overrides the default <code>Api</code>authorization configuration.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.publish_auth_modes.is_none()`.
    pub fn publish_auth_modes(&self) -> &[crate::types::AuthMode] {
        self.publish_auth_modes.as_deref().unwrap_or_default()
    }
    /// <p>The event handler functions that run custom business logic to process published events and subscribe requests.</p>
    pub fn code_handlers(&self) -> ::std::option::Option<&str> {
        self.code_handlers.as_deref()
    }
    /// <p>A map with keys of <code>TagKey</code> objects and values of <code>TagValue</code> objects.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) for the <code>ChannelNamespace</code>.</p>
    pub fn channel_namespace_arn(&self) -> ::std::option::Option<&str> {
        self.channel_namespace_arn.as_deref()
    }
    /// <p>The date and time that the <code>ChannelNamespace</code> was created.</p>
    pub fn created(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created.as_ref()
    }
    /// <p>The date and time that the <code>ChannelNamespace</code> was last changed.</p>
    pub fn last_modified(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified.as_ref()
    }
    /// <p>The configuration for the <code>OnPublish</code> and <code>OnSubscribe</code> handlers.</p>
    pub fn handler_configs(&self) -> ::std::option::Option<&crate::types::HandlerConfigs> {
        self.handler_configs.as_ref()
    }
}
impl ChannelNamespace {
    /// Creates a new builder-style object to manufacture [`ChannelNamespace`](crate::types::ChannelNamespace).
    pub fn builder() -> crate::types::builders::ChannelNamespaceBuilder {
        crate::types::builders::ChannelNamespaceBuilder::default()
    }
}

/// A builder for [`ChannelNamespace`](crate::types::ChannelNamespace).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChannelNamespaceBuilder {
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) subscribe_auth_modes: ::std::option::Option<::std::vec::Vec<crate::types::AuthMode>>,
    pub(crate) publish_auth_modes: ::std::option::Option<::std::vec::Vec<crate::types::AuthMode>>,
    pub(crate) code_handlers: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) channel_namespace_arn: ::std::option::Option<::std::string::String>,
    pub(crate) created: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) handler_configs: ::std::option::Option<crate::types::HandlerConfigs>,
}
impl ChannelNamespaceBuilder {
    /// <p>The <code>Api</code> ID.</p>
    pub fn api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>Api</code> ID.</p>
    pub fn set_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_id = input;
        self
    }
    /// <p>The <code>Api</code> ID.</p>
    pub fn get_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_id
    }
    /// <p>The name of the channel namespace. This name must be unique within the <code>Api</code>.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the channel namespace. This name must be unique within the <code>Api</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the channel namespace. This name must be unique within the <code>Api</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `subscribe_auth_modes`.
    ///
    /// To override the contents of this collection use [`set_subscribe_auth_modes`](Self::set_subscribe_auth_modes).
    ///
    /// <p>The authorization mode to use for subscribing to messages on the channel namespace. This configuration overrides the default <code>Api</code>authorization configuration.</p>
    pub fn subscribe_auth_modes(mut self, input: crate::types::AuthMode) -> Self {
        let mut v = self.subscribe_auth_modes.unwrap_or_default();
        v.push(input);
        self.subscribe_auth_modes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The authorization mode to use for subscribing to messages on the channel namespace. This configuration overrides the default <code>Api</code>authorization configuration.</p>
    pub fn set_subscribe_auth_modes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AuthMode>>) -> Self {
        self.subscribe_auth_modes = input;
        self
    }
    /// <p>The authorization mode to use for subscribing to messages on the channel namespace. This configuration overrides the default <code>Api</code>authorization configuration.</p>
    pub fn get_subscribe_auth_modes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AuthMode>> {
        &self.subscribe_auth_modes
    }
    /// Appends an item to `publish_auth_modes`.
    ///
    /// To override the contents of this collection use [`set_publish_auth_modes`](Self::set_publish_auth_modes).
    ///
    /// <p>The authorization mode to use for publishing messages on the channel namespace. This configuration overrides the default <code>Api</code>authorization configuration.</p>
    pub fn publish_auth_modes(mut self, input: crate::types::AuthMode) -> Self {
        let mut v = self.publish_auth_modes.unwrap_or_default();
        v.push(input);
        self.publish_auth_modes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The authorization mode to use for publishing messages on the channel namespace. This configuration overrides the default <code>Api</code>authorization configuration.</p>
    pub fn set_publish_auth_modes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AuthMode>>) -> Self {
        self.publish_auth_modes = input;
        self
    }
    /// <p>The authorization mode to use for publishing messages on the channel namespace. This configuration overrides the default <code>Api</code>authorization configuration.</p>
    pub fn get_publish_auth_modes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AuthMode>> {
        &self.publish_auth_modes
    }
    /// <p>The event handler functions that run custom business logic to process published events and subscribe requests.</p>
    pub fn code_handlers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code_handlers = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The event handler functions that run custom business logic to process published events and subscribe requests.</p>
    pub fn set_code_handlers(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code_handlers = input;
        self
    }
    /// <p>The event handler functions that run custom business logic to process published events and subscribe requests.</p>
    pub fn get_code_handlers(&self) -> &::std::option::Option<::std::string::String> {
        &self.code_handlers
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A map with keys of <code>TagKey</code> objects and values of <code>TagValue</code> objects.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map with keys of <code>TagKey</code> objects and values of <code>TagValue</code> objects.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A map with keys of <code>TagKey</code> objects and values of <code>TagValue</code> objects.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The Amazon Resource Name (ARN) for the <code>ChannelNamespace</code>.</p>
    pub fn channel_namespace_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_namespace_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the <code>ChannelNamespace</code>.</p>
    pub fn set_channel_namespace_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_namespace_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the <code>ChannelNamespace</code>.</p>
    pub fn get_channel_namespace_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_namespace_arn
    }
    /// <p>The date and time that the <code>ChannelNamespace</code> was created.</p>
    pub fn created(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the <code>ChannelNamespace</code> was created.</p>
    pub fn set_created(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created = input;
        self
    }
    /// <p>The date and time that the <code>ChannelNamespace</code> was created.</p>
    pub fn get_created(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created
    }
    /// <p>The date and time that the <code>ChannelNamespace</code> was last changed.</p>
    pub fn last_modified(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the <code>ChannelNamespace</code> was last changed.</p>
    pub fn set_last_modified(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified = input;
        self
    }
    /// <p>The date and time that the <code>ChannelNamespace</code> was last changed.</p>
    pub fn get_last_modified(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified
    }
    /// <p>The configuration for the <code>OnPublish</code> and <code>OnSubscribe</code> handlers.</p>
    pub fn handler_configs(mut self, input: crate::types::HandlerConfigs) -> Self {
        self.handler_configs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for the <code>OnPublish</code> and <code>OnSubscribe</code> handlers.</p>
    pub fn set_handler_configs(mut self, input: ::std::option::Option<crate::types::HandlerConfigs>) -> Self {
        self.handler_configs = input;
        self
    }
    /// <p>The configuration for the <code>OnPublish</code> and <code>OnSubscribe</code> handlers.</p>
    pub fn get_handler_configs(&self) -> &::std::option::Option<crate::types::HandlerConfigs> {
        &self.handler_configs
    }
    /// Consumes the builder and constructs a [`ChannelNamespace`](crate::types::ChannelNamespace).
    pub fn build(self) -> crate::types::ChannelNamespace {
        crate::types::ChannelNamespace {
            api_id: self.api_id,
            name: self.name,
            subscribe_auth_modes: self.subscribe_auth_modes,
            publish_auth_modes: self.publish_auth_modes,
            code_handlers: self.code_handlers,
            tags: self.tags,
            channel_namespace_arn: self.channel_namespace_arn,
            created: self.created,
            last_modified: self.last_modified,
            handler_configs: self.handler_configs,
        }
    }
}
