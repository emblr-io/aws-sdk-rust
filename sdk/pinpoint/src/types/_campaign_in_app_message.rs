// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>In-app message configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CampaignInAppMessage {
    /// <p>The message body of the notification, the email body or the text message.</p>
    pub body: ::std::option::Option<::std::string::String>,
    /// <p>In-app message content.</p>
    pub content: ::std::option::Option<::std::vec::Vec<crate::types::InAppMessageContent>>,
    /// <p>Custom config to be sent to client.</p>
    pub custom_config: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>In-app message layout.</p>
    pub layout: ::std::option::Option<crate::types::Layout>,
}
impl CampaignInAppMessage {
    /// <p>The message body of the notification, the email body or the text message.</p>
    pub fn body(&self) -> ::std::option::Option<&str> {
        self.body.as_deref()
    }
    /// <p>In-app message content.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.content.is_none()`.
    pub fn content(&self) -> &[crate::types::InAppMessageContent] {
        self.content.as_deref().unwrap_or_default()
    }
    /// <p>Custom config to be sent to client.</p>
    pub fn custom_config(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.custom_config.as_ref()
    }
    /// <p>In-app message layout.</p>
    pub fn layout(&self) -> ::std::option::Option<&crate::types::Layout> {
        self.layout.as_ref()
    }
}
impl CampaignInAppMessage {
    /// Creates a new builder-style object to manufacture [`CampaignInAppMessage`](crate::types::CampaignInAppMessage).
    pub fn builder() -> crate::types::builders::CampaignInAppMessageBuilder {
        crate::types::builders::CampaignInAppMessageBuilder::default()
    }
}

/// A builder for [`CampaignInAppMessage`](crate::types::CampaignInAppMessage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CampaignInAppMessageBuilder {
    pub(crate) body: ::std::option::Option<::std::string::String>,
    pub(crate) content: ::std::option::Option<::std::vec::Vec<crate::types::InAppMessageContent>>,
    pub(crate) custom_config: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) layout: ::std::option::Option<crate::types::Layout>,
}
impl CampaignInAppMessageBuilder {
    /// <p>The message body of the notification, the email body or the text message.</p>
    pub fn body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message body of the notification, the email body or the text message.</p>
    pub fn set_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.body = input;
        self
    }
    /// <p>The message body of the notification, the email body or the text message.</p>
    pub fn get_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.body
    }
    /// Appends an item to `content`.
    ///
    /// To override the contents of this collection use [`set_content`](Self::set_content).
    ///
    /// <p>In-app message content.</p>
    pub fn content(mut self, input: crate::types::InAppMessageContent) -> Self {
        let mut v = self.content.unwrap_or_default();
        v.push(input);
        self.content = ::std::option::Option::Some(v);
        self
    }
    /// <p>In-app message content.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InAppMessageContent>>) -> Self {
        self.content = input;
        self
    }
    /// <p>In-app message content.</p>
    pub fn get_content(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InAppMessageContent>> {
        &self.content
    }
    /// Adds a key-value pair to `custom_config`.
    ///
    /// To override the contents of this collection use [`set_custom_config`](Self::set_custom_config).
    ///
    /// <p>Custom config to be sent to client.</p>
    pub fn custom_config(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.custom_config.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.custom_config = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Custom config to be sent to client.</p>
    pub fn set_custom_config(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.custom_config = input;
        self
    }
    /// <p>Custom config to be sent to client.</p>
    pub fn get_custom_config(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.custom_config
    }
    /// <p>In-app message layout.</p>
    pub fn layout(mut self, input: crate::types::Layout) -> Self {
        self.layout = ::std::option::Option::Some(input);
        self
    }
    /// <p>In-app message layout.</p>
    pub fn set_layout(mut self, input: ::std::option::Option<crate::types::Layout>) -> Self {
        self.layout = input;
        self
    }
    /// <p>In-app message layout.</p>
    pub fn get_layout(&self) -> &::std::option::Option<crate::types::Layout> {
        &self.layout
    }
    /// Consumes the builder and constructs a [`CampaignInAppMessage`](crate::types::CampaignInAppMessage).
    pub fn build(self) -> crate::types::CampaignInAppMessage {
        crate::types::CampaignInAppMessage {
            body: self.body,
            content: self.content,
            custom_config: self.custom_config,
            layout: self.layout,
        }
    }
}
