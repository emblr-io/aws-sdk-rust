// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the content, including message variables and attributes, to use in a message that's sent directly to an endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EndpointSendConfiguration {
    /// <p>The body of the message. If specified, this value overrides the default message body.</p>
    pub body_override: ::std::option::Option<::std::string::String>,
    /// <p>A map of custom attributes to attach to the message for the address. Attribute names are case sensitive.</p>
    /// <p>For a push notification, this payload is added to the data.pinpoint object. For an email or text message, this payload is added to email/SMS delivery receipt event attributes.</p>
    pub context: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The raw, JSON-formatted string to use as the payload for the message. If specified, this value overrides all other values for the message.</p>
    pub raw_content: ::std::option::Option<::std::string::String>,
    /// <p>A map of the message variables to merge with the variables specified for the default message (DefaultMessage.Substitutions). The variables specified in this map take precedence over all other variables.</p>
    pub substitutions: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    /// <p>The title or subject line of the message. If specified, this value overrides the default message title or subject line.</p>
    pub title_override: ::std::option::Option<::std::string::String>,
}
impl EndpointSendConfiguration {
    /// <p>The body of the message. If specified, this value overrides the default message body.</p>
    pub fn body_override(&self) -> ::std::option::Option<&str> {
        self.body_override.as_deref()
    }
    /// <p>A map of custom attributes to attach to the message for the address. Attribute names are case sensitive.</p>
    /// <p>For a push notification, this payload is added to the data.pinpoint object. For an email or text message, this payload is added to email/SMS delivery receipt event attributes.</p>
    pub fn context(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.context.as_ref()
    }
    /// <p>The raw, JSON-formatted string to use as the payload for the message. If specified, this value overrides all other values for the message.</p>
    pub fn raw_content(&self) -> ::std::option::Option<&str> {
        self.raw_content.as_deref()
    }
    /// <p>A map of the message variables to merge with the variables specified for the default message (DefaultMessage.Substitutions). The variables specified in this map take precedence over all other variables.</p>
    pub fn substitutions(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        self.substitutions.as_ref()
    }
    /// <p>The title or subject line of the message. If specified, this value overrides the default message title or subject line.</p>
    pub fn title_override(&self) -> ::std::option::Option<&str> {
        self.title_override.as_deref()
    }
}
impl EndpointSendConfiguration {
    /// Creates a new builder-style object to manufacture [`EndpointSendConfiguration`](crate::types::EndpointSendConfiguration).
    pub fn builder() -> crate::types::builders::EndpointSendConfigurationBuilder {
        crate::types::builders::EndpointSendConfigurationBuilder::default()
    }
}

/// A builder for [`EndpointSendConfiguration`](crate::types::EndpointSendConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EndpointSendConfigurationBuilder {
    pub(crate) body_override: ::std::option::Option<::std::string::String>,
    pub(crate) context: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) raw_content: ::std::option::Option<::std::string::String>,
    pub(crate) substitutions: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    pub(crate) title_override: ::std::option::Option<::std::string::String>,
}
impl EndpointSendConfigurationBuilder {
    /// <p>The body of the message. If specified, this value overrides the default message body.</p>
    pub fn body_override(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.body_override = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The body of the message. If specified, this value overrides the default message body.</p>
    pub fn set_body_override(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.body_override = input;
        self
    }
    /// <p>The body of the message. If specified, this value overrides the default message body.</p>
    pub fn get_body_override(&self) -> &::std::option::Option<::std::string::String> {
        &self.body_override
    }
    /// Adds a key-value pair to `context`.
    ///
    /// To override the contents of this collection use [`set_context`](Self::set_context).
    ///
    /// <p>A map of custom attributes to attach to the message for the address. Attribute names are case sensitive.</p>
    /// <p>For a push notification, this payload is added to the data.pinpoint object. For an email or text message, this payload is added to email/SMS delivery receipt event attributes.</p>
    pub fn context(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.context.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.context = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of custom attributes to attach to the message for the address. Attribute names are case sensitive.</p>
    /// <p>For a push notification, this payload is added to the data.pinpoint object. For an email or text message, this payload is added to email/SMS delivery receipt event attributes.</p>
    pub fn set_context(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.context = input;
        self
    }
    /// <p>A map of custom attributes to attach to the message for the address. Attribute names are case sensitive.</p>
    /// <p>For a push notification, this payload is added to the data.pinpoint object. For an email or text message, this payload is added to email/SMS delivery receipt event attributes.</p>
    pub fn get_context(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.context
    }
    /// <p>The raw, JSON-formatted string to use as the payload for the message. If specified, this value overrides all other values for the message.</p>
    pub fn raw_content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.raw_content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The raw, JSON-formatted string to use as the payload for the message. If specified, this value overrides all other values for the message.</p>
    pub fn set_raw_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.raw_content = input;
        self
    }
    /// <p>The raw, JSON-formatted string to use as the payload for the message. If specified, this value overrides all other values for the message.</p>
    pub fn get_raw_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.raw_content
    }
    /// Adds a key-value pair to `substitutions`.
    ///
    /// To override the contents of this collection use [`set_substitutions`](Self::set_substitutions).
    ///
    /// <p>A map of the message variables to merge with the variables specified for the default message (DefaultMessage.Substitutions). The variables specified in this map take precedence over all other variables.</p>
    pub fn substitutions(mut self, k: impl ::std::convert::Into<::std::string::String>, v: ::std::vec::Vec<::std::string::String>) -> Self {
        let mut hash_map = self.substitutions.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.substitutions = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of the message variables to merge with the variables specified for the default message (DefaultMessage.Substitutions). The variables specified in this map take precedence over all other variables.</p>
    pub fn set_substitutions(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    ) -> Self {
        self.substitutions = input;
        self
    }
    /// <p>A map of the message variables to merge with the variables specified for the default message (DefaultMessage.Substitutions). The variables specified in this map take precedence over all other variables.</p>
    pub fn get_substitutions(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        &self.substitutions
    }
    /// <p>The title or subject line of the message. If specified, this value overrides the default message title or subject line.</p>
    pub fn title_override(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title_override = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title or subject line of the message. If specified, this value overrides the default message title or subject line.</p>
    pub fn set_title_override(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title_override = input;
        self
    }
    /// <p>The title or subject line of the message. If specified, this value overrides the default message title or subject line.</p>
    pub fn get_title_override(&self) -> &::std::option::Option<::std::string::String> {
        &self.title_override
    }
    /// Consumes the builder and constructs a [`EndpointSendConfiguration`](crate::types::EndpointSendConfiguration).
    pub fn build(self) -> crate::types::EndpointSendConfiguration {
        crate::types::EndpointSendConfiguration {
            body_override: self.body_override,
            context: self.context,
            raw_content: self.raw_content,
            substitutions: self.substitutions,
            title_override: self.title_override,
        }
    }
}
