// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The attributes that are used with the message template.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct MessageTemplateAttributes {
    /// <p>The system attributes that are used with the message template.</p>
    pub system_attributes: ::std::option::Option<crate::types::SystemAttributes>,
    /// <p>The agent attributes that are used with the message template.</p>
    pub agent_attributes: ::std::option::Option<crate::types::AgentAttributes>,
    /// <p>The customer profile attributes that are used with the message template.</p>
    pub customer_profile_attributes: ::std::option::Option<crate::types::CustomerProfileAttributes>,
    /// <p>The custom attributes that are used with the message template.</p>
    pub custom_attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl MessageTemplateAttributes {
    /// <p>The system attributes that are used with the message template.</p>
    pub fn system_attributes(&self) -> ::std::option::Option<&crate::types::SystemAttributes> {
        self.system_attributes.as_ref()
    }
    /// <p>The agent attributes that are used with the message template.</p>
    pub fn agent_attributes(&self) -> ::std::option::Option<&crate::types::AgentAttributes> {
        self.agent_attributes.as_ref()
    }
    /// <p>The customer profile attributes that are used with the message template.</p>
    pub fn customer_profile_attributes(&self) -> ::std::option::Option<&crate::types::CustomerProfileAttributes> {
        self.customer_profile_attributes.as_ref()
    }
    /// <p>The custom attributes that are used with the message template.</p>
    pub fn custom_attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.custom_attributes.as_ref()
    }
}
impl ::std::fmt::Debug for MessageTemplateAttributes {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("MessageTemplateAttributes");
        formatter.field("system_attributes", &self.system_attributes);
        formatter.field("agent_attributes", &self.agent_attributes);
        formatter.field("customer_profile_attributes", &self.customer_profile_attributes);
        formatter.field("custom_attributes", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl MessageTemplateAttributes {
    /// Creates a new builder-style object to manufacture [`MessageTemplateAttributes`](crate::types::MessageTemplateAttributes).
    pub fn builder() -> crate::types::builders::MessageTemplateAttributesBuilder {
        crate::types::builders::MessageTemplateAttributesBuilder::default()
    }
}

/// A builder for [`MessageTemplateAttributes`](crate::types::MessageTemplateAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct MessageTemplateAttributesBuilder {
    pub(crate) system_attributes: ::std::option::Option<crate::types::SystemAttributes>,
    pub(crate) agent_attributes: ::std::option::Option<crate::types::AgentAttributes>,
    pub(crate) customer_profile_attributes: ::std::option::Option<crate::types::CustomerProfileAttributes>,
    pub(crate) custom_attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl MessageTemplateAttributesBuilder {
    /// <p>The system attributes that are used with the message template.</p>
    pub fn system_attributes(mut self, input: crate::types::SystemAttributes) -> Self {
        self.system_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The system attributes that are used with the message template.</p>
    pub fn set_system_attributes(mut self, input: ::std::option::Option<crate::types::SystemAttributes>) -> Self {
        self.system_attributes = input;
        self
    }
    /// <p>The system attributes that are used with the message template.</p>
    pub fn get_system_attributes(&self) -> &::std::option::Option<crate::types::SystemAttributes> {
        &self.system_attributes
    }
    /// <p>The agent attributes that are used with the message template.</p>
    pub fn agent_attributes(mut self, input: crate::types::AgentAttributes) -> Self {
        self.agent_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The agent attributes that are used with the message template.</p>
    pub fn set_agent_attributes(mut self, input: ::std::option::Option<crate::types::AgentAttributes>) -> Self {
        self.agent_attributes = input;
        self
    }
    /// <p>The agent attributes that are used with the message template.</p>
    pub fn get_agent_attributes(&self) -> &::std::option::Option<crate::types::AgentAttributes> {
        &self.agent_attributes
    }
    /// <p>The customer profile attributes that are used with the message template.</p>
    pub fn customer_profile_attributes(mut self, input: crate::types::CustomerProfileAttributes) -> Self {
        self.customer_profile_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The customer profile attributes that are used with the message template.</p>
    pub fn set_customer_profile_attributes(mut self, input: ::std::option::Option<crate::types::CustomerProfileAttributes>) -> Self {
        self.customer_profile_attributes = input;
        self
    }
    /// <p>The customer profile attributes that are used with the message template.</p>
    pub fn get_customer_profile_attributes(&self) -> &::std::option::Option<crate::types::CustomerProfileAttributes> {
        &self.customer_profile_attributes
    }
    /// Adds a key-value pair to `custom_attributes`.
    ///
    /// To override the contents of this collection use [`set_custom_attributes`](Self::set_custom_attributes).
    ///
    /// <p>The custom attributes that are used with the message template.</p>
    pub fn custom_attributes(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.custom_attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.custom_attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The custom attributes that are used with the message template.</p>
    pub fn set_custom_attributes(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.custom_attributes = input;
        self
    }
    /// <p>The custom attributes that are used with the message template.</p>
    pub fn get_custom_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.custom_attributes
    }
    /// Consumes the builder and constructs a [`MessageTemplateAttributes`](crate::types::MessageTemplateAttributes).
    pub fn build(self) -> crate::types::MessageTemplateAttributes {
        crate::types::MessageTemplateAttributes {
            system_attributes: self.system_attributes,
            agent_attributes: self.agent_attributes,
            customer_profile_attributes: self.customer_profile_attributes,
            custom_attributes: self.custom_attributes,
        }
    }
}
impl ::std::fmt::Debug for MessageTemplateAttributesBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("MessageTemplateAttributesBuilder");
        formatter.field("system_attributes", &self.system_attributes);
        formatter.field("agent_attributes", &self.agent_attributes);
        formatter.field("customer_profile_attributes", &self.customer_profile_attributes);
        formatter.field("custom_attributes", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
