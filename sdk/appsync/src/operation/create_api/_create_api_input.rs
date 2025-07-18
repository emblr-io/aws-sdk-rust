// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateApiInput {
    /// <p>The name for the <code>Api</code>.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The owner contact information for the <code>Api</code>.</p>
    pub owner_contact: ::std::option::Option<::std::string::String>,
    /// <p>A map with keys of <code>TagKey</code> objects and values of <code>TagValue</code> objects.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The Event API configuration. This includes the default authorization configuration for connecting, publishing, and subscribing to an Event API.</p>
    pub event_config: ::std::option::Option<crate::types::EventConfig>,
}
impl CreateApiInput {
    /// <p>The name for the <code>Api</code>.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The owner contact information for the <code>Api</code>.</p>
    pub fn owner_contact(&self) -> ::std::option::Option<&str> {
        self.owner_contact.as_deref()
    }
    /// <p>A map with keys of <code>TagKey</code> objects and values of <code>TagValue</code> objects.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The Event API configuration. This includes the default authorization configuration for connecting, publishing, and subscribing to an Event API.</p>
    pub fn event_config(&self) -> ::std::option::Option<&crate::types::EventConfig> {
        self.event_config.as_ref()
    }
}
impl CreateApiInput {
    /// Creates a new builder-style object to manufacture [`CreateApiInput`](crate::operation::create_api::CreateApiInput).
    pub fn builder() -> crate::operation::create_api::builders::CreateApiInputBuilder {
        crate::operation::create_api::builders::CreateApiInputBuilder::default()
    }
}

/// A builder for [`CreateApiInput`](crate::operation::create_api::CreateApiInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateApiInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) owner_contact: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) event_config: ::std::option::Option<crate::types::EventConfig>,
}
impl CreateApiInputBuilder {
    /// <p>The name for the <code>Api</code>.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name for the <code>Api</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name for the <code>Api</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The owner contact information for the <code>Api</code>.</p>
    pub fn owner_contact(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_contact = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner contact information for the <code>Api</code>.</p>
    pub fn set_owner_contact(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_contact = input;
        self
    }
    /// <p>The owner contact information for the <code>Api</code>.</p>
    pub fn get_owner_contact(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_contact
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
    /// <p>The Event API configuration. This includes the default authorization configuration for connecting, publishing, and subscribing to an Event API.</p>
    pub fn event_config(mut self, input: crate::types::EventConfig) -> Self {
        self.event_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Event API configuration. This includes the default authorization configuration for connecting, publishing, and subscribing to an Event API.</p>
    pub fn set_event_config(mut self, input: ::std::option::Option<crate::types::EventConfig>) -> Self {
        self.event_config = input;
        self
    }
    /// <p>The Event API configuration. This includes the default authorization configuration for connecting, publishing, and subscribing to an Event API.</p>
    pub fn get_event_config(&self) -> &::std::option::Option<crate::types::EventConfig> {
        &self.event_config
    }
    /// Consumes the builder and constructs a [`CreateApiInput`](crate::operation::create_api::CreateApiInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_api::CreateApiInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_api::CreateApiInput {
            name: self.name,
            owner_contact: self.owner_contact,
            tags: self.tags,
            event_config: self.event_config,
        })
    }
}
