// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Thing group properties.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ThingGroupProperties {
    /// <p>The thing group description.</p>
    pub thing_group_description: ::std::option::Option<::std::string::String>,
    /// <p>The thing group attributes in JSON format.</p>
    pub attribute_payload: ::std::option::Option<crate::types::AttributePayload>,
}
impl ThingGroupProperties {
    /// <p>The thing group description.</p>
    pub fn thing_group_description(&self) -> ::std::option::Option<&str> {
        self.thing_group_description.as_deref()
    }
    /// <p>The thing group attributes in JSON format.</p>
    pub fn attribute_payload(&self) -> ::std::option::Option<&crate::types::AttributePayload> {
        self.attribute_payload.as_ref()
    }
}
impl ThingGroupProperties {
    /// Creates a new builder-style object to manufacture [`ThingGroupProperties`](crate::types::ThingGroupProperties).
    pub fn builder() -> crate::types::builders::ThingGroupPropertiesBuilder {
        crate::types::builders::ThingGroupPropertiesBuilder::default()
    }
}

/// A builder for [`ThingGroupProperties`](crate::types::ThingGroupProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ThingGroupPropertiesBuilder {
    pub(crate) thing_group_description: ::std::option::Option<::std::string::String>,
    pub(crate) attribute_payload: ::std::option::Option<crate::types::AttributePayload>,
}
impl ThingGroupPropertiesBuilder {
    /// <p>The thing group description.</p>
    pub fn thing_group_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_group_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The thing group description.</p>
    pub fn set_thing_group_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_group_description = input;
        self
    }
    /// <p>The thing group description.</p>
    pub fn get_thing_group_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_group_description
    }
    /// <p>The thing group attributes in JSON format.</p>
    pub fn attribute_payload(mut self, input: crate::types::AttributePayload) -> Self {
        self.attribute_payload = ::std::option::Option::Some(input);
        self
    }
    /// <p>The thing group attributes in JSON format.</p>
    pub fn set_attribute_payload(mut self, input: ::std::option::Option<crate::types::AttributePayload>) -> Self {
        self.attribute_payload = input;
        self
    }
    /// <p>The thing group attributes in JSON format.</p>
    pub fn get_attribute_payload(&self) -> &::std::option::Option<crate::types::AttributePayload> {
        &self.attribute_payload
    }
    /// Consumes the builder and constructs a [`ThingGroupProperties`](crate::types::ThingGroupProperties).
    pub fn build(self) -> crate::types::ThingGroupProperties {
        crate::types::ThingGroupProperties {
            thing_group_description: self.thing_group_description,
            attribute_payload: self.attribute_payload,
        }
    }
}
