// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The capability configuration for an Amazon Q in Connect assistant.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssistantCapabilityConfiguration {
    /// <p>The type of Amazon Q in Connect assistant capability.</p>
    pub r#type: ::std::option::Option<crate::types::AssistantCapabilityType>,
}
impl AssistantCapabilityConfiguration {
    /// <p>The type of Amazon Q in Connect assistant capability.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::AssistantCapabilityType> {
        self.r#type.as_ref()
    }
}
impl AssistantCapabilityConfiguration {
    /// Creates a new builder-style object to manufacture [`AssistantCapabilityConfiguration`](crate::types::AssistantCapabilityConfiguration).
    pub fn builder() -> crate::types::builders::AssistantCapabilityConfigurationBuilder {
        crate::types::builders::AssistantCapabilityConfigurationBuilder::default()
    }
}

/// A builder for [`AssistantCapabilityConfiguration`](crate::types::AssistantCapabilityConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssistantCapabilityConfigurationBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::AssistantCapabilityType>,
}
impl AssistantCapabilityConfigurationBuilder {
    /// <p>The type of Amazon Q in Connect assistant capability.</p>
    pub fn r#type(mut self, input: crate::types::AssistantCapabilityType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of Amazon Q in Connect assistant capability.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::AssistantCapabilityType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of Amazon Q in Connect assistant capability.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::AssistantCapabilityType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`AssistantCapabilityConfiguration`](crate::types::AssistantCapabilityConfiguration).
    pub fn build(self) -> crate::types::AssistantCapabilityConfiguration {
        crate::types::AssistantCapabilityConfiguration { r#type: self.r#type }
    }
}
