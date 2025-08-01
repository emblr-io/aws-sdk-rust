// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specific schema validation configuration settings that tell Lambda the message attributes you want to validate and filter using your schema registry.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KafkaSchemaValidationConfig {
    /// <p>The attributes you want your schema registry to validate and filter for. If you selected <code>JSON</code> as the <code>EventRecordFormat</code>, Lambda also deserializes the selected message attributes.</p>
    pub attribute: ::std::option::Option<crate::types::KafkaSchemaValidationAttribute>,
}
impl KafkaSchemaValidationConfig {
    /// <p>The attributes you want your schema registry to validate and filter for. If you selected <code>JSON</code> as the <code>EventRecordFormat</code>, Lambda also deserializes the selected message attributes.</p>
    pub fn attribute(&self) -> ::std::option::Option<&crate::types::KafkaSchemaValidationAttribute> {
        self.attribute.as_ref()
    }
}
impl KafkaSchemaValidationConfig {
    /// Creates a new builder-style object to manufacture [`KafkaSchemaValidationConfig`](crate::types::KafkaSchemaValidationConfig).
    pub fn builder() -> crate::types::builders::KafkaSchemaValidationConfigBuilder {
        crate::types::builders::KafkaSchemaValidationConfigBuilder::default()
    }
}

/// A builder for [`KafkaSchemaValidationConfig`](crate::types::KafkaSchemaValidationConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KafkaSchemaValidationConfigBuilder {
    pub(crate) attribute: ::std::option::Option<crate::types::KafkaSchemaValidationAttribute>,
}
impl KafkaSchemaValidationConfigBuilder {
    /// <p>The attributes you want your schema registry to validate and filter for. If you selected <code>JSON</code> as the <code>EventRecordFormat</code>, Lambda also deserializes the selected message attributes.</p>
    pub fn attribute(mut self, input: crate::types::KafkaSchemaValidationAttribute) -> Self {
        self.attribute = ::std::option::Option::Some(input);
        self
    }
    /// <p>The attributes you want your schema registry to validate and filter for. If you selected <code>JSON</code> as the <code>EventRecordFormat</code>, Lambda also deserializes the selected message attributes.</p>
    pub fn set_attribute(mut self, input: ::std::option::Option<crate::types::KafkaSchemaValidationAttribute>) -> Self {
        self.attribute = input;
        self
    }
    /// <p>The attributes you want your schema registry to validate and filter for. If you selected <code>JSON</code> as the <code>EventRecordFormat</code>, Lambda also deserializes the selected message attributes.</p>
    pub fn get_attribute(&self) -> &::std::option::Option<crate::types::KafkaSchemaValidationAttribute> {
        &self.attribute
    }
    /// Consumes the builder and constructs a [`KafkaSchemaValidationConfig`](crate::types::KafkaSchemaValidationConfig).
    pub fn build(self) -> crate::types::KafkaSchemaValidationConfig {
        crate::types::KafkaSchemaValidationConfig { attribute: self.attribute }
    }
}
