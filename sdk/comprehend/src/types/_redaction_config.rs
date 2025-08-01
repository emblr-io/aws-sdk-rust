// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides configuration parameters for PII entity redaction.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RedactionConfig {
    /// <p>An array of the types of PII entities that Amazon Comprehend detects in the input text for your request.</p>
    pub pii_entity_types: ::std::option::Option<::std::vec::Vec<crate::types::PiiEntityType>>,
    /// <p>Specifies whether the PII entity is redacted with the mask character or the entity type.</p>
    pub mask_mode: ::std::option::Option<crate::types::PiiEntitiesDetectionMaskMode>,
    /// <p>A character that replaces each character in the redacted PII entity.</p>
    pub mask_character: ::std::option::Option<::std::string::String>,
}
impl RedactionConfig {
    /// <p>An array of the types of PII entities that Amazon Comprehend detects in the input text for your request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.pii_entity_types.is_none()`.
    pub fn pii_entity_types(&self) -> &[crate::types::PiiEntityType] {
        self.pii_entity_types.as_deref().unwrap_or_default()
    }
    /// <p>Specifies whether the PII entity is redacted with the mask character or the entity type.</p>
    pub fn mask_mode(&self) -> ::std::option::Option<&crate::types::PiiEntitiesDetectionMaskMode> {
        self.mask_mode.as_ref()
    }
    /// <p>A character that replaces each character in the redacted PII entity.</p>
    pub fn mask_character(&self) -> ::std::option::Option<&str> {
        self.mask_character.as_deref()
    }
}
impl RedactionConfig {
    /// Creates a new builder-style object to manufacture [`RedactionConfig`](crate::types::RedactionConfig).
    pub fn builder() -> crate::types::builders::RedactionConfigBuilder {
        crate::types::builders::RedactionConfigBuilder::default()
    }
}

/// A builder for [`RedactionConfig`](crate::types::RedactionConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RedactionConfigBuilder {
    pub(crate) pii_entity_types: ::std::option::Option<::std::vec::Vec<crate::types::PiiEntityType>>,
    pub(crate) mask_mode: ::std::option::Option<crate::types::PiiEntitiesDetectionMaskMode>,
    pub(crate) mask_character: ::std::option::Option<::std::string::String>,
}
impl RedactionConfigBuilder {
    /// Appends an item to `pii_entity_types`.
    ///
    /// To override the contents of this collection use [`set_pii_entity_types`](Self::set_pii_entity_types).
    ///
    /// <p>An array of the types of PII entities that Amazon Comprehend detects in the input text for your request.</p>
    pub fn pii_entity_types(mut self, input: crate::types::PiiEntityType) -> Self {
        let mut v = self.pii_entity_types.unwrap_or_default();
        v.push(input);
        self.pii_entity_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of the types of PII entities that Amazon Comprehend detects in the input text for your request.</p>
    pub fn set_pii_entity_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PiiEntityType>>) -> Self {
        self.pii_entity_types = input;
        self
    }
    /// <p>An array of the types of PII entities that Amazon Comprehend detects in the input text for your request.</p>
    pub fn get_pii_entity_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PiiEntityType>> {
        &self.pii_entity_types
    }
    /// <p>Specifies whether the PII entity is redacted with the mask character or the entity type.</p>
    pub fn mask_mode(mut self, input: crate::types::PiiEntitiesDetectionMaskMode) -> Self {
        self.mask_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the PII entity is redacted with the mask character or the entity type.</p>
    pub fn set_mask_mode(mut self, input: ::std::option::Option<crate::types::PiiEntitiesDetectionMaskMode>) -> Self {
        self.mask_mode = input;
        self
    }
    /// <p>Specifies whether the PII entity is redacted with the mask character or the entity type.</p>
    pub fn get_mask_mode(&self) -> &::std::option::Option<crate::types::PiiEntitiesDetectionMaskMode> {
        &self.mask_mode
    }
    /// <p>A character that replaces each character in the redacted PII entity.</p>
    pub fn mask_character(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mask_character = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A character that replaces each character in the redacted PII entity.</p>
    pub fn set_mask_character(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mask_character = input;
        self
    }
    /// <p>A character that replaces each character in the redacted PII entity.</p>
    pub fn get_mask_character(&self) -> &::std::option::Option<::std::string::String> {
        &self.mask_character
    }
    /// Consumes the builder and constructs a [`RedactionConfig`](crate::types::RedactionConfig).
    pub fn build(self) -> crate::types::RedactionConfig {
        crate::types::RedactionConfig {
            pii_entity_types: self.pii_entity_types,
            mask_mode: self.mask_mode,
            mask_character: self.mask_character,
        }
    }
}
