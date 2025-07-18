// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details regarding all the supported <code>FieldTypes</code> and their corresponding <code>filterOperators</code> and <code>supportedValues</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SupportedFieldTypeDetails {
    /// <p>The initial supported version for <code>fieldType</code>. If this is later changed to a different version, v2 will be introduced.</p>
    pub v1: ::std::option::Option<crate::types::FieldTypeDetails>,
}
impl SupportedFieldTypeDetails {
    /// <p>The initial supported version for <code>fieldType</code>. If this is later changed to a different version, v2 will be introduced.</p>
    pub fn v1(&self) -> ::std::option::Option<&crate::types::FieldTypeDetails> {
        self.v1.as_ref()
    }
}
impl SupportedFieldTypeDetails {
    /// Creates a new builder-style object to manufacture [`SupportedFieldTypeDetails`](crate::types::SupportedFieldTypeDetails).
    pub fn builder() -> crate::types::builders::SupportedFieldTypeDetailsBuilder {
        crate::types::builders::SupportedFieldTypeDetailsBuilder::default()
    }
}

/// A builder for [`SupportedFieldTypeDetails`](crate::types::SupportedFieldTypeDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SupportedFieldTypeDetailsBuilder {
    pub(crate) v1: ::std::option::Option<crate::types::FieldTypeDetails>,
}
impl SupportedFieldTypeDetailsBuilder {
    /// <p>The initial supported version for <code>fieldType</code>. If this is later changed to a different version, v2 will be introduced.</p>
    /// This field is required.
    pub fn v1(mut self, input: crate::types::FieldTypeDetails) -> Self {
        self.v1 = ::std::option::Option::Some(input);
        self
    }
    /// <p>The initial supported version for <code>fieldType</code>. If this is later changed to a different version, v2 will be introduced.</p>
    pub fn set_v1(mut self, input: ::std::option::Option<crate::types::FieldTypeDetails>) -> Self {
        self.v1 = input;
        self
    }
    /// <p>The initial supported version for <code>fieldType</code>. If this is later changed to a different version, v2 will be introduced.</p>
    pub fn get_v1(&self) -> &::std::option::Option<crate::types::FieldTypeDetails> {
        &self.v1
    }
    /// Consumes the builder and constructs a [`SupportedFieldTypeDetails`](crate::types::SupportedFieldTypeDetails).
    pub fn build(self) -> crate::types::SupportedFieldTypeDetails {
        crate::types::SupportedFieldTypeDetails { v1: self.v1 }
    }
}
