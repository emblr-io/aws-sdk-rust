// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a value for a resource attribute that is a Boolean value.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AttributeBooleanValue {
    /// <p>The attribute value. The valid values are <code>true</code> or <code>false</code>.</p>
    pub value: ::std::option::Option<bool>,
}
impl AttributeBooleanValue {
    /// <p>The attribute value. The valid values are <code>true</code> or <code>false</code>.</p>
    pub fn value(&self) -> ::std::option::Option<bool> {
        self.value
    }
}
impl AttributeBooleanValue {
    /// Creates a new builder-style object to manufacture [`AttributeBooleanValue`](crate::types::AttributeBooleanValue).
    pub fn builder() -> crate::types::builders::AttributeBooleanValueBuilder {
        crate::types::builders::AttributeBooleanValueBuilder::default()
    }
}

/// A builder for [`AttributeBooleanValue`](crate::types::AttributeBooleanValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AttributeBooleanValueBuilder {
    pub(crate) value: ::std::option::Option<bool>,
}
impl AttributeBooleanValueBuilder {
    /// <p>The attribute value. The valid values are <code>true</code> or <code>false</code>.</p>
    pub fn value(mut self, input: bool) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The attribute value. The valid values are <code>true</code> or <code>false</code>.</p>
    pub fn set_value(mut self, input: ::std::option::Option<bool>) -> Self {
        self.value = input;
        self
    }
    /// <p>The attribute value. The valid values are <code>true</code> or <code>false</code>.</p>
    pub fn get_value(&self) -> &::std::option::Option<bool> {
        &self.value
    }
    /// Consumes the builder and constructs a [`AttributeBooleanValue`](crate::types::AttributeBooleanValue).
    pub fn build(self) -> crate::types::AttributeBooleanValue {
        crate::types::AttributeBooleanValue { value: self.value }
    }
}
