// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The latest value of the property.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PropertyLatestValue {
    /// <p>An object that specifies information about a property.</p>
    pub property_reference: ::std::option::Option<crate::types::EntityPropertyReference>,
    /// <p>The value of the property.</p>
    pub property_value: ::std::option::Option<crate::types::DataValue>,
}
impl PropertyLatestValue {
    /// <p>An object that specifies information about a property.</p>
    pub fn property_reference(&self) -> ::std::option::Option<&crate::types::EntityPropertyReference> {
        self.property_reference.as_ref()
    }
    /// <p>The value of the property.</p>
    pub fn property_value(&self) -> ::std::option::Option<&crate::types::DataValue> {
        self.property_value.as_ref()
    }
}
impl PropertyLatestValue {
    /// Creates a new builder-style object to manufacture [`PropertyLatestValue`](crate::types::PropertyLatestValue).
    pub fn builder() -> crate::types::builders::PropertyLatestValueBuilder {
        crate::types::builders::PropertyLatestValueBuilder::default()
    }
}

/// A builder for [`PropertyLatestValue`](crate::types::PropertyLatestValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PropertyLatestValueBuilder {
    pub(crate) property_reference: ::std::option::Option<crate::types::EntityPropertyReference>,
    pub(crate) property_value: ::std::option::Option<crate::types::DataValue>,
}
impl PropertyLatestValueBuilder {
    /// <p>An object that specifies information about a property.</p>
    /// This field is required.
    pub fn property_reference(mut self, input: crate::types::EntityPropertyReference) -> Self {
        self.property_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that specifies information about a property.</p>
    pub fn set_property_reference(mut self, input: ::std::option::Option<crate::types::EntityPropertyReference>) -> Self {
        self.property_reference = input;
        self
    }
    /// <p>An object that specifies information about a property.</p>
    pub fn get_property_reference(&self) -> &::std::option::Option<crate::types::EntityPropertyReference> {
        &self.property_reference
    }
    /// <p>The value of the property.</p>
    pub fn property_value(mut self, input: crate::types::DataValue) -> Self {
        self.property_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value of the property.</p>
    pub fn set_property_value(mut self, input: ::std::option::Option<crate::types::DataValue>) -> Self {
        self.property_value = input;
        self
    }
    /// <p>The value of the property.</p>
    pub fn get_property_value(&self) -> &::std::option::Option<crate::types::DataValue> {
        &self.property_value
    }
    /// Consumes the builder and constructs a [`PropertyLatestValue`](crate::types::PropertyLatestValue).
    pub fn build(self) -> crate::types::PropertyLatestValue {
        crate::types::PropertyLatestValue {
            property_reference: self.property_reference,
            property_value: self.property_value,
        }
    }
}
