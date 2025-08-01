// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that specifies information about time series property values. This object is used and consumed by the <a href="https://docs.aws.amazon.com/iot-twinmaker/latest/apireference/API_BatchPutPropertyValues.html">BatchPutPropertyValues</a> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PropertyValueEntry {
    /// <p>An object that contains information about the entity that has the property.</p>
    pub entity_property_reference: ::std::option::Option<crate::types::EntityPropertyReference>,
    /// <p>A list of objects that specify time series property values.</p>
    pub property_values: ::std::option::Option<::std::vec::Vec<crate::types::PropertyValue>>,
}
impl PropertyValueEntry {
    /// <p>An object that contains information about the entity that has the property.</p>
    pub fn entity_property_reference(&self) -> ::std::option::Option<&crate::types::EntityPropertyReference> {
        self.entity_property_reference.as_ref()
    }
    /// <p>A list of objects that specify time series property values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.property_values.is_none()`.
    pub fn property_values(&self) -> &[crate::types::PropertyValue] {
        self.property_values.as_deref().unwrap_or_default()
    }
}
impl PropertyValueEntry {
    /// Creates a new builder-style object to manufacture [`PropertyValueEntry`](crate::types::PropertyValueEntry).
    pub fn builder() -> crate::types::builders::PropertyValueEntryBuilder {
        crate::types::builders::PropertyValueEntryBuilder::default()
    }
}

/// A builder for [`PropertyValueEntry`](crate::types::PropertyValueEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PropertyValueEntryBuilder {
    pub(crate) entity_property_reference: ::std::option::Option<crate::types::EntityPropertyReference>,
    pub(crate) property_values: ::std::option::Option<::std::vec::Vec<crate::types::PropertyValue>>,
}
impl PropertyValueEntryBuilder {
    /// <p>An object that contains information about the entity that has the property.</p>
    /// This field is required.
    pub fn entity_property_reference(mut self, input: crate::types::EntityPropertyReference) -> Self {
        self.entity_property_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information about the entity that has the property.</p>
    pub fn set_entity_property_reference(mut self, input: ::std::option::Option<crate::types::EntityPropertyReference>) -> Self {
        self.entity_property_reference = input;
        self
    }
    /// <p>An object that contains information about the entity that has the property.</p>
    pub fn get_entity_property_reference(&self) -> &::std::option::Option<crate::types::EntityPropertyReference> {
        &self.entity_property_reference
    }
    /// Appends an item to `property_values`.
    ///
    /// To override the contents of this collection use [`set_property_values`](Self::set_property_values).
    ///
    /// <p>A list of objects that specify time series property values.</p>
    pub fn property_values(mut self, input: crate::types::PropertyValue) -> Self {
        let mut v = self.property_values.unwrap_or_default();
        v.push(input);
        self.property_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of objects that specify time series property values.</p>
    pub fn set_property_values(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PropertyValue>>) -> Self {
        self.property_values = input;
        self
    }
    /// <p>A list of objects that specify time series property values.</p>
    pub fn get_property_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PropertyValue>> {
        &self.property_values
    }
    /// Consumes the builder and constructs a [`PropertyValueEntry`](crate::types::PropertyValueEntry).
    pub fn build(self) -> crate::types::PropertyValueEntry {
        crate::types::PropertyValueEntry {
            entity_property_reference: self.entity_property_reference,
            property_values: self.property_values,
        }
    }
}
