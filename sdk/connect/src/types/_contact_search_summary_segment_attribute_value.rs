// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The value of a segment attribute. This is structured as a map with a single key-value pair. The key 'valueString' indicates that the attribute type is a string, and its corresponding value is the actual string value of the segment attribute.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContactSearchSummarySegmentAttributeValue {
    /// <p>The value of a segment attribute represented as a string.</p>
    pub value_string: ::std::option::Option<::std::string::String>,
}
impl ContactSearchSummarySegmentAttributeValue {
    /// <p>The value of a segment attribute represented as a string.</p>
    pub fn value_string(&self) -> ::std::option::Option<&str> {
        self.value_string.as_deref()
    }
}
impl ContactSearchSummarySegmentAttributeValue {
    /// Creates a new builder-style object to manufacture [`ContactSearchSummarySegmentAttributeValue`](crate::types::ContactSearchSummarySegmentAttributeValue).
    pub fn builder() -> crate::types::builders::ContactSearchSummarySegmentAttributeValueBuilder {
        crate::types::builders::ContactSearchSummarySegmentAttributeValueBuilder::default()
    }
}

/// A builder for [`ContactSearchSummarySegmentAttributeValue`](crate::types::ContactSearchSummarySegmentAttributeValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContactSearchSummarySegmentAttributeValueBuilder {
    pub(crate) value_string: ::std::option::Option<::std::string::String>,
}
impl ContactSearchSummarySegmentAttributeValueBuilder {
    /// <p>The value of a segment attribute represented as a string.</p>
    pub fn value_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of a segment attribute represented as a string.</p>
    pub fn set_value_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value_string = input;
        self
    }
    /// <p>The value of a segment attribute represented as a string.</p>
    pub fn get_value_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.value_string
    }
    /// Consumes the builder and constructs a [`ContactSearchSummarySegmentAttributeValue`](crate::types::ContactSearchSummarySegmentAttributeValue).
    pub fn build(self) -> crate::types::ContactSearchSummarySegmentAttributeValue {
        crate::types::ContactSearchSummarySegmentAttributeValue {
            value_string: self.value_string,
        }
    }
}
