// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of message attribute values.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MessageAttributeValue {
    /// <p>The strings in a message attribute value.</p>
    pub string_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl MessageAttributeValue {
    /// <p>The strings in a message attribute value.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.string_values.is_none()`.
    pub fn string_values(&self) -> &[::std::string::String] {
        self.string_values.as_deref().unwrap_or_default()
    }
}
impl MessageAttributeValue {
    /// Creates a new builder-style object to manufacture [`MessageAttributeValue`](crate::types::MessageAttributeValue).
    pub fn builder() -> crate::types::builders::MessageAttributeValueBuilder {
        crate::types::builders::MessageAttributeValueBuilder::default()
    }
}

/// A builder for [`MessageAttributeValue`](crate::types::MessageAttributeValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MessageAttributeValueBuilder {
    pub(crate) string_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl MessageAttributeValueBuilder {
    /// Appends an item to `string_values`.
    ///
    /// To override the contents of this collection use [`set_string_values`](Self::set_string_values).
    ///
    /// <p>The strings in a message attribute value.</p>
    pub fn string_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.string_values.unwrap_or_default();
        v.push(input.into());
        self.string_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The strings in a message attribute value.</p>
    pub fn set_string_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.string_values = input;
        self
    }
    /// <p>The strings in a message attribute value.</p>
    pub fn get_string_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.string_values
    }
    /// Consumes the builder and constructs a [`MessageAttributeValue`](crate::types::MessageAttributeValue).
    pub fn build(self) -> crate::types::MessageAttributeValue {
        crate::types::MessageAttributeValue {
            string_values: self.string_values,
        }
    }
}
