// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The filter for machine learning product entity IDs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MachineLearningProductEntityIdFilter {
    /// <p>A list of entity IDs to filter by. The operation returns machine learning products with entity IDs that match the values in this list.</p>
    pub value_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl MachineLearningProductEntityIdFilter {
    /// <p>A list of entity IDs to filter by. The operation returns machine learning products with entity IDs that match the values in this list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.value_list.is_none()`.
    pub fn value_list(&self) -> &[::std::string::String] {
        self.value_list.as_deref().unwrap_or_default()
    }
}
impl MachineLearningProductEntityIdFilter {
    /// Creates a new builder-style object to manufacture [`MachineLearningProductEntityIdFilter`](crate::types::MachineLearningProductEntityIdFilter).
    pub fn builder() -> crate::types::builders::MachineLearningProductEntityIdFilterBuilder {
        crate::types::builders::MachineLearningProductEntityIdFilterBuilder::default()
    }
}

/// A builder for [`MachineLearningProductEntityIdFilter`](crate::types::MachineLearningProductEntityIdFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MachineLearningProductEntityIdFilterBuilder {
    pub(crate) value_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl MachineLearningProductEntityIdFilterBuilder {
    /// Appends an item to `value_list`.
    ///
    /// To override the contents of this collection use [`set_value_list`](Self::set_value_list).
    ///
    /// <p>A list of entity IDs to filter by. The operation returns machine learning products with entity IDs that match the values in this list.</p>
    pub fn value_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.value_list.unwrap_or_default();
        v.push(input.into());
        self.value_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of entity IDs to filter by. The operation returns machine learning products with entity IDs that match the values in this list.</p>
    pub fn set_value_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.value_list = input;
        self
    }
    /// <p>A list of entity IDs to filter by. The operation returns machine learning products with entity IDs that match the values in this list.</p>
    pub fn get_value_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.value_list
    }
    /// Consumes the builder and constructs a [`MachineLearningProductEntityIdFilter`](crate::types::MachineLearningProductEntityIdFilter).
    pub fn build(self) -> crate::types::MachineLearningProductEntityIdFilter {
        crate::types::MachineLearningProductEntityIdFilter { value_list: self.value_list }
    }
}
