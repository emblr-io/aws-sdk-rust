// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The filter for machine learning product visibility status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MachineLearningProductVisibilityFilter {
    /// <p>A list of visibility values to filter by. The operation returns machine learning products with visibility status that match the values in this list.</p>
    pub value_list: ::std::option::Option<::std::vec::Vec<crate::types::MachineLearningProductVisibilityString>>,
}
impl MachineLearningProductVisibilityFilter {
    /// <p>A list of visibility values to filter by. The operation returns machine learning products with visibility status that match the values in this list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.value_list.is_none()`.
    pub fn value_list(&self) -> &[crate::types::MachineLearningProductVisibilityString] {
        self.value_list.as_deref().unwrap_or_default()
    }
}
impl MachineLearningProductVisibilityFilter {
    /// Creates a new builder-style object to manufacture [`MachineLearningProductVisibilityFilter`](crate::types::MachineLearningProductVisibilityFilter).
    pub fn builder() -> crate::types::builders::MachineLearningProductVisibilityFilterBuilder {
        crate::types::builders::MachineLearningProductVisibilityFilterBuilder::default()
    }
}

/// A builder for [`MachineLearningProductVisibilityFilter`](crate::types::MachineLearningProductVisibilityFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MachineLearningProductVisibilityFilterBuilder {
    pub(crate) value_list: ::std::option::Option<::std::vec::Vec<crate::types::MachineLearningProductVisibilityString>>,
}
impl MachineLearningProductVisibilityFilterBuilder {
    /// Appends an item to `value_list`.
    ///
    /// To override the contents of this collection use [`set_value_list`](Self::set_value_list).
    ///
    /// <p>A list of visibility values to filter by. The operation returns machine learning products with visibility status that match the values in this list.</p>
    pub fn value_list(mut self, input: crate::types::MachineLearningProductVisibilityString) -> Self {
        let mut v = self.value_list.unwrap_or_default();
        v.push(input);
        self.value_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of visibility values to filter by. The operation returns machine learning products with visibility status that match the values in this list.</p>
    pub fn set_value_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MachineLearningProductVisibilityString>>) -> Self {
        self.value_list = input;
        self
    }
    /// <p>A list of visibility values to filter by. The operation returns machine learning products with visibility status that match the values in this list.</p>
    pub fn get_value_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MachineLearningProductVisibilityString>> {
        &self.value_list
    }
    /// Consumes the builder and constructs a [`MachineLearningProductVisibilityFilter`](crate::types::MachineLearningProductVisibilityFilter).
    pub fn build(self) -> crate::types::MachineLearningProductVisibilityFilter {
        crate::types::MachineLearningProductVisibilityFilter { value_list: self.value_list }
    }
}
