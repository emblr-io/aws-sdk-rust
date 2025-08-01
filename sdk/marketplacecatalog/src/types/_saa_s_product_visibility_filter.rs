// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Object that allows filtering on the visibility of the product in the AWS Marketplace.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SaaSProductVisibilityFilter {
    /// <p>A string array of unique visibility values to be filtered on.</p>
    pub value_list: ::std::option::Option<::std::vec::Vec<crate::types::SaaSProductVisibilityString>>,
}
impl SaaSProductVisibilityFilter {
    /// <p>A string array of unique visibility values to be filtered on.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.value_list.is_none()`.
    pub fn value_list(&self) -> &[crate::types::SaaSProductVisibilityString] {
        self.value_list.as_deref().unwrap_or_default()
    }
}
impl SaaSProductVisibilityFilter {
    /// Creates a new builder-style object to manufacture [`SaaSProductVisibilityFilter`](crate::types::SaaSProductVisibilityFilter).
    pub fn builder() -> crate::types::builders::SaaSProductVisibilityFilterBuilder {
        crate::types::builders::SaaSProductVisibilityFilterBuilder::default()
    }
}

/// A builder for [`SaaSProductVisibilityFilter`](crate::types::SaaSProductVisibilityFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SaaSProductVisibilityFilterBuilder {
    pub(crate) value_list: ::std::option::Option<::std::vec::Vec<crate::types::SaaSProductVisibilityString>>,
}
impl SaaSProductVisibilityFilterBuilder {
    /// Appends an item to `value_list`.
    ///
    /// To override the contents of this collection use [`set_value_list`](Self::set_value_list).
    ///
    /// <p>A string array of unique visibility values to be filtered on.</p>
    pub fn value_list(mut self, input: crate::types::SaaSProductVisibilityString) -> Self {
        let mut v = self.value_list.unwrap_or_default();
        v.push(input);
        self.value_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A string array of unique visibility values to be filtered on.</p>
    pub fn set_value_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SaaSProductVisibilityString>>) -> Self {
        self.value_list = input;
        self
    }
    /// <p>A string array of unique visibility values to be filtered on.</p>
    pub fn get_value_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SaaSProductVisibilityString>> {
        &self.value_list
    }
    /// Consumes the builder and constructs a [`SaaSProductVisibilityFilter`](crate::types::SaaSProductVisibilityFilter).
    pub fn build(self) -> crate::types::SaaSProductVisibilityFilter {
        crate::types::SaaSProductVisibilityFilter { value_list: self.value_list }
    }
}
