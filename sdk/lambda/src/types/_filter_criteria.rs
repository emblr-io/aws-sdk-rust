// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains the filters for an event source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FilterCriteria {
    /// <p>A list of filters.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
}
impl FilterCriteria {
    /// <p>A list of filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
}
impl FilterCriteria {
    /// Creates a new builder-style object to manufacture [`FilterCriteria`](crate::types::FilterCriteria).
    pub fn builder() -> crate::types::builders::FilterCriteriaBuilder {
        crate::types::builders::FilterCriteriaBuilder::default()
    }
}

/// A builder for [`FilterCriteria`](crate::types::FilterCriteria).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilterCriteriaBuilder {
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
}
impl FilterCriteriaBuilder {
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>A list of filters.</p>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of filters.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>A list of filters.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// Consumes the builder and constructs a [`FilterCriteria`](crate::types::FilterCriteria).
    pub fn build(self) -> crate::types::FilterCriteria {
        crate::types::FilterCriteria { filters: self.filters }
    }
}
