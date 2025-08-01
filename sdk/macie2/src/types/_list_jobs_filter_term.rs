// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a condition that filters the results of a request for information about classification jobs. Each condition consists of a property, an operator, and one or more values.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListJobsFilterTerm {
    /// <p>The operator to use to filter the results.</p>
    pub comparator: ::std::option::Option<crate::types::JobComparator>,
    /// <p>The property to use to filter the results.</p>
    pub key: ::std::option::Option<crate::types::ListJobsFilterKey>,
    /// <p>An array that lists one or more values to use to filter the results.</p>
    pub values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListJobsFilterTerm {
    /// <p>The operator to use to filter the results.</p>
    pub fn comparator(&self) -> ::std::option::Option<&crate::types::JobComparator> {
        self.comparator.as_ref()
    }
    /// <p>The property to use to filter the results.</p>
    pub fn key(&self) -> ::std::option::Option<&crate::types::ListJobsFilterKey> {
        self.key.as_ref()
    }
    /// <p>An array that lists one or more values to use to filter the results.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.values.is_none()`.
    pub fn values(&self) -> &[::std::string::String] {
        self.values.as_deref().unwrap_or_default()
    }
}
impl ListJobsFilterTerm {
    /// Creates a new builder-style object to manufacture [`ListJobsFilterTerm`](crate::types::ListJobsFilterTerm).
    pub fn builder() -> crate::types::builders::ListJobsFilterTermBuilder {
        crate::types::builders::ListJobsFilterTermBuilder::default()
    }
}

/// A builder for [`ListJobsFilterTerm`](crate::types::ListJobsFilterTerm).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListJobsFilterTermBuilder {
    pub(crate) comparator: ::std::option::Option<crate::types::JobComparator>,
    pub(crate) key: ::std::option::Option<crate::types::ListJobsFilterKey>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListJobsFilterTermBuilder {
    /// <p>The operator to use to filter the results.</p>
    pub fn comparator(mut self, input: crate::types::JobComparator) -> Self {
        self.comparator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operator to use to filter the results.</p>
    pub fn set_comparator(mut self, input: ::std::option::Option<crate::types::JobComparator>) -> Self {
        self.comparator = input;
        self
    }
    /// <p>The operator to use to filter the results.</p>
    pub fn get_comparator(&self) -> &::std::option::Option<crate::types::JobComparator> {
        &self.comparator
    }
    /// <p>The property to use to filter the results.</p>
    pub fn key(mut self, input: crate::types::ListJobsFilterKey) -> Self {
        self.key = ::std::option::Option::Some(input);
        self
    }
    /// <p>The property to use to filter the results.</p>
    pub fn set_key(mut self, input: ::std::option::Option<crate::types::ListJobsFilterKey>) -> Self {
        self.key = input;
        self
    }
    /// <p>The property to use to filter the results.</p>
    pub fn get_key(&self) -> &::std::option::Option<crate::types::ListJobsFilterKey> {
        &self.key
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>An array that lists one or more values to use to filter the results.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array that lists one or more values to use to filter the results.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>An array that lists one or more values to use to filter the results.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`ListJobsFilterTerm`](crate::types::ListJobsFilterTerm).
    pub fn build(self) -> crate::types::ListJobsFilterTerm {
        crate::types::ListJobsFilterTerm {
            comparator: self.comparator,
            key: self.key,
            values: self.values,
        }
    }
}
