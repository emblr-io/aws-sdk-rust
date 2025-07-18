// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Filter for the DescribeActivation API.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeActivationsFilter {
    /// <p>The name of the filter.</p>
    pub filter_key: ::std::option::Option<crate::types::DescribeActivationsFilterKeys>,
    /// <p>The filter values.</p>
    pub filter_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeActivationsFilter {
    /// <p>The name of the filter.</p>
    pub fn filter_key(&self) -> ::std::option::Option<&crate::types::DescribeActivationsFilterKeys> {
        self.filter_key.as_ref()
    }
    /// <p>The filter values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filter_values.is_none()`.
    pub fn filter_values(&self) -> &[::std::string::String] {
        self.filter_values.as_deref().unwrap_or_default()
    }
}
impl DescribeActivationsFilter {
    /// Creates a new builder-style object to manufacture [`DescribeActivationsFilter`](crate::types::DescribeActivationsFilter).
    pub fn builder() -> crate::types::builders::DescribeActivationsFilterBuilder {
        crate::types::builders::DescribeActivationsFilterBuilder::default()
    }
}

/// A builder for [`DescribeActivationsFilter`](crate::types::DescribeActivationsFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeActivationsFilterBuilder {
    pub(crate) filter_key: ::std::option::Option<crate::types::DescribeActivationsFilterKeys>,
    pub(crate) filter_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeActivationsFilterBuilder {
    /// <p>The name of the filter.</p>
    pub fn filter_key(mut self, input: crate::types::DescribeActivationsFilterKeys) -> Self {
        self.filter_key = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the filter.</p>
    pub fn set_filter_key(mut self, input: ::std::option::Option<crate::types::DescribeActivationsFilterKeys>) -> Self {
        self.filter_key = input;
        self
    }
    /// <p>The name of the filter.</p>
    pub fn get_filter_key(&self) -> &::std::option::Option<crate::types::DescribeActivationsFilterKeys> {
        &self.filter_key
    }
    /// Appends an item to `filter_values`.
    ///
    /// To override the contents of this collection use [`set_filter_values`](Self::set_filter_values).
    ///
    /// <p>The filter values.</p>
    pub fn filter_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.filter_values.unwrap_or_default();
        v.push(input.into());
        self.filter_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The filter values.</p>
    pub fn set_filter_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.filter_values = input;
        self
    }
    /// <p>The filter values.</p>
    pub fn get_filter_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.filter_values
    }
    /// Consumes the builder and constructs a [`DescribeActivationsFilter`](crate::types::DescribeActivationsFilter).
    pub fn build(self) -> crate::types::DescribeActivationsFilter {
        crate::types::DescribeActivationsFilter {
            filter_key: self.filter_key,
            filter_values: self.filter_values,
        }
    }
}
