// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The sort configuration of a pie chart.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PieChartSortConfiguration {
    /// <p>The sort configuration of the category fields.</p>
    pub category_sort: ::std::option::Option<::std::vec::Vec<crate::types::FieldSortOptions>>,
    /// <p>The limit on the number of categories that are displayed in a pie chart.</p>
    pub category_items_limit: ::std::option::Option<crate::types::ItemsLimitConfiguration>,
    /// <p>The sort configuration of the small multiples field.</p>
    pub small_multiples_sort: ::std::option::Option<::std::vec::Vec<crate::types::FieldSortOptions>>,
    /// <p>The limit on the number of small multiples panels that are displayed.</p>
    pub small_multiples_limit_configuration: ::std::option::Option<crate::types::ItemsLimitConfiguration>,
}
impl PieChartSortConfiguration {
    /// <p>The sort configuration of the category fields.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.category_sort.is_none()`.
    pub fn category_sort(&self) -> &[crate::types::FieldSortOptions] {
        self.category_sort.as_deref().unwrap_or_default()
    }
    /// <p>The limit on the number of categories that are displayed in a pie chart.</p>
    pub fn category_items_limit(&self) -> ::std::option::Option<&crate::types::ItemsLimitConfiguration> {
        self.category_items_limit.as_ref()
    }
    /// <p>The sort configuration of the small multiples field.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.small_multiples_sort.is_none()`.
    pub fn small_multiples_sort(&self) -> &[crate::types::FieldSortOptions] {
        self.small_multiples_sort.as_deref().unwrap_or_default()
    }
    /// <p>The limit on the number of small multiples panels that are displayed.</p>
    pub fn small_multiples_limit_configuration(&self) -> ::std::option::Option<&crate::types::ItemsLimitConfiguration> {
        self.small_multiples_limit_configuration.as_ref()
    }
}
impl PieChartSortConfiguration {
    /// Creates a new builder-style object to manufacture [`PieChartSortConfiguration`](crate::types::PieChartSortConfiguration).
    pub fn builder() -> crate::types::builders::PieChartSortConfigurationBuilder {
        crate::types::builders::PieChartSortConfigurationBuilder::default()
    }
}

/// A builder for [`PieChartSortConfiguration`](crate::types::PieChartSortConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PieChartSortConfigurationBuilder {
    pub(crate) category_sort: ::std::option::Option<::std::vec::Vec<crate::types::FieldSortOptions>>,
    pub(crate) category_items_limit: ::std::option::Option<crate::types::ItemsLimitConfiguration>,
    pub(crate) small_multiples_sort: ::std::option::Option<::std::vec::Vec<crate::types::FieldSortOptions>>,
    pub(crate) small_multiples_limit_configuration: ::std::option::Option<crate::types::ItemsLimitConfiguration>,
}
impl PieChartSortConfigurationBuilder {
    /// Appends an item to `category_sort`.
    ///
    /// To override the contents of this collection use [`set_category_sort`](Self::set_category_sort).
    ///
    /// <p>The sort configuration of the category fields.</p>
    pub fn category_sort(mut self, input: crate::types::FieldSortOptions) -> Self {
        let mut v = self.category_sort.unwrap_or_default();
        v.push(input);
        self.category_sort = ::std::option::Option::Some(v);
        self
    }
    /// <p>The sort configuration of the category fields.</p>
    pub fn set_category_sort(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FieldSortOptions>>) -> Self {
        self.category_sort = input;
        self
    }
    /// <p>The sort configuration of the category fields.</p>
    pub fn get_category_sort(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FieldSortOptions>> {
        &self.category_sort
    }
    /// <p>The limit on the number of categories that are displayed in a pie chart.</p>
    pub fn category_items_limit(mut self, input: crate::types::ItemsLimitConfiguration) -> Self {
        self.category_items_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The limit on the number of categories that are displayed in a pie chart.</p>
    pub fn set_category_items_limit(mut self, input: ::std::option::Option<crate::types::ItemsLimitConfiguration>) -> Self {
        self.category_items_limit = input;
        self
    }
    /// <p>The limit on the number of categories that are displayed in a pie chart.</p>
    pub fn get_category_items_limit(&self) -> &::std::option::Option<crate::types::ItemsLimitConfiguration> {
        &self.category_items_limit
    }
    /// Appends an item to `small_multiples_sort`.
    ///
    /// To override the contents of this collection use [`set_small_multiples_sort`](Self::set_small_multiples_sort).
    ///
    /// <p>The sort configuration of the small multiples field.</p>
    pub fn small_multiples_sort(mut self, input: crate::types::FieldSortOptions) -> Self {
        let mut v = self.small_multiples_sort.unwrap_or_default();
        v.push(input);
        self.small_multiples_sort = ::std::option::Option::Some(v);
        self
    }
    /// <p>The sort configuration of the small multiples field.</p>
    pub fn set_small_multiples_sort(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FieldSortOptions>>) -> Self {
        self.small_multiples_sort = input;
        self
    }
    /// <p>The sort configuration of the small multiples field.</p>
    pub fn get_small_multiples_sort(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FieldSortOptions>> {
        &self.small_multiples_sort
    }
    /// <p>The limit on the number of small multiples panels that are displayed.</p>
    pub fn small_multiples_limit_configuration(mut self, input: crate::types::ItemsLimitConfiguration) -> Self {
        self.small_multiples_limit_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The limit on the number of small multiples panels that are displayed.</p>
    pub fn set_small_multiples_limit_configuration(mut self, input: ::std::option::Option<crate::types::ItemsLimitConfiguration>) -> Self {
        self.small_multiples_limit_configuration = input;
        self
    }
    /// <p>The limit on the number of small multiples panels that are displayed.</p>
    pub fn get_small_multiples_limit_configuration(&self) -> &::std::option::Option<crate::types::ItemsLimitConfiguration> {
        &self.small_multiples_limit_configuration
    }
    /// Consumes the builder and constructs a [`PieChartSortConfiguration`](crate::types::PieChartSortConfiguration).
    pub fn build(self) -> crate::types::PieChartSortConfiguration {
        crate::types::PieChartSortConfiguration {
            category_sort: self.category_sort,
            category_items_limit: self.category_items_limit,
            small_multiples_sort: self.small_multiples_sort,
            small_multiples_limit_configuration: self.small_multiples_limit_configuration,
        }
    }
}
