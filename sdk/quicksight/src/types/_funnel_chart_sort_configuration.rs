// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The sort configuration of a <code>FunnelChartVisual</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FunnelChartSortConfiguration {
    /// <p>The sort configuration of the category fields.</p>
    pub category_sort: ::std::option::Option<::std::vec::Vec<crate::types::FieldSortOptions>>,
    /// <p>The limit on the number of categories displayed.</p>
    pub category_items_limit: ::std::option::Option<crate::types::ItemsLimitConfiguration>,
}
impl FunnelChartSortConfiguration {
    /// <p>The sort configuration of the category fields.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.category_sort.is_none()`.
    pub fn category_sort(&self) -> &[crate::types::FieldSortOptions] {
        self.category_sort.as_deref().unwrap_or_default()
    }
    /// <p>The limit on the number of categories displayed.</p>
    pub fn category_items_limit(&self) -> ::std::option::Option<&crate::types::ItemsLimitConfiguration> {
        self.category_items_limit.as_ref()
    }
}
impl FunnelChartSortConfiguration {
    /// Creates a new builder-style object to manufacture [`FunnelChartSortConfiguration`](crate::types::FunnelChartSortConfiguration).
    pub fn builder() -> crate::types::builders::FunnelChartSortConfigurationBuilder {
        crate::types::builders::FunnelChartSortConfigurationBuilder::default()
    }
}

/// A builder for [`FunnelChartSortConfiguration`](crate::types::FunnelChartSortConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FunnelChartSortConfigurationBuilder {
    pub(crate) category_sort: ::std::option::Option<::std::vec::Vec<crate::types::FieldSortOptions>>,
    pub(crate) category_items_limit: ::std::option::Option<crate::types::ItemsLimitConfiguration>,
}
impl FunnelChartSortConfigurationBuilder {
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
    /// <p>The limit on the number of categories displayed.</p>
    pub fn category_items_limit(mut self, input: crate::types::ItemsLimitConfiguration) -> Self {
        self.category_items_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The limit on the number of categories displayed.</p>
    pub fn set_category_items_limit(mut self, input: ::std::option::Option<crate::types::ItemsLimitConfiguration>) -> Self {
        self.category_items_limit = input;
        self
    }
    /// <p>The limit on the number of categories displayed.</p>
    pub fn get_category_items_limit(&self) -> &::std::option::Option<crate::types::ItemsLimitConfiguration> {
        &self.category_items_limit
    }
    /// Consumes the builder and constructs a [`FunnelChartSortConfiguration`](crate::types::FunnelChartSortConfiguration).
    pub fn build(self) -> crate::types::FunnelChartSortConfiguration {
        crate::types::FunnelChartSortConfiguration {
            category_sort: self.category_sort,
            category_items_limit: self.category_items_limit,
        }
    }
}
