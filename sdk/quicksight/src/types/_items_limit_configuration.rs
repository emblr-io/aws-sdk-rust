// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The limit configuration of the visual display for an axis.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ItemsLimitConfiguration {
    /// <p>The limit on how many items of a field are showed in the chart. For example, the number of slices that are displayed in a pie chart.</p>
    pub items_limit: ::std::option::Option<i64>,
    /// <p>The <code>Show other</code> of an axis in the chart. Choose one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>INCLUDE</code></p></li>
    /// <li>
    /// <p><code>EXCLUDE</code></p></li>
    /// </ul>
    pub other_categories: ::std::option::Option<crate::types::OtherCategories>,
}
impl ItemsLimitConfiguration {
    /// <p>The limit on how many items of a field are showed in the chart. For example, the number of slices that are displayed in a pie chart.</p>
    pub fn items_limit(&self) -> ::std::option::Option<i64> {
        self.items_limit
    }
    /// <p>The <code>Show other</code> of an axis in the chart. Choose one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>INCLUDE</code></p></li>
    /// <li>
    /// <p><code>EXCLUDE</code></p></li>
    /// </ul>
    pub fn other_categories(&self) -> ::std::option::Option<&crate::types::OtherCategories> {
        self.other_categories.as_ref()
    }
}
impl ItemsLimitConfiguration {
    /// Creates a new builder-style object to manufacture [`ItemsLimitConfiguration`](crate::types::ItemsLimitConfiguration).
    pub fn builder() -> crate::types::builders::ItemsLimitConfigurationBuilder {
        crate::types::builders::ItemsLimitConfigurationBuilder::default()
    }
}

/// A builder for [`ItemsLimitConfiguration`](crate::types::ItemsLimitConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ItemsLimitConfigurationBuilder {
    pub(crate) items_limit: ::std::option::Option<i64>,
    pub(crate) other_categories: ::std::option::Option<crate::types::OtherCategories>,
}
impl ItemsLimitConfigurationBuilder {
    /// <p>The limit on how many items of a field are showed in the chart. For example, the number of slices that are displayed in a pie chart.</p>
    pub fn items_limit(mut self, input: i64) -> Self {
        self.items_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The limit on how many items of a field are showed in the chart. For example, the number of slices that are displayed in a pie chart.</p>
    pub fn set_items_limit(mut self, input: ::std::option::Option<i64>) -> Self {
        self.items_limit = input;
        self
    }
    /// <p>The limit on how many items of a field are showed in the chart. For example, the number of slices that are displayed in a pie chart.</p>
    pub fn get_items_limit(&self) -> &::std::option::Option<i64> {
        &self.items_limit
    }
    /// <p>The <code>Show other</code> of an axis in the chart. Choose one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>INCLUDE</code></p></li>
    /// <li>
    /// <p><code>EXCLUDE</code></p></li>
    /// </ul>
    pub fn other_categories(mut self, input: crate::types::OtherCategories) -> Self {
        self.other_categories = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>Show other</code> of an axis in the chart. Choose one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>INCLUDE</code></p></li>
    /// <li>
    /// <p><code>EXCLUDE</code></p></li>
    /// </ul>
    pub fn set_other_categories(mut self, input: ::std::option::Option<crate::types::OtherCategories>) -> Self {
        self.other_categories = input;
        self
    }
    /// <p>The <code>Show other</code> of an axis in the chart. Choose one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>INCLUDE</code></p></li>
    /// <li>
    /// <p><code>EXCLUDE</code></p></li>
    /// </ul>
    pub fn get_other_categories(&self) -> &::std::option::Option<crate::types::OtherCategories> {
        &self.other_categories
    }
    /// Consumes the builder and constructs a [`ItemsLimitConfiguration`](crate::types::ItemsLimitConfiguration).
    pub fn build(self) -> crate::types::ItemsLimitConfiguration {
        crate::types::ItemsLimitConfiguration {
            items_limit: self.items_limit,
            other_categories: self.other_categories,
        }
    }
}
