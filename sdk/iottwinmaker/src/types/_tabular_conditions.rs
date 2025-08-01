// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The tabular conditions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TabularConditions {
    /// <p>Filter criteria that orders the output. It can be sorted in ascending or descending order.</p>
    pub order_by: ::std::option::Option<::std::vec::Vec<crate::types::OrderBy>>,
    /// <p>You can filter the request using various logical operators and a key-value format. For example:</p>
    /// <p><code>{"key": "serverType", "value": "webServer"}</code></p>
    pub property_filters: ::std::option::Option<::std::vec::Vec<crate::types::PropertyFilter>>,
}
impl TabularConditions {
    /// <p>Filter criteria that orders the output. It can be sorted in ascending or descending order.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.order_by.is_none()`.
    pub fn order_by(&self) -> &[crate::types::OrderBy] {
        self.order_by.as_deref().unwrap_or_default()
    }
    /// <p>You can filter the request using various logical operators and a key-value format. For example:</p>
    /// <p><code>{"key": "serverType", "value": "webServer"}</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.property_filters.is_none()`.
    pub fn property_filters(&self) -> &[crate::types::PropertyFilter] {
        self.property_filters.as_deref().unwrap_or_default()
    }
}
impl TabularConditions {
    /// Creates a new builder-style object to manufacture [`TabularConditions`](crate::types::TabularConditions).
    pub fn builder() -> crate::types::builders::TabularConditionsBuilder {
        crate::types::builders::TabularConditionsBuilder::default()
    }
}

/// A builder for [`TabularConditions`](crate::types::TabularConditions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TabularConditionsBuilder {
    pub(crate) order_by: ::std::option::Option<::std::vec::Vec<crate::types::OrderBy>>,
    pub(crate) property_filters: ::std::option::Option<::std::vec::Vec<crate::types::PropertyFilter>>,
}
impl TabularConditionsBuilder {
    /// Appends an item to `order_by`.
    ///
    /// To override the contents of this collection use [`set_order_by`](Self::set_order_by).
    ///
    /// <p>Filter criteria that orders the output. It can be sorted in ascending or descending order.</p>
    pub fn order_by(mut self, input: crate::types::OrderBy) -> Self {
        let mut v = self.order_by.unwrap_or_default();
        v.push(input);
        self.order_by = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filter criteria that orders the output. It can be sorted in ascending or descending order.</p>
    pub fn set_order_by(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OrderBy>>) -> Self {
        self.order_by = input;
        self
    }
    /// <p>Filter criteria that orders the output. It can be sorted in ascending or descending order.</p>
    pub fn get_order_by(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OrderBy>> {
        &self.order_by
    }
    /// Appends an item to `property_filters`.
    ///
    /// To override the contents of this collection use [`set_property_filters`](Self::set_property_filters).
    ///
    /// <p>You can filter the request using various logical operators and a key-value format. For example:</p>
    /// <p><code>{"key": "serverType", "value": "webServer"}</code></p>
    pub fn property_filters(mut self, input: crate::types::PropertyFilter) -> Self {
        let mut v = self.property_filters.unwrap_or_default();
        v.push(input);
        self.property_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can filter the request using various logical operators and a key-value format. For example:</p>
    /// <p><code>{"key": "serverType", "value": "webServer"}</code></p>
    pub fn set_property_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PropertyFilter>>) -> Self {
        self.property_filters = input;
        self
    }
    /// <p>You can filter the request using various logical operators and a key-value format. For example:</p>
    /// <p><code>{"key": "serverType", "value": "webServer"}</code></p>
    pub fn get_property_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PropertyFilter>> {
        &self.property_filters
    }
    /// Consumes the builder and constructs a [`TabularConditions`](crate::types::TabularConditions).
    pub fn build(self) -> crate::types::TabularConditions {
        crate::types::TabularConditions {
            order_by: self.order_by,
            property_filters: self.property_filters,
        }
    }
}
