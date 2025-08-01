// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a set of real-time metrics.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CurrentMetricResult {
    /// <p>The dimensions for the metrics.</p>
    pub dimensions: ::std::option::Option<crate::types::Dimensions>,
    /// <p>The set of metrics.</p>
    pub collections: ::std::option::Option<::std::vec::Vec<crate::types::CurrentMetricData>>,
}
impl CurrentMetricResult {
    /// <p>The dimensions for the metrics.</p>
    pub fn dimensions(&self) -> ::std::option::Option<&crate::types::Dimensions> {
        self.dimensions.as_ref()
    }
    /// <p>The set of metrics.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.collections.is_none()`.
    pub fn collections(&self) -> &[crate::types::CurrentMetricData] {
        self.collections.as_deref().unwrap_or_default()
    }
}
impl CurrentMetricResult {
    /// Creates a new builder-style object to manufacture [`CurrentMetricResult`](crate::types::CurrentMetricResult).
    pub fn builder() -> crate::types::builders::CurrentMetricResultBuilder {
        crate::types::builders::CurrentMetricResultBuilder::default()
    }
}

/// A builder for [`CurrentMetricResult`](crate::types::CurrentMetricResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CurrentMetricResultBuilder {
    pub(crate) dimensions: ::std::option::Option<crate::types::Dimensions>,
    pub(crate) collections: ::std::option::Option<::std::vec::Vec<crate::types::CurrentMetricData>>,
}
impl CurrentMetricResultBuilder {
    /// <p>The dimensions for the metrics.</p>
    pub fn dimensions(mut self, input: crate::types::Dimensions) -> Self {
        self.dimensions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The dimensions for the metrics.</p>
    pub fn set_dimensions(mut self, input: ::std::option::Option<crate::types::Dimensions>) -> Self {
        self.dimensions = input;
        self
    }
    /// <p>The dimensions for the metrics.</p>
    pub fn get_dimensions(&self) -> &::std::option::Option<crate::types::Dimensions> {
        &self.dimensions
    }
    /// Appends an item to `collections`.
    ///
    /// To override the contents of this collection use [`set_collections`](Self::set_collections).
    ///
    /// <p>The set of metrics.</p>
    pub fn collections(mut self, input: crate::types::CurrentMetricData) -> Self {
        let mut v = self.collections.unwrap_or_default();
        v.push(input);
        self.collections = ::std::option::Option::Some(v);
        self
    }
    /// <p>The set of metrics.</p>
    pub fn set_collections(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CurrentMetricData>>) -> Self {
        self.collections = input;
        self
    }
    /// <p>The set of metrics.</p>
    pub fn get_collections(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CurrentMetricData>> {
        &self.collections
    }
    /// Consumes the builder and constructs a [`CurrentMetricResult`](crate::types::CurrentMetricResult).
    pub fn build(self) -> crate::types::CurrentMetricResult {
        crate::types::CurrentMetricResult {
            dimensions: self.dimensions,
            collections: self.collections,
        }
    }
}
