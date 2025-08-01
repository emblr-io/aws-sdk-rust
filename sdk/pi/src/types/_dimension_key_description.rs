// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that includes the requested dimension key values and aggregated metric values within a dimension group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DimensionKeyDescription {
    /// <p>A map of name-value pairs for the dimensions in the group.</p>
    pub dimensions: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The aggregated metric value for the dimensions, over the requested time range.</p>
    pub total: ::std::option::Option<f64>,
    /// <p>A map that contains the value for each additional metric.</p>
    pub additional_metrics: ::std::option::Option<::std::collections::HashMap<::std::string::String, f64>>,
    /// <p>If <code>PartitionBy</code> was specified, <code>PartitionKeys</code> contains the dimensions that were.</p>
    pub partitions: ::std::option::Option<::std::vec::Vec<f64>>,
}
impl DimensionKeyDescription {
    /// <p>A map of name-value pairs for the dimensions in the group.</p>
    pub fn dimensions(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.dimensions.as_ref()
    }
    /// <p>The aggregated metric value for the dimensions, over the requested time range.</p>
    pub fn total(&self) -> ::std::option::Option<f64> {
        self.total
    }
    /// <p>A map that contains the value for each additional metric.</p>
    pub fn additional_metrics(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, f64>> {
        self.additional_metrics.as_ref()
    }
    /// <p>If <code>PartitionBy</code> was specified, <code>PartitionKeys</code> contains the dimensions that were.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.partitions.is_none()`.
    pub fn partitions(&self) -> &[f64] {
        self.partitions.as_deref().unwrap_or_default()
    }
}
impl DimensionKeyDescription {
    /// Creates a new builder-style object to manufacture [`DimensionKeyDescription`](crate::types::DimensionKeyDescription).
    pub fn builder() -> crate::types::builders::DimensionKeyDescriptionBuilder {
        crate::types::builders::DimensionKeyDescriptionBuilder::default()
    }
}

/// A builder for [`DimensionKeyDescription`](crate::types::DimensionKeyDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DimensionKeyDescriptionBuilder {
    pub(crate) dimensions: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) total: ::std::option::Option<f64>,
    pub(crate) additional_metrics: ::std::option::Option<::std::collections::HashMap<::std::string::String, f64>>,
    pub(crate) partitions: ::std::option::Option<::std::vec::Vec<f64>>,
}
impl DimensionKeyDescriptionBuilder {
    /// Adds a key-value pair to `dimensions`.
    ///
    /// To override the contents of this collection use [`set_dimensions`](Self::set_dimensions).
    ///
    /// <p>A map of name-value pairs for the dimensions in the group.</p>
    pub fn dimensions(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.dimensions.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.dimensions = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of name-value pairs for the dimensions in the group.</p>
    pub fn set_dimensions(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.dimensions = input;
        self
    }
    /// <p>A map of name-value pairs for the dimensions in the group.</p>
    pub fn get_dimensions(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.dimensions
    }
    /// <p>The aggregated metric value for the dimensions, over the requested time range.</p>
    pub fn total(mut self, input: f64) -> Self {
        self.total = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregated metric value for the dimensions, over the requested time range.</p>
    pub fn set_total(mut self, input: ::std::option::Option<f64>) -> Self {
        self.total = input;
        self
    }
    /// <p>The aggregated metric value for the dimensions, over the requested time range.</p>
    pub fn get_total(&self) -> &::std::option::Option<f64> {
        &self.total
    }
    /// Adds a key-value pair to `additional_metrics`.
    ///
    /// To override the contents of this collection use [`set_additional_metrics`](Self::set_additional_metrics).
    ///
    /// <p>A map that contains the value for each additional metric.</p>
    pub fn additional_metrics(mut self, k: impl ::std::convert::Into<::std::string::String>, v: f64) -> Self {
        let mut hash_map = self.additional_metrics.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.additional_metrics = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map that contains the value for each additional metric.</p>
    pub fn set_additional_metrics(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, f64>>) -> Self {
        self.additional_metrics = input;
        self
    }
    /// <p>A map that contains the value for each additional metric.</p>
    pub fn get_additional_metrics(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, f64>> {
        &self.additional_metrics
    }
    /// Appends an item to `partitions`.
    ///
    /// To override the contents of this collection use [`set_partitions`](Self::set_partitions).
    ///
    /// <p>If <code>PartitionBy</code> was specified, <code>PartitionKeys</code> contains the dimensions that were.</p>
    pub fn partitions(mut self, input: f64) -> Self {
        let mut v = self.partitions.unwrap_or_default();
        v.push(input);
        self.partitions = ::std::option::Option::Some(v);
        self
    }
    /// <p>If <code>PartitionBy</code> was specified, <code>PartitionKeys</code> contains the dimensions that were.</p>
    pub fn set_partitions(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.partitions = input;
        self
    }
    /// <p>If <code>PartitionBy</code> was specified, <code>PartitionKeys</code> contains the dimensions that were.</p>
    pub fn get_partitions(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.partitions
    }
    /// Consumes the builder and constructs a [`DimensionKeyDescription`](crate::types::DimensionKeyDescription).
    pub fn build(self) -> crate::types::DimensionKeyDescription {
        crate::types::DimensionKeyDescription {
            dimensions: self.dimensions,
            total: self.total,
            additional_metrics: self.additional_metrics,
            partitions: self.partitions,
        }
    }
}
