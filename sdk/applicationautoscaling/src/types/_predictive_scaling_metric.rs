// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the scaling metric.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PredictiveScalingMetric {
    /// <p>Describes the dimensions of the metric.</p>
    pub dimensions: ::std::option::Option<::std::vec::Vec<crate::types::PredictiveScalingMetricDimension>>,
    /// <p>The name of the metric.</p>
    pub metric_name: ::std::option::Option<::std::string::String>,
    /// <p>The namespace of the metric.</p>
    pub namespace: ::std::option::Option<::std::string::String>,
}
impl PredictiveScalingMetric {
    /// <p>Describes the dimensions of the metric.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dimensions.is_none()`.
    pub fn dimensions(&self) -> &[crate::types::PredictiveScalingMetricDimension] {
        self.dimensions.as_deref().unwrap_or_default()
    }
    /// <p>The name of the metric.</p>
    pub fn metric_name(&self) -> ::std::option::Option<&str> {
        self.metric_name.as_deref()
    }
    /// <p>The namespace of the metric.</p>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
}
impl PredictiveScalingMetric {
    /// Creates a new builder-style object to manufacture [`PredictiveScalingMetric`](crate::types::PredictiveScalingMetric).
    pub fn builder() -> crate::types::builders::PredictiveScalingMetricBuilder {
        crate::types::builders::PredictiveScalingMetricBuilder::default()
    }
}

/// A builder for [`PredictiveScalingMetric`](crate::types::PredictiveScalingMetric).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PredictiveScalingMetricBuilder {
    pub(crate) dimensions: ::std::option::Option<::std::vec::Vec<crate::types::PredictiveScalingMetricDimension>>,
    pub(crate) metric_name: ::std::option::Option<::std::string::String>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
}
impl PredictiveScalingMetricBuilder {
    /// Appends an item to `dimensions`.
    ///
    /// To override the contents of this collection use [`set_dimensions`](Self::set_dimensions).
    ///
    /// <p>Describes the dimensions of the metric.</p>
    pub fn dimensions(mut self, input: crate::types::PredictiveScalingMetricDimension) -> Self {
        let mut v = self.dimensions.unwrap_or_default();
        v.push(input);
        self.dimensions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the dimensions of the metric.</p>
    pub fn set_dimensions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PredictiveScalingMetricDimension>>) -> Self {
        self.dimensions = input;
        self
    }
    /// <p>Describes the dimensions of the metric.</p>
    pub fn get_dimensions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PredictiveScalingMetricDimension>> {
        &self.dimensions
    }
    /// <p>The name of the metric.</p>
    pub fn metric_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the metric.</p>
    pub fn set_metric_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_name = input;
        self
    }
    /// <p>The name of the metric.</p>
    pub fn get_metric_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_name
    }
    /// <p>The namespace of the metric.</p>
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace of the metric.</p>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The namespace of the metric.</p>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// Consumes the builder and constructs a [`PredictiveScalingMetric`](crate::types::PredictiveScalingMetric).
    pub fn build(self) -> crate::types::PredictiveScalingMetric {
        crate::types::PredictiveScalingMetric {
            dimensions: self.dimensions,
            metric_name: self.metric_name,
            namespace: self.namespace,
        }
    }
}
