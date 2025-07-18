// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This object contains the information for one metric that is to be streamed with additional statistics.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MetricStreamStatisticsMetric {
    /// <p>The namespace of the metric.</p>
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>The name of the metric.</p>
    pub metric_name: ::std::option::Option<::std::string::String>,
}
impl MetricStreamStatisticsMetric {
    /// <p>The namespace of the metric.</p>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>The name of the metric.</p>
    pub fn metric_name(&self) -> ::std::option::Option<&str> {
        self.metric_name.as_deref()
    }
}
impl MetricStreamStatisticsMetric {
    /// Creates a new builder-style object to manufacture [`MetricStreamStatisticsMetric`](crate::types::MetricStreamStatisticsMetric).
    pub fn builder() -> crate::types::builders::MetricStreamStatisticsMetricBuilder {
        crate::types::builders::MetricStreamStatisticsMetricBuilder::default()
    }
}

/// A builder for [`MetricStreamStatisticsMetric`](crate::types::MetricStreamStatisticsMetric).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MetricStreamStatisticsMetricBuilder {
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) metric_name: ::std::option::Option<::std::string::String>,
}
impl MetricStreamStatisticsMetricBuilder {
    /// <p>The namespace of the metric.</p>
    /// This field is required.
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
    /// <p>The name of the metric.</p>
    /// This field is required.
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
    /// Consumes the builder and constructs a [`MetricStreamStatisticsMetric`](crate::types::MetricStreamStatisticsMetric).
    pub fn build(self) -> crate::types::MetricStreamStatisticsMetric {
        crate::types::MetricStreamStatisticsMetric {
            namespace: self.namespace,
            metric_name: self.metric_name,
        }
    }
}
