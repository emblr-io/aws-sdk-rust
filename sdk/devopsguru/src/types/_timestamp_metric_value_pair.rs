// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A pair that contains metric values at the respective timestamp.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimestampMetricValuePair {
    /// <p>A <code>Timestamp</code> that specifies the time the event occurred.</p>
    pub timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Value of the anomalous metric data point at respective Timestamp.</p>
    pub metric_value: ::std::option::Option<f64>,
}
impl TimestampMetricValuePair {
    /// <p>A <code>Timestamp</code> that specifies the time the event occurred.</p>
    pub fn timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.timestamp.as_ref()
    }
    /// <p>Value of the anomalous metric data point at respective Timestamp.</p>
    pub fn metric_value(&self) -> ::std::option::Option<f64> {
        self.metric_value
    }
}
impl TimestampMetricValuePair {
    /// Creates a new builder-style object to manufacture [`TimestampMetricValuePair`](crate::types::TimestampMetricValuePair).
    pub fn builder() -> crate::types::builders::TimestampMetricValuePairBuilder {
        crate::types::builders::TimestampMetricValuePairBuilder::default()
    }
}

/// A builder for [`TimestampMetricValuePair`](crate::types::TimestampMetricValuePair).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimestampMetricValuePairBuilder {
    pub(crate) timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) metric_value: ::std::option::Option<f64>,
}
impl TimestampMetricValuePairBuilder {
    /// <p>A <code>Timestamp</code> that specifies the time the event occurred.</p>
    pub fn timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>Timestamp</code> that specifies the time the event occurred.</p>
    pub fn set_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.timestamp = input;
        self
    }
    /// <p>A <code>Timestamp</code> that specifies the time the event occurred.</p>
    pub fn get_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.timestamp
    }
    /// <p>Value of the anomalous metric data point at respective Timestamp.</p>
    pub fn metric_value(mut self, input: f64) -> Self {
        self.metric_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>Value of the anomalous metric data point at respective Timestamp.</p>
    pub fn set_metric_value(mut self, input: ::std::option::Option<f64>) -> Self {
        self.metric_value = input;
        self
    }
    /// <p>Value of the anomalous metric data point at respective Timestamp.</p>
    pub fn get_metric_value(&self) -> &::std::option::Option<f64> {
        &self.metric_value
    }
    /// Consumes the builder and constructs a [`TimestampMetricValuePair`](crate::types::TimestampMetricValuePair).
    pub fn build(self) -> crate::types::TimestampMetricValuePair {
        crate::types::TimestampMetricValuePair {
            timestamp: self.timestamp,
            metric_value: self.metric_value,
        }
    }
}
