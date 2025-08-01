// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Account Takeover Insights (ATI) model training metric details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AtiTrainingMetricsValue {
    /// <p>The model's performance metrics data points.</p>
    pub metric_data_points: ::std::option::Option<::std::vec::Vec<crate::types::AtiMetricDataPoint>>,
    /// <p>The model's overall performance scores.</p>
    pub model_performance: ::std::option::Option<crate::types::AtiModelPerformance>,
}
impl AtiTrainingMetricsValue {
    /// <p>The model's performance metrics data points.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.metric_data_points.is_none()`.
    pub fn metric_data_points(&self) -> &[crate::types::AtiMetricDataPoint] {
        self.metric_data_points.as_deref().unwrap_or_default()
    }
    /// <p>The model's overall performance scores.</p>
    pub fn model_performance(&self) -> ::std::option::Option<&crate::types::AtiModelPerformance> {
        self.model_performance.as_ref()
    }
}
impl AtiTrainingMetricsValue {
    /// Creates a new builder-style object to manufacture [`AtiTrainingMetricsValue`](crate::types::AtiTrainingMetricsValue).
    pub fn builder() -> crate::types::builders::AtiTrainingMetricsValueBuilder {
        crate::types::builders::AtiTrainingMetricsValueBuilder::default()
    }
}

/// A builder for [`AtiTrainingMetricsValue`](crate::types::AtiTrainingMetricsValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AtiTrainingMetricsValueBuilder {
    pub(crate) metric_data_points: ::std::option::Option<::std::vec::Vec<crate::types::AtiMetricDataPoint>>,
    pub(crate) model_performance: ::std::option::Option<crate::types::AtiModelPerformance>,
}
impl AtiTrainingMetricsValueBuilder {
    /// Appends an item to `metric_data_points`.
    ///
    /// To override the contents of this collection use [`set_metric_data_points`](Self::set_metric_data_points).
    ///
    /// <p>The model's performance metrics data points.</p>
    pub fn metric_data_points(mut self, input: crate::types::AtiMetricDataPoint) -> Self {
        let mut v = self.metric_data_points.unwrap_or_default();
        v.push(input);
        self.metric_data_points = ::std::option::Option::Some(v);
        self
    }
    /// <p>The model's performance metrics data points.</p>
    pub fn set_metric_data_points(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AtiMetricDataPoint>>) -> Self {
        self.metric_data_points = input;
        self
    }
    /// <p>The model's performance metrics data points.</p>
    pub fn get_metric_data_points(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AtiMetricDataPoint>> {
        &self.metric_data_points
    }
    /// <p>The model's overall performance scores.</p>
    pub fn model_performance(mut self, input: crate::types::AtiModelPerformance) -> Self {
        self.model_performance = ::std::option::Option::Some(input);
        self
    }
    /// <p>The model's overall performance scores.</p>
    pub fn set_model_performance(mut self, input: ::std::option::Option<crate::types::AtiModelPerformance>) -> Self {
        self.model_performance = input;
        self
    }
    /// <p>The model's overall performance scores.</p>
    pub fn get_model_performance(&self) -> &::std::option::Option<crate::types::AtiModelPerformance> {
        &self.model_performance
    }
    /// Consumes the builder and constructs a [`AtiTrainingMetricsValue`](crate::types::AtiTrainingMetricsValue).
    pub fn build(self) -> crate::types::AtiTrainingMetricsValue {
        crate::types::AtiTrainingMetricsValue {
            metric_data_points: self.metric_data_points,
            model_performance: self.model_performance,
        }
    }
}
