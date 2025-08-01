// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the analyzed metrics that displayed anomalous behavior.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudWatchMetricsDataSummary {
    /// <p>This is a list of Amazon CloudWatch metric values at given timestamp.</p>
    pub timestamp_metric_value_pair_list: ::std::option::Option<::std::vec::Vec<crate::types::TimestampMetricValuePair>>,
    /// <p>This is an enum of the status showing whether the metric value pair list has partial or complete data, or if there was an error.</p>
    pub status_code: ::std::option::Option<crate::types::CloudWatchMetricDataStatusCode>,
}
impl CloudWatchMetricsDataSummary {
    /// <p>This is a list of Amazon CloudWatch metric values at given timestamp.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.timestamp_metric_value_pair_list.is_none()`.
    pub fn timestamp_metric_value_pair_list(&self) -> &[crate::types::TimestampMetricValuePair] {
        self.timestamp_metric_value_pair_list.as_deref().unwrap_or_default()
    }
    /// <p>This is an enum of the status showing whether the metric value pair list has partial or complete data, or if there was an error.</p>
    pub fn status_code(&self) -> ::std::option::Option<&crate::types::CloudWatchMetricDataStatusCode> {
        self.status_code.as_ref()
    }
}
impl CloudWatchMetricsDataSummary {
    /// Creates a new builder-style object to manufacture [`CloudWatchMetricsDataSummary`](crate::types::CloudWatchMetricsDataSummary).
    pub fn builder() -> crate::types::builders::CloudWatchMetricsDataSummaryBuilder {
        crate::types::builders::CloudWatchMetricsDataSummaryBuilder::default()
    }
}

/// A builder for [`CloudWatchMetricsDataSummary`](crate::types::CloudWatchMetricsDataSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudWatchMetricsDataSummaryBuilder {
    pub(crate) timestamp_metric_value_pair_list: ::std::option::Option<::std::vec::Vec<crate::types::TimestampMetricValuePair>>,
    pub(crate) status_code: ::std::option::Option<crate::types::CloudWatchMetricDataStatusCode>,
}
impl CloudWatchMetricsDataSummaryBuilder {
    /// Appends an item to `timestamp_metric_value_pair_list`.
    ///
    /// To override the contents of this collection use [`set_timestamp_metric_value_pair_list`](Self::set_timestamp_metric_value_pair_list).
    ///
    /// <p>This is a list of Amazon CloudWatch metric values at given timestamp.</p>
    pub fn timestamp_metric_value_pair_list(mut self, input: crate::types::TimestampMetricValuePair) -> Self {
        let mut v = self.timestamp_metric_value_pair_list.unwrap_or_default();
        v.push(input);
        self.timestamp_metric_value_pair_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>This is a list of Amazon CloudWatch metric values at given timestamp.</p>
    pub fn set_timestamp_metric_value_pair_list(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::TimestampMetricValuePair>>,
    ) -> Self {
        self.timestamp_metric_value_pair_list = input;
        self
    }
    /// <p>This is a list of Amazon CloudWatch metric values at given timestamp.</p>
    pub fn get_timestamp_metric_value_pair_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TimestampMetricValuePair>> {
        &self.timestamp_metric_value_pair_list
    }
    /// <p>This is an enum of the status showing whether the metric value pair list has partial or complete data, or if there was an error.</p>
    pub fn status_code(mut self, input: crate::types::CloudWatchMetricDataStatusCode) -> Self {
        self.status_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is an enum of the status showing whether the metric value pair list has partial or complete data, or if there was an error.</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<crate::types::CloudWatchMetricDataStatusCode>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>This is an enum of the status showing whether the metric value pair list has partial or complete data, or if there was an error.</p>
    pub fn get_status_code(&self) -> &::std::option::Option<crate::types::CloudWatchMetricDataStatusCode> {
        &self.status_code
    }
    /// Consumes the builder and constructs a [`CloudWatchMetricsDataSummary`](crate::types::CloudWatchMetricsDataSummary).
    pub fn build(self) -> crate::types::CloudWatchMetricsDataSummary {
        crate::types::CloudWatchMetricsDataSummary {
            timestamp_metric_value_pair_list: self.timestamp_metric_value_pair_list,
            status_code: self.status_code,
        }
    }
}
