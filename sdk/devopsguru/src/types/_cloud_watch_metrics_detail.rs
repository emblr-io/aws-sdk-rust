// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about an Amazon CloudWatch metric.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudWatchMetricsDetail {
    /// <p>The name of the CloudWatch metric.</p>
    pub metric_name: ::std::option::Option<::std::string::String>,
    /// <p>The namespace of the CloudWatch metric. A namespace is a container for CloudWatch metrics.</p>
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>An array of CloudWatch dimensions associated with</p>
    pub dimensions: ::std::option::Option<::std::vec::Vec<crate::types::CloudWatchMetricsDimension>>,
    /// <p>The type of statistic associated with the CloudWatch metric. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Statistic">Statistics</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
    pub stat: ::std::option::Option<crate::types::CloudWatchMetricsStat>,
    /// <p>The unit of measure used for the CloudWatch metric. For example, <code>Bytes</code>, <code>Seconds</code>, <code>Count</code>, and <code>Percent</code>.</p>
    pub unit: ::std::option::Option<::std::string::String>,
    /// <p>The length of time associated with the CloudWatch metric in number of seconds.</p>
    pub period: i32,
    /// <p>This object returns anomaly metric data.</p>
    pub metric_data_summary: ::std::option::Option<crate::types::CloudWatchMetricsDataSummary>,
}
impl CloudWatchMetricsDetail {
    /// <p>The name of the CloudWatch metric.</p>
    pub fn metric_name(&self) -> ::std::option::Option<&str> {
        self.metric_name.as_deref()
    }
    /// <p>The namespace of the CloudWatch metric. A namespace is a container for CloudWatch metrics.</p>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>An array of CloudWatch dimensions associated with</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dimensions.is_none()`.
    pub fn dimensions(&self) -> &[crate::types::CloudWatchMetricsDimension] {
        self.dimensions.as_deref().unwrap_or_default()
    }
    /// <p>The type of statistic associated with the CloudWatch metric. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Statistic">Statistics</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
    pub fn stat(&self) -> ::std::option::Option<&crate::types::CloudWatchMetricsStat> {
        self.stat.as_ref()
    }
    /// <p>The unit of measure used for the CloudWatch metric. For example, <code>Bytes</code>, <code>Seconds</code>, <code>Count</code>, and <code>Percent</code>.</p>
    pub fn unit(&self) -> ::std::option::Option<&str> {
        self.unit.as_deref()
    }
    /// <p>The length of time associated with the CloudWatch metric in number of seconds.</p>
    pub fn period(&self) -> i32 {
        self.period
    }
    /// <p>This object returns anomaly metric data.</p>
    pub fn metric_data_summary(&self) -> ::std::option::Option<&crate::types::CloudWatchMetricsDataSummary> {
        self.metric_data_summary.as_ref()
    }
}
impl CloudWatchMetricsDetail {
    /// Creates a new builder-style object to manufacture [`CloudWatchMetricsDetail`](crate::types::CloudWatchMetricsDetail).
    pub fn builder() -> crate::types::builders::CloudWatchMetricsDetailBuilder {
        crate::types::builders::CloudWatchMetricsDetailBuilder::default()
    }
}

/// A builder for [`CloudWatchMetricsDetail`](crate::types::CloudWatchMetricsDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudWatchMetricsDetailBuilder {
    pub(crate) metric_name: ::std::option::Option<::std::string::String>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) dimensions: ::std::option::Option<::std::vec::Vec<crate::types::CloudWatchMetricsDimension>>,
    pub(crate) stat: ::std::option::Option<crate::types::CloudWatchMetricsStat>,
    pub(crate) unit: ::std::option::Option<::std::string::String>,
    pub(crate) period: ::std::option::Option<i32>,
    pub(crate) metric_data_summary: ::std::option::Option<crate::types::CloudWatchMetricsDataSummary>,
}
impl CloudWatchMetricsDetailBuilder {
    /// <p>The name of the CloudWatch metric.</p>
    pub fn metric_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the CloudWatch metric.</p>
    pub fn set_metric_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_name = input;
        self
    }
    /// <p>The name of the CloudWatch metric.</p>
    pub fn get_metric_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_name
    }
    /// <p>The namespace of the CloudWatch metric. A namespace is a container for CloudWatch metrics.</p>
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace of the CloudWatch metric. A namespace is a container for CloudWatch metrics.</p>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The namespace of the CloudWatch metric. A namespace is a container for CloudWatch metrics.</p>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// Appends an item to `dimensions`.
    ///
    /// To override the contents of this collection use [`set_dimensions`](Self::set_dimensions).
    ///
    /// <p>An array of CloudWatch dimensions associated with</p>
    pub fn dimensions(mut self, input: crate::types::CloudWatchMetricsDimension) -> Self {
        let mut v = self.dimensions.unwrap_or_default();
        v.push(input);
        self.dimensions = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of CloudWatch dimensions associated with</p>
    pub fn set_dimensions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CloudWatchMetricsDimension>>) -> Self {
        self.dimensions = input;
        self
    }
    /// <p>An array of CloudWatch dimensions associated with</p>
    pub fn get_dimensions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CloudWatchMetricsDimension>> {
        &self.dimensions
    }
    /// <p>The type of statistic associated with the CloudWatch metric. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Statistic">Statistics</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
    pub fn stat(mut self, input: crate::types::CloudWatchMetricsStat) -> Self {
        self.stat = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of statistic associated with the CloudWatch metric. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Statistic">Statistics</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
    pub fn set_stat(mut self, input: ::std::option::Option<crate::types::CloudWatchMetricsStat>) -> Self {
        self.stat = input;
        self
    }
    /// <p>The type of statistic associated with the CloudWatch metric. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Statistic">Statistics</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
    pub fn get_stat(&self) -> &::std::option::Option<crate::types::CloudWatchMetricsStat> {
        &self.stat
    }
    /// <p>The unit of measure used for the CloudWatch metric. For example, <code>Bytes</code>, <code>Seconds</code>, <code>Count</code>, and <code>Percent</code>.</p>
    pub fn unit(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.unit = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unit of measure used for the CloudWatch metric. For example, <code>Bytes</code>, <code>Seconds</code>, <code>Count</code>, and <code>Percent</code>.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.unit = input;
        self
    }
    /// <p>The unit of measure used for the CloudWatch metric. For example, <code>Bytes</code>, <code>Seconds</code>, <code>Count</code>, and <code>Percent</code>.</p>
    pub fn get_unit(&self) -> &::std::option::Option<::std::string::String> {
        &self.unit
    }
    /// <p>The length of time associated with the CloudWatch metric in number of seconds.</p>
    pub fn period(mut self, input: i32) -> Self {
        self.period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The length of time associated with the CloudWatch metric in number of seconds.</p>
    pub fn set_period(mut self, input: ::std::option::Option<i32>) -> Self {
        self.period = input;
        self
    }
    /// <p>The length of time associated with the CloudWatch metric in number of seconds.</p>
    pub fn get_period(&self) -> &::std::option::Option<i32> {
        &self.period
    }
    /// <p>This object returns anomaly metric data.</p>
    pub fn metric_data_summary(mut self, input: crate::types::CloudWatchMetricsDataSummary) -> Self {
        self.metric_data_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>This object returns anomaly metric data.</p>
    pub fn set_metric_data_summary(mut self, input: ::std::option::Option<crate::types::CloudWatchMetricsDataSummary>) -> Self {
        self.metric_data_summary = input;
        self
    }
    /// <p>This object returns anomaly metric data.</p>
    pub fn get_metric_data_summary(&self) -> &::std::option::Option<crate::types::CloudWatchMetricsDataSummary> {
        &self.metric_data_summary
    }
    /// Consumes the builder and constructs a [`CloudWatchMetricsDetail`](crate::types::CloudWatchMetricsDetail).
    pub fn build(self) -> crate::types::CloudWatchMetricsDetail {
        crate::types::CloudWatchMetricsDetail {
            metric_name: self.metric_name,
            namespace: self.namespace,
            dimensions: self.dimensions,
            stat: self.stat,
            unit: self.unit,
            period: self.period.unwrap_or_default(),
            metric_data_summary: self.metric_data_summary,
        }
    }
}
