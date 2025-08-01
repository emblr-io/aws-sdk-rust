// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about Performance Insights metrics.</p>
/// <p>Amazon RDS Performance Insights enables you to monitor and explore different dimensions of database load based on data captured from a running DB instance. DB load is measured as average active sessions. Performance Insights provides the data to API consumers as a two-dimensional time-series dataset. The time dimension provides DB load data for each time point in the queried time range. Each time point decomposes overall load in relation to the requested dimensions, measured at that time point. Examples include SQL, Wait event, User, and Host.</p>
/// <ul>
/// <li>
/// <p>To learn more about Performance Insights and Amazon Aurora DB instances, go to the <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_PerfInsights.html"> Amazon Aurora User Guide</a>.</p></li>
/// <li>
/// <p>To learn more about Performance Insights and Amazon RDS DB instances, go to the <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.html"> Amazon RDS User Guide</a>.</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PerformanceInsightsMetricsDetail {
    /// <p>The name used for a specific Performance Insights metric.</p>
    pub metric_display_name: ::std::option::Option<::std::string::String>,
    /// <p>The unit of measure for a metric. For example, a session or a process.</p>
    pub unit: ::std::option::Option<::std::string::String>,
    /// <p>A single query to be processed for the metric. For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsMetricQuery.html">PerformanceInsightsMetricQuery</a> </code>.</p>
    pub metric_query: ::std::option::Option<crate::types::PerformanceInsightsMetricQuery>,
    /// <p>For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsReferenceData.html">PerformanceInsightsReferenceData</a> </code>.</p>
    pub reference_data: ::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsReferenceData>>,
    /// <p>The metric statistics during the anomalous period detected by DevOps Guru;</p>
    pub stats_at_anomaly: ::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsStat>>,
    /// <p>Typical metric statistics that are not considered anomalous. When DevOps Guru analyzes metrics, it compares them to <code>StatsAtBaseline</code> to help determine if they are anomalous.</p>
    pub stats_at_baseline: ::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsStat>>,
}
impl PerformanceInsightsMetricsDetail {
    /// <p>The name used for a specific Performance Insights metric.</p>
    pub fn metric_display_name(&self) -> ::std::option::Option<&str> {
        self.metric_display_name.as_deref()
    }
    /// <p>The unit of measure for a metric. For example, a session or a process.</p>
    pub fn unit(&self) -> ::std::option::Option<&str> {
        self.unit.as_deref()
    }
    /// <p>A single query to be processed for the metric. For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsMetricQuery.html">PerformanceInsightsMetricQuery</a> </code>.</p>
    pub fn metric_query(&self) -> ::std::option::Option<&crate::types::PerformanceInsightsMetricQuery> {
        self.metric_query.as_ref()
    }
    /// <p>For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsReferenceData.html">PerformanceInsightsReferenceData</a> </code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reference_data.is_none()`.
    pub fn reference_data(&self) -> &[crate::types::PerformanceInsightsReferenceData] {
        self.reference_data.as_deref().unwrap_or_default()
    }
    /// <p>The metric statistics during the anomalous period detected by DevOps Guru;</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stats_at_anomaly.is_none()`.
    pub fn stats_at_anomaly(&self) -> &[crate::types::PerformanceInsightsStat] {
        self.stats_at_anomaly.as_deref().unwrap_or_default()
    }
    /// <p>Typical metric statistics that are not considered anomalous. When DevOps Guru analyzes metrics, it compares them to <code>StatsAtBaseline</code> to help determine if they are anomalous.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stats_at_baseline.is_none()`.
    pub fn stats_at_baseline(&self) -> &[crate::types::PerformanceInsightsStat] {
        self.stats_at_baseline.as_deref().unwrap_or_default()
    }
}
impl PerformanceInsightsMetricsDetail {
    /// Creates a new builder-style object to manufacture [`PerformanceInsightsMetricsDetail`](crate::types::PerformanceInsightsMetricsDetail).
    pub fn builder() -> crate::types::builders::PerformanceInsightsMetricsDetailBuilder {
        crate::types::builders::PerformanceInsightsMetricsDetailBuilder::default()
    }
}

/// A builder for [`PerformanceInsightsMetricsDetail`](crate::types::PerformanceInsightsMetricsDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PerformanceInsightsMetricsDetailBuilder {
    pub(crate) metric_display_name: ::std::option::Option<::std::string::String>,
    pub(crate) unit: ::std::option::Option<::std::string::String>,
    pub(crate) metric_query: ::std::option::Option<crate::types::PerformanceInsightsMetricQuery>,
    pub(crate) reference_data: ::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsReferenceData>>,
    pub(crate) stats_at_anomaly: ::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsStat>>,
    pub(crate) stats_at_baseline: ::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsStat>>,
}
impl PerformanceInsightsMetricsDetailBuilder {
    /// <p>The name used for a specific Performance Insights metric.</p>
    pub fn metric_display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name used for a specific Performance Insights metric.</p>
    pub fn set_metric_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_display_name = input;
        self
    }
    /// <p>The name used for a specific Performance Insights metric.</p>
    pub fn get_metric_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_display_name
    }
    /// <p>The unit of measure for a metric. For example, a session or a process.</p>
    pub fn unit(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.unit = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unit of measure for a metric. For example, a session or a process.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.unit = input;
        self
    }
    /// <p>The unit of measure for a metric. For example, a session or a process.</p>
    pub fn get_unit(&self) -> &::std::option::Option<::std::string::String> {
        &self.unit
    }
    /// <p>A single query to be processed for the metric. For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsMetricQuery.html">PerformanceInsightsMetricQuery</a> </code>.</p>
    pub fn metric_query(mut self, input: crate::types::PerformanceInsightsMetricQuery) -> Self {
        self.metric_query = ::std::option::Option::Some(input);
        self
    }
    /// <p>A single query to be processed for the metric. For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsMetricQuery.html">PerformanceInsightsMetricQuery</a> </code>.</p>
    pub fn set_metric_query(mut self, input: ::std::option::Option<crate::types::PerformanceInsightsMetricQuery>) -> Self {
        self.metric_query = input;
        self
    }
    /// <p>A single query to be processed for the metric. For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsMetricQuery.html">PerformanceInsightsMetricQuery</a> </code>.</p>
    pub fn get_metric_query(&self) -> &::std::option::Option<crate::types::PerformanceInsightsMetricQuery> {
        &self.metric_query
    }
    /// Appends an item to `reference_data`.
    ///
    /// To override the contents of this collection use [`set_reference_data`](Self::set_reference_data).
    ///
    /// <p>For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsReferenceData.html">PerformanceInsightsReferenceData</a> </code>.</p>
    pub fn reference_data(mut self, input: crate::types::PerformanceInsightsReferenceData) -> Self {
        let mut v = self.reference_data.unwrap_or_default();
        v.push(input);
        self.reference_data = ::std::option::Option::Some(v);
        self
    }
    /// <p>For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsReferenceData.html">PerformanceInsightsReferenceData</a> </code>.</p>
    pub fn set_reference_data(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsReferenceData>>) -> Self {
        self.reference_data = input;
        self
    }
    /// <p>For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsReferenceData.html">PerformanceInsightsReferenceData</a> </code>.</p>
    pub fn get_reference_data(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsReferenceData>> {
        &self.reference_data
    }
    /// Appends an item to `stats_at_anomaly`.
    ///
    /// To override the contents of this collection use [`set_stats_at_anomaly`](Self::set_stats_at_anomaly).
    ///
    /// <p>The metric statistics during the anomalous period detected by DevOps Guru;</p>
    pub fn stats_at_anomaly(mut self, input: crate::types::PerformanceInsightsStat) -> Self {
        let mut v = self.stats_at_anomaly.unwrap_or_default();
        v.push(input);
        self.stats_at_anomaly = ::std::option::Option::Some(v);
        self
    }
    /// <p>The metric statistics during the anomalous period detected by DevOps Guru;</p>
    pub fn set_stats_at_anomaly(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsStat>>) -> Self {
        self.stats_at_anomaly = input;
        self
    }
    /// <p>The metric statistics during the anomalous period detected by DevOps Guru;</p>
    pub fn get_stats_at_anomaly(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsStat>> {
        &self.stats_at_anomaly
    }
    /// Appends an item to `stats_at_baseline`.
    ///
    /// To override the contents of this collection use [`set_stats_at_baseline`](Self::set_stats_at_baseline).
    ///
    /// <p>Typical metric statistics that are not considered anomalous. When DevOps Guru analyzes metrics, it compares them to <code>StatsAtBaseline</code> to help determine if they are anomalous.</p>
    pub fn stats_at_baseline(mut self, input: crate::types::PerformanceInsightsStat) -> Self {
        let mut v = self.stats_at_baseline.unwrap_or_default();
        v.push(input);
        self.stats_at_baseline = ::std::option::Option::Some(v);
        self
    }
    /// <p>Typical metric statistics that are not considered anomalous. When DevOps Guru analyzes metrics, it compares them to <code>StatsAtBaseline</code> to help determine if they are anomalous.</p>
    pub fn set_stats_at_baseline(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsStat>>) -> Self {
        self.stats_at_baseline = input;
        self
    }
    /// <p>Typical metric statistics that are not considered anomalous. When DevOps Guru analyzes metrics, it compares them to <code>StatsAtBaseline</code> to help determine if they are anomalous.</p>
    pub fn get_stats_at_baseline(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PerformanceInsightsStat>> {
        &self.stats_at_baseline
    }
    /// Consumes the builder and constructs a [`PerformanceInsightsMetricsDetail`](crate::types::PerformanceInsightsMetricsDetail).
    pub fn build(self) -> crate::types::PerformanceInsightsMetricsDetail {
        crate::types::PerformanceInsightsMetricsDetail {
            metric_display_name: self.metric_display_name,
            unit: self.unit,
            metric_query: self.metric_query,
            reference_data: self.reference_data,
            stats_at_anomaly: self.stats_at_anomaly,
            stats_at_baseline: self.stats_at_baseline,
        }
    }
}
