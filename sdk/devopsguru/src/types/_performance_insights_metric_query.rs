// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A single query to be processed. Use these parameters to query the Performance Insights <code>GetResourceMetrics</code> API to retrieve the metrics for an anomaly. For more information, see <code> <a href="https://docs.aws.amazon.com/performance-insights/latest/APIReference/API_GetResourceMetrics.html">GetResourceMetrics</a> </code> in the <i>Amazon RDS Performance Insights API Reference</i>.</p>
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
pub struct PerformanceInsightsMetricQuery {
    /// <p>The name of the meteric used used when querying an Performance Insights <code>GetResourceMetrics</code> API for anomaly metrics.</p>
    /// <p>Valid values for <code>Metric</code> are:</p>
    /// <ul>
    /// <li>
    /// <p><code>db.load.avg</code> - a scaled representation of the number of active sessions for the database engine.</p></li>
    /// <li>
    /// <p><code>db.sampledload.avg</code> - the raw number of active sessions for the database engine.</p></li>
    /// </ul>
    /// <p>If the number of active sessions is less than an internal Performance Insights threshold, <code>db.load.avg</code> and <code>db.sampledload.avg</code> are the same value. If the number of active sessions is greater than the internal threshold, Performance Insights samples the active sessions, with <code>db.load.avg</code> showing the scaled values, <code>db.sampledload.avg</code> showing the raw values, and <code>db.sampledload.avg</code> less than <code>db.load.avg</code>. For most use cases, you can query <code>db.load.avg</code> only.</p>
    pub metric: ::std::option::Option<::std::string::String>,
    /// <p>The specification for how to aggregate the data points from a Performance Insights <code>GetResourceMetrics</code> API query. The Performance Insights query returns all of the dimensions within that group, unless you provide the names of specific dimensions within that group. You can also request that Performance Insights return a limited number of values for a dimension.</p>
    pub group_by: ::std::option::Option<crate::types::PerformanceInsightsMetricDimensionGroup>,
    /// <p>One or more filters to apply to a Performance Insights <code>GetResourceMetrics</code> API query. Restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>Any number of filters by the same dimension, as specified in the <code>GroupBy</code> parameter.</p></li>
    /// <li>
    /// <p>A single filter for any other dimension in this dimension group.</p></li>
    /// </ul>
    pub filter: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PerformanceInsightsMetricQuery {
    /// <p>The name of the meteric used used when querying an Performance Insights <code>GetResourceMetrics</code> API for anomaly metrics.</p>
    /// <p>Valid values for <code>Metric</code> are:</p>
    /// <ul>
    /// <li>
    /// <p><code>db.load.avg</code> - a scaled representation of the number of active sessions for the database engine.</p></li>
    /// <li>
    /// <p><code>db.sampledload.avg</code> - the raw number of active sessions for the database engine.</p></li>
    /// </ul>
    /// <p>If the number of active sessions is less than an internal Performance Insights threshold, <code>db.load.avg</code> and <code>db.sampledload.avg</code> are the same value. If the number of active sessions is greater than the internal threshold, Performance Insights samples the active sessions, with <code>db.load.avg</code> showing the scaled values, <code>db.sampledload.avg</code> showing the raw values, and <code>db.sampledload.avg</code> less than <code>db.load.avg</code>. For most use cases, you can query <code>db.load.avg</code> only.</p>
    pub fn metric(&self) -> ::std::option::Option<&str> {
        self.metric.as_deref()
    }
    /// <p>The specification for how to aggregate the data points from a Performance Insights <code>GetResourceMetrics</code> API query. The Performance Insights query returns all of the dimensions within that group, unless you provide the names of specific dimensions within that group. You can also request that Performance Insights return a limited number of values for a dimension.</p>
    pub fn group_by(&self) -> ::std::option::Option<&crate::types::PerformanceInsightsMetricDimensionGroup> {
        self.group_by.as_ref()
    }
    /// <p>One or more filters to apply to a Performance Insights <code>GetResourceMetrics</code> API query. Restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>Any number of filters by the same dimension, as specified in the <code>GroupBy</code> parameter.</p></li>
    /// <li>
    /// <p>A single filter for any other dimension in this dimension group.</p></li>
    /// </ul>
    pub fn filter(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.filter.as_ref()
    }
}
impl PerformanceInsightsMetricQuery {
    /// Creates a new builder-style object to manufacture [`PerformanceInsightsMetricQuery`](crate::types::PerformanceInsightsMetricQuery).
    pub fn builder() -> crate::types::builders::PerformanceInsightsMetricQueryBuilder {
        crate::types::builders::PerformanceInsightsMetricQueryBuilder::default()
    }
}

/// A builder for [`PerformanceInsightsMetricQuery`](crate::types::PerformanceInsightsMetricQuery).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PerformanceInsightsMetricQueryBuilder {
    pub(crate) metric: ::std::option::Option<::std::string::String>,
    pub(crate) group_by: ::std::option::Option<crate::types::PerformanceInsightsMetricDimensionGroup>,
    pub(crate) filter: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PerformanceInsightsMetricQueryBuilder {
    /// <p>The name of the meteric used used when querying an Performance Insights <code>GetResourceMetrics</code> API for anomaly metrics.</p>
    /// <p>Valid values for <code>Metric</code> are:</p>
    /// <ul>
    /// <li>
    /// <p><code>db.load.avg</code> - a scaled representation of the number of active sessions for the database engine.</p></li>
    /// <li>
    /// <p><code>db.sampledload.avg</code> - the raw number of active sessions for the database engine.</p></li>
    /// </ul>
    /// <p>If the number of active sessions is less than an internal Performance Insights threshold, <code>db.load.avg</code> and <code>db.sampledload.avg</code> are the same value. If the number of active sessions is greater than the internal threshold, Performance Insights samples the active sessions, with <code>db.load.avg</code> showing the scaled values, <code>db.sampledload.avg</code> showing the raw values, and <code>db.sampledload.avg</code> less than <code>db.load.avg</code>. For most use cases, you can query <code>db.load.avg</code> only.</p>
    pub fn metric(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the meteric used used when querying an Performance Insights <code>GetResourceMetrics</code> API for anomaly metrics.</p>
    /// <p>Valid values for <code>Metric</code> are:</p>
    /// <ul>
    /// <li>
    /// <p><code>db.load.avg</code> - a scaled representation of the number of active sessions for the database engine.</p></li>
    /// <li>
    /// <p><code>db.sampledload.avg</code> - the raw number of active sessions for the database engine.</p></li>
    /// </ul>
    /// <p>If the number of active sessions is less than an internal Performance Insights threshold, <code>db.load.avg</code> and <code>db.sampledload.avg</code> are the same value. If the number of active sessions is greater than the internal threshold, Performance Insights samples the active sessions, with <code>db.load.avg</code> showing the scaled values, <code>db.sampledload.avg</code> showing the raw values, and <code>db.sampledload.avg</code> less than <code>db.load.avg</code>. For most use cases, you can query <code>db.load.avg</code> only.</p>
    pub fn set_metric(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric = input;
        self
    }
    /// <p>The name of the meteric used used when querying an Performance Insights <code>GetResourceMetrics</code> API for anomaly metrics.</p>
    /// <p>Valid values for <code>Metric</code> are:</p>
    /// <ul>
    /// <li>
    /// <p><code>db.load.avg</code> - a scaled representation of the number of active sessions for the database engine.</p></li>
    /// <li>
    /// <p><code>db.sampledload.avg</code> - the raw number of active sessions for the database engine.</p></li>
    /// </ul>
    /// <p>If the number of active sessions is less than an internal Performance Insights threshold, <code>db.load.avg</code> and <code>db.sampledload.avg</code> are the same value. If the number of active sessions is greater than the internal threshold, Performance Insights samples the active sessions, with <code>db.load.avg</code> showing the scaled values, <code>db.sampledload.avg</code> showing the raw values, and <code>db.sampledload.avg</code> less than <code>db.load.avg</code>. For most use cases, you can query <code>db.load.avg</code> only.</p>
    pub fn get_metric(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric
    }
    /// <p>The specification for how to aggregate the data points from a Performance Insights <code>GetResourceMetrics</code> API query. The Performance Insights query returns all of the dimensions within that group, unless you provide the names of specific dimensions within that group. You can also request that Performance Insights return a limited number of values for a dimension.</p>
    pub fn group_by(mut self, input: crate::types::PerformanceInsightsMetricDimensionGroup) -> Self {
        self.group_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>The specification for how to aggregate the data points from a Performance Insights <code>GetResourceMetrics</code> API query. The Performance Insights query returns all of the dimensions within that group, unless you provide the names of specific dimensions within that group. You can also request that Performance Insights return a limited number of values for a dimension.</p>
    pub fn set_group_by(mut self, input: ::std::option::Option<crate::types::PerformanceInsightsMetricDimensionGroup>) -> Self {
        self.group_by = input;
        self
    }
    /// <p>The specification for how to aggregate the data points from a Performance Insights <code>GetResourceMetrics</code> API query. The Performance Insights query returns all of the dimensions within that group, unless you provide the names of specific dimensions within that group. You can also request that Performance Insights return a limited number of values for a dimension.</p>
    pub fn get_group_by(&self) -> &::std::option::Option<crate::types::PerformanceInsightsMetricDimensionGroup> {
        &self.group_by
    }
    /// Adds a key-value pair to `filter`.
    ///
    /// To override the contents of this collection use [`set_filter`](Self::set_filter).
    ///
    /// <p>One or more filters to apply to a Performance Insights <code>GetResourceMetrics</code> API query. Restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>Any number of filters by the same dimension, as specified in the <code>GroupBy</code> parameter.</p></li>
    /// <li>
    /// <p>A single filter for any other dimension in this dimension group.</p></li>
    /// </ul>
    pub fn filter(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.filter.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.filter = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>One or more filters to apply to a Performance Insights <code>GetResourceMetrics</code> API query. Restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>Any number of filters by the same dimension, as specified in the <code>GroupBy</code> parameter.</p></li>
    /// <li>
    /// <p>A single filter for any other dimension in this dimension group.</p></li>
    /// </ul>
    pub fn set_filter(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.filter = input;
        self
    }
    /// <p>One or more filters to apply to a Performance Insights <code>GetResourceMetrics</code> API query. Restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>Any number of filters by the same dimension, as specified in the <code>GroupBy</code> parameter.</p></li>
    /// <li>
    /// <p>A single filter for any other dimension in this dimension group.</p></li>
    /// </ul>
    pub fn get_filter(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.filter
    }
    /// Consumes the builder and constructs a [`PerformanceInsightsMetricQuery`](crate::types::PerformanceInsightsMetricQuery).
    pub fn build(self) -> crate::types::PerformanceInsightsMetricQuery {
        crate::types::PerformanceInsightsMetricQuery {
            metric: self.metric,
            group_by: self.group_by,
            filter: self.filter,
        }
    }
}
