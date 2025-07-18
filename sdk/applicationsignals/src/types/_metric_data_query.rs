// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Use this structure to define a metric or metric math expression that you want to use as for a service level objective.</p>
/// <p>Each <code>MetricDataQuery</code> in the <code>MetricDataQueries</code> array specifies either a metric to retrieve, or a metric math expression to be performed on retrieved metrics. A single <code>MetricDataQueries</code> array can include as many as 20 <code>MetricDataQuery</code> structures in the array. The 20 structures can include as many as 10 structures that contain a <code>MetricStat</code> parameter to retrieve a metric, and as many as 10 structures that contain the <code>Expression</code> parameter to perform a math expression. Of those <code>Expression</code> structures, exactly one must have true as the value for <code>ReturnData</code>. The result of this expression used for the SLO.</p>
/// <p>For more information about metric math expressions, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html">CloudWatchUse metric math</a>.</p>
/// <p>Within each <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MetricDataQuery {
    /// <p>A short name used to tie this object to the results in the response. This <code>Id</code> must be unique within a <code>MetricDataQueries</code> array. If you are performing math expressions on this set of data, this name represents that data and can serve as a variable in the metric math expression. The valid characters are letters, numbers, and underscore. The first character must be a lowercase letter.</p>
    pub id: ::std::string::String,
    /// <p>A metric to be used directly for the SLO, or to be used in the math expression that will be used for the SLO.</p>
    /// <p>Within one <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
    pub metric_stat: ::std::option::Option<crate::types::MetricStat>,
    /// <p>This field can contain a metric math expression to be performed on the other metrics that you are retrieving within this <code>MetricDataQueries</code> structure.</p>
    /// <p>A math expression can use the <code>Id</code> of the other metrics or queries to refer to those metrics, and can also use the <code>Id</code> of other expressions to use the result of those expressions. For more information about metric math expressions, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html#metric-math-syntax">Metric Math Syntax and Functions</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
    /// <p>Within each <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
    pub expression: ::std::option::Option<::std::string::String>,
    /// <p>A human-readable label for this metric or expression. This is especially useful if this is an expression, so that you know what the value represents. If the metric or expression is shown in a CloudWatch dashboard widget, the label is shown. If <code>Label</code> is omitted, CloudWatch generates a default.</p>
    /// <p>You can put dynamic expressions into a label, so that it is more descriptive. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/graph-dynamic-labels.html">Using Dynamic Labels</a>.</p>
    pub label: ::std::option::Option<::std::string::String>,
    /// <p>Use this only if you are using a metric math expression for the SLO. Specify <code>true</code> for <code>ReturnData</code> for only the one expression result to use as the alarm. For all other metrics and expressions in the same <code>CreateServiceLevelObjective</code> operation, specify <code>ReturnData</code> as <code>false</code>.</p>
    pub return_data: ::std::option::Option<bool>,
    /// <p>The granularity, in seconds, of the returned data points for this metric. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60. For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 60. High-resolution metrics are those metrics stored by a <code>PutMetricData</code> call that includes a <code>StorageResolution</code> of 1 second.</p>
    /// <p>If the <code>StartTime</code> parameter specifies a time stamp that is greater than 3 hours ago, you must specify the period as follows or no data points in that time range is returned:</p>
    /// <ul>
    /// <li>
    /// <p>Start time between 3 hours and 15 days ago - Use a multiple of 60 seconds (1 minute).</p></li>
    /// <li>
    /// <p>Start time between 15 and 63 days ago - Use a multiple of 300 seconds (5 minutes).</p></li>
    /// <li>
    /// <p>Start time greater than 63 days ago - Use a multiple of 3600 seconds (1 hour).</p></li>
    /// </ul>
    pub period: ::std::option::Option<i32>,
    /// <p>The ID of the account where this metric is located. If you are performing this operation in a monitoring account, use this to specify which source account to retrieve this metric from.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
}
impl MetricDataQuery {
    /// <p>A short name used to tie this object to the results in the response. This <code>Id</code> must be unique within a <code>MetricDataQueries</code> array. If you are performing math expressions on this set of data, this name represents that data and can serve as a variable in the metric math expression. The valid characters are letters, numbers, and underscore. The first character must be a lowercase letter.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>A metric to be used directly for the SLO, or to be used in the math expression that will be used for the SLO.</p>
    /// <p>Within one <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
    pub fn metric_stat(&self) -> ::std::option::Option<&crate::types::MetricStat> {
        self.metric_stat.as_ref()
    }
    /// <p>This field can contain a metric math expression to be performed on the other metrics that you are retrieving within this <code>MetricDataQueries</code> structure.</p>
    /// <p>A math expression can use the <code>Id</code> of the other metrics or queries to refer to those metrics, and can also use the <code>Id</code> of other expressions to use the result of those expressions. For more information about metric math expressions, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html#metric-math-syntax">Metric Math Syntax and Functions</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
    /// <p>Within each <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
    pub fn expression(&self) -> ::std::option::Option<&str> {
        self.expression.as_deref()
    }
    /// <p>A human-readable label for this metric or expression. This is especially useful if this is an expression, so that you know what the value represents. If the metric or expression is shown in a CloudWatch dashboard widget, the label is shown. If <code>Label</code> is omitted, CloudWatch generates a default.</p>
    /// <p>You can put dynamic expressions into a label, so that it is more descriptive. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/graph-dynamic-labels.html">Using Dynamic Labels</a>.</p>
    pub fn label(&self) -> ::std::option::Option<&str> {
        self.label.as_deref()
    }
    /// <p>Use this only if you are using a metric math expression for the SLO. Specify <code>true</code> for <code>ReturnData</code> for only the one expression result to use as the alarm. For all other metrics and expressions in the same <code>CreateServiceLevelObjective</code> operation, specify <code>ReturnData</code> as <code>false</code>.</p>
    pub fn return_data(&self) -> ::std::option::Option<bool> {
        self.return_data
    }
    /// <p>The granularity, in seconds, of the returned data points for this metric. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60. For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 60. High-resolution metrics are those metrics stored by a <code>PutMetricData</code> call that includes a <code>StorageResolution</code> of 1 second.</p>
    /// <p>If the <code>StartTime</code> parameter specifies a time stamp that is greater than 3 hours ago, you must specify the period as follows or no data points in that time range is returned:</p>
    /// <ul>
    /// <li>
    /// <p>Start time between 3 hours and 15 days ago - Use a multiple of 60 seconds (1 minute).</p></li>
    /// <li>
    /// <p>Start time between 15 and 63 days ago - Use a multiple of 300 seconds (5 minutes).</p></li>
    /// <li>
    /// <p>Start time greater than 63 days ago - Use a multiple of 3600 seconds (1 hour).</p></li>
    /// </ul>
    pub fn period(&self) -> ::std::option::Option<i32> {
        self.period
    }
    /// <p>The ID of the account where this metric is located. If you are performing this operation in a monitoring account, use this to specify which source account to retrieve this metric from.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
}
impl MetricDataQuery {
    /// Creates a new builder-style object to manufacture [`MetricDataQuery`](crate::types::MetricDataQuery).
    pub fn builder() -> crate::types::builders::MetricDataQueryBuilder {
        crate::types::builders::MetricDataQueryBuilder::default()
    }
}

/// A builder for [`MetricDataQuery`](crate::types::MetricDataQuery).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MetricDataQueryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) metric_stat: ::std::option::Option<crate::types::MetricStat>,
    pub(crate) expression: ::std::option::Option<::std::string::String>,
    pub(crate) label: ::std::option::Option<::std::string::String>,
    pub(crate) return_data: ::std::option::Option<bool>,
    pub(crate) period: ::std::option::Option<i32>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
}
impl MetricDataQueryBuilder {
    /// <p>A short name used to tie this object to the results in the response. This <code>Id</code> must be unique within a <code>MetricDataQueries</code> array. If you are performing math expressions on this set of data, this name represents that data and can serve as a variable in the metric math expression. The valid characters are letters, numbers, and underscore. The first character must be a lowercase letter.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short name used to tie this object to the results in the response. This <code>Id</code> must be unique within a <code>MetricDataQueries</code> array. If you are performing math expressions on this set of data, this name represents that data and can serve as a variable in the metric math expression. The valid characters are letters, numbers, and underscore. The first character must be a lowercase letter.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>A short name used to tie this object to the results in the response. This <code>Id</code> must be unique within a <code>MetricDataQueries</code> array. If you are performing math expressions on this set of data, this name represents that data and can serve as a variable in the metric math expression. The valid characters are letters, numbers, and underscore. The first character must be a lowercase letter.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A metric to be used directly for the SLO, or to be used in the math expression that will be used for the SLO.</p>
    /// <p>Within one <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
    pub fn metric_stat(mut self, input: crate::types::MetricStat) -> Self {
        self.metric_stat = ::std::option::Option::Some(input);
        self
    }
    /// <p>A metric to be used directly for the SLO, or to be used in the math expression that will be used for the SLO.</p>
    /// <p>Within one <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
    pub fn set_metric_stat(mut self, input: ::std::option::Option<crate::types::MetricStat>) -> Self {
        self.metric_stat = input;
        self
    }
    /// <p>A metric to be used directly for the SLO, or to be used in the math expression that will be used for the SLO.</p>
    /// <p>Within one <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
    pub fn get_metric_stat(&self) -> &::std::option::Option<crate::types::MetricStat> {
        &self.metric_stat
    }
    /// <p>This field can contain a metric math expression to be performed on the other metrics that you are retrieving within this <code>MetricDataQueries</code> structure.</p>
    /// <p>A math expression can use the <code>Id</code> of the other metrics or queries to refer to those metrics, and can also use the <code>Id</code> of other expressions to use the result of those expressions. For more information about metric math expressions, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html#metric-math-syntax">Metric Math Syntax and Functions</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
    /// <p>Within each <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
    pub fn expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This field can contain a metric math expression to be performed on the other metrics that you are retrieving within this <code>MetricDataQueries</code> structure.</p>
    /// <p>A math expression can use the <code>Id</code> of the other metrics or queries to refer to those metrics, and can also use the <code>Id</code> of other expressions to use the result of those expressions. For more information about metric math expressions, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html#metric-math-syntax">Metric Math Syntax and Functions</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
    /// <p>Within each <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
    pub fn set_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expression = input;
        self
    }
    /// <p>This field can contain a metric math expression to be performed on the other metrics that you are retrieving within this <code>MetricDataQueries</code> structure.</p>
    /// <p>A math expression can use the <code>Id</code> of the other metrics or queries to refer to those metrics, and can also use the <code>Id</code> of other expressions to use the result of those expressions. For more information about metric math expressions, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html#metric-math-syntax">Metric Math Syntax and Functions</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
    /// <p>Within each <code>MetricDataQuery</code> object, you must specify either <code>Expression</code> or <code>MetricStat</code> but not both.</p>
    pub fn get_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.expression
    }
    /// <p>A human-readable label for this metric or expression. This is especially useful if this is an expression, so that you know what the value represents. If the metric or expression is shown in a CloudWatch dashboard widget, the label is shown. If <code>Label</code> is omitted, CloudWatch generates a default.</p>
    /// <p>You can put dynamic expressions into a label, so that it is more descriptive. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/graph-dynamic-labels.html">Using Dynamic Labels</a>.</p>
    pub fn label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A human-readable label for this metric or expression. This is especially useful if this is an expression, so that you know what the value represents. If the metric or expression is shown in a CloudWatch dashboard widget, the label is shown. If <code>Label</code> is omitted, CloudWatch generates a default.</p>
    /// <p>You can put dynamic expressions into a label, so that it is more descriptive. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/graph-dynamic-labels.html">Using Dynamic Labels</a>.</p>
    pub fn set_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.label = input;
        self
    }
    /// <p>A human-readable label for this metric or expression. This is especially useful if this is an expression, so that you know what the value represents. If the metric or expression is shown in a CloudWatch dashboard widget, the label is shown. If <code>Label</code> is omitted, CloudWatch generates a default.</p>
    /// <p>You can put dynamic expressions into a label, so that it is more descriptive. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/graph-dynamic-labels.html">Using Dynamic Labels</a>.</p>
    pub fn get_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.label
    }
    /// <p>Use this only if you are using a metric math expression for the SLO. Specify <code>true</code> for <code>ReturnData</code> for only the one expression result to use as the alarm. For all other metrics and expressions in the same <code>CreateServiceLevelObjective</code> operation, specify <code>ReturnData</code> as <code>false</code>.</p>
    pub fn return_data(mut self, input: bool) -> Self {
        self.return_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use this only if you are using a metric math expression for the SLO. Specify <code>true</code> for <code>ReturnData</code> for only the one expression result to use as the alarm. For all other metrics and expressions in the same <code>CreateServiceLevelObjective</code> operation, specify <code>ReturnData</code> as <code>false</code>.</p>
    pub fn set_return_data(mut self, input: ::std::option::Option<bool>) -> Self {
        self.return_data = input;
        self
    }
    /// <p>Use this only if you are using a metric math expression for the SLO. Specify <code>true</code> for <code>ReturnData</code> for only the one expression result to use as the alarm. For all other metrics and expressions in the same <code>CreateServiceLevelObjective</code> operation, specify <code>ReturnData</code> as <code>false</code>.</p>
    pub fn get_return_data(&self) -> &::std::option::Option<bool> {
        &self.return_data
    }
    /// <p>The granularity, in seconds, of the returned data points for this metric. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60. For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 60. High-resolution metrics are those metrics stored by a <code>PutMetricData</code> call that includes a <code>StorageResolution</code> of 1 second.</p>
    /// <p>If the <code>StartTime</code> parameter specifies a time stamp that is greater than 3 hours ago, you must specify the period as follows or no data points in that time range is returned:</p>
    /// <ul>
    /// <li>
    /// <p>Start time between 3 hours and 15 days ago - Use a multiple of 60 seconds (1 minute).</p></li>
    /// <li>
    /// <p>Start time between 15 and 63 days ago - Use a multiple of 300 seconds (5 minutes).</p></li>
    /// <li>
    /// <p>Start time greater than 63 days ago - Use a multiple of 3600 seconds (1 hour).</p></li>
    /// </ul>
    pub fn period(mut self, input: i32) -> Self {
        self.period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The granularity, in seconds, of the returned data points for this metric. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60. For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 60. High-resolution metrics are those metrics stored by a <code>PutMetricData</code> call that includes a <code>StorageResolution</code> of 1 second.</p>
    /// <p>If the <code>StartTime</code> parameter specifies a time stamp that is greater than 3 hours ago, you must specify the period as follows or no data points in that time range is returned:</p>
    /// <ul>
    /// <li>
    /// <p>Start time between 3 hours and 15 days ago - Use a multiple of 60 seconds (1 minute).</p></li>
    /// <li>
    /// <p>Start time between 15 and 63 days ago - Use a multiple of 300 seconds (5 minutes).</p></li>
    /// <li>
    /// <p>Start time greater than 63 days ago - Use a multiple of 3600 seconds (1 hour).</p></li>
    /// </ul>
    pub fn set_period(mut self, input: ::std::option::Option<i32>) -> Self {
        self.period = input;
        self
    }
    /// <p>The granularity, in seconds, of the returned data points for this metric. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60. For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 60. High-resolution metrics are those metrics stored by a <code>PutMetricData</code> call that includes a <code>StorageResolution</code> of 1 second.</p>
    /// <p>If the <code>StartTime</code> parameter specifies a time stamp that is greater than 3 hours ago, you must specify the period as follows or no data points in that time range is returned:</p>
    /// <ul>
    /// <li>
    /// <p>Start time between 3 hours and 15 days ago - Use a multiple of 60 seconds (1 minute).</p></li>
    /// <li>
    /// <p>Start time between 15 and 63 days ago - Use a multiple of 300 seconds (5 minutes).</p></li>
    /// <li>
    /// <p>Start time greater than 63 days ago - Use a multiple of 3600 seconds (1 hour).</p></li>
    /// </ul>
    pub fn get_period(&self) -> &::std::option::Option<i32> {
        &self.period
    }
    /// <p>The ID of the account where this metric is located. If you are performing this operation in a monitoring account, use this to specify which source account to retrieve this metric from.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the account where this metric is located. If you are performing this operation in a monitoring account, use this to specify which source account to retrieve this metric from.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The ID of the account where this metric is located. If you are performing this operation in a monitoring account, use this to specify which source account to retrieve this metric from.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// Consumes the builder and constructs a [`MetricDataQuery`](crate::types::MetricDataQuery).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::MetricDataQueryBuilder::id)
    pub fn build(self) -> ::std::result::Result<crate::types::MetricDataQuery, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MetricDataQuery {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building MetricDataQuery",
                )
            })?,
            metric_stat: self.metric_stat,
            expression: self.expression,
            label: self.label,
            return_data: self.return_data,
            period: self.period,
            account_id: self.account_id,
        })
    }
}
