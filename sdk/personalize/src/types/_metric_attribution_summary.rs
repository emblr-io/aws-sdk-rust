// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides a summary of the properties of a metric attribution. For a complete listing, call the <a href="https://docs.aws.amazon.com/personalize/latest/dg/API_DescribeMetricAttribution.html">DescribeMetricAttribution</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MetricAttributionSummary {
    /// <p>The name of the metric attribution.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The metric attribution's Amazon Resource Name (ARN).</p>
    pub metric_attribution_arn: ::std::option::Option<::std::string::String>,
    /// <p>The metric attribution's status.</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The metric attribution's creation date time.</p>
    pub creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The metric attribution's last updated date time.</p>
    pub last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The metric attribution's failure reason.</p>
    pub failure_reason: ::std::option::Option<::std::string::String>,
}
impl MetricAttributionSummary {
    /// <p>The name of the metric attribution.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The metric attribution's Amazon Resource Name (ARN).</p>
    pub fn metric_attribution_arn(&self) -> ::std::option::Option<&str> {
        self.metric_attribution_arn.as_deref()
    }
    /// <p>The metric attribution's status.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The metric attribution's creation date time.</p>
    pub fn creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date_time.as_ref()
    }
    /// <p>The metric attribution's last updated date time.</p>
    pub fn last_updated_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_date_time.as_ref()
    }
    /// <p>The metric attribution's failure reason.</p>
    pub fn failure_reason(&self) -> ::std::option::Option<&str> {
        self.failure_reason.as_deref()
    }
}
impl MetricAttributionSummary {
    /// Creates a new builder-style object to manufacture [`MetricAttributionSummary`](crate::types::MetricAttributionSummary).
    pub fn builder() -> crate::types::builders::MetricAttributionSummaryBuilder {
        crate::types::builders::MetricAttributionSummaryBuilder::default()
    }
}

/// A builder for [`MetricAttributionSummary`](crate::types::MetricAttributionSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MetricAttributionSummaryBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) metric_attribution_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) failure_reason: ::std::option::Option<::std::string::String>,
}
impl MetricAttributionSummaryBuilder {
    /// <p>The name of the metric attribution.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the metric attribution.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the metric attribution.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The metric attribution's Amazon Resource Name (ARN).</p>
    pub fn metric_attribution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_attribution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The metric attribution's Amazon Resource Name (ARN).</p>
    pub fn set_metric_attribution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_attribution_arn = input;
        self
    }
    /// <p>The metric attribution's Amazon Resource Name (ARN).</p>
    pub fn get_metric_attribution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_attribution_arn
    }
    /// <p>The metric attribution's status.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The metric attribution's status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The metric attribution's status.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The metric attribution's creation date time.</p>
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metric attribution's creation date time.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>The metric attribution's creation date time.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    /// <p>The metric attribution's last updated date time.</p>
    pub fn last_updated_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metric attribution's last updated date time.</p>
    pub fn set_last_updated_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_date_time = input;
        self
    }
    /// <p>The metric attribution's last updated date time.</p>
    pub fn get_last_updated_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_date_time
    }
    /// <p>The metric attribution's failure reason.</p>
    pub fn failure_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.failure_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The metric attribution's failure reason.</p>
    pub fn set_failure_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.failure_reason = input;
        self
    }
    /// <p>The metric attribution's failure reason.</p>
    pub fn get_failure_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.failure_reason
    }
    /// Consumes the builder and constructs a [`MetricAttributionSummary`](crate::types::MetricAttributionSummary).
    pub fn build(self) -> crate::types::MetricAttributionSummary {
        crate::types::MetricAttributionSummary {
            name: self.name,
            metric_attribution_arn: self.metric_attribution_arn,
            status: self.status,
            creation_date_time: self.creation_date_time,
            last_updated_date_time: self.last_updated_date_time,
            failure_reason: self.failure_reason,
        }
    }
}
