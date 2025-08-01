// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines and enables Amazon CloudWatch metrics and web request sample collection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsWafv2VisibilityConfigDetails {
    /// <p>A boolean indicating whether the associated resource sends metrics to Amazon CloudWatch. For the list of available metrics, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics">WAF metrics and dimensions</a> in the <i>WAF Developer Guide</i>.</p>
    pub cloud_watch_metrics_enabled: ::std::option::Option<bool>,
    /// <p>A name of the Amazon CloudWatch metric.</p>
    pub metric_name: ::std::option::Option<::std::string::String>,
    /// <p>A boolean indicating whether WAF should store a sampling of the web requests that match the rules. You can view the sampled requests through the WAF console.</p>
    pub sampled_requests_enabled: ::std::option::Option<bool>,
}
impl AwsWafv2VisibilityConfigDetails {
    /// <p>A boolean indicating whether the associated resource sends metrics to Amazon CloudWatch. For the list of available metrics, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics">WAF metrics and dimensions</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn cloud_watch_metrics_enabled(&self) -> ::std::option::Option<bool> {
        self.cloud_watch_metrics_enabled
    }
    /// <p>A name of the Amazon CloudWatch metric.</p>
    pub fn metric_name(&self) -> ::std::option::Option<&str> {
        self.metric_name.as_deref()
    }
    /// <p>A boolean indicating whether WAF should store a sampling of the web requests that match the rules. You can view the sampled requests through the WAF console.</p>
    pub fn sampled_requests_enabled(&self) -> ::std::option::Option<bool> {
        self.sampled_requests_enabled
    }
}
impl AwsWafv2VisibilityConfigDetails {
    /// Creates a new builder-style object to manufacture [`AwsWafv2VisibilityConfigDetails`](crate::types::AwsWafv2VisibilityConfigDetails).
    pub fn builder() -> crate::types::builders::AwsWafv2VisibilityConfigDetailsBuilder {
        crate::types::builders::AwsWafv2VisibilityConfigDetailsBuilder::default()
    }
}

/// A builder for [`AwsWafv2VisibilityConfigDetails`](crate::types::AwsWafv2VisibilityConfigDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsWafv2VisibilityConfigDetailsBuilder {
    pub(crate) cloud_watch_metrics_enabled: ::std::option::Option<bool>,
    pub(crate) metric_name: ::std::option::Option<::std::string::String>,
    pub(crate) sampled_requests_enabled: ::std::option::Option<bool>,
}
impl AwsWafv2VisibilityConfigDetailsBuilder {
    /// <p>A boolean indicating whether the associated resource sends metrics to Amazon CloudWatch. For the list of available metrics, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics">WAF metrics and dimensions</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn cloud_watch_metrics_enabled(mut self, input: bool) -> Self {
        self.cloud_watch_metrics_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>A boolean indicating whether the associated resource sends metrics to Amazon CloudWatch. For the list of available metrics, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics">WAF metrics and dimensions</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn set_cloud_watch_metrics_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.cloud_watch_metrics_enabled = input;
        self
    }
    /// <p>A boolean indicating whether the associated resource sends metrics to Amazon CloudWatch. For the list of available metrics, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics">WAF metrics and dimensions</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn get_cloud_watch_metrics_enabled(&self) -> &::std::option::Option<bool> {
        &self.cloud_watch_metrics_enabled
    }
    /// <p>A name of the Amazon CloudWatch metric.</p>
    pub fn metric_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name of the Amazon CloudWatch metric.</p>
    pub fn set_metric_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_name = input;
        self
    }
    /// <p>A name of the Amazon CloudWatch metric.</p>
    pub fn get_metric_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_name
    }
    /// <p>A boolean indicating whether WAF should store a sampling of the web requests that match the rules. You can view the sampled requests through the WAF console.</p>
    pub fn sampled_requests_enabled(mut self, input: bool) -> Self {
        self.sampled_requests_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>A boolean indicating whether WAF should store a sampling of the web requests that match the rules. You can view the sampled requests through the WAF console.</p>
    pub fn set_sampled_requests_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.sampled_requests_enabled = input;
        self
    }
    /// <p>A boolean indicating whether WAF should store a sampling of the web requests that match the rules. You can view the sampled requests through the WAF console.</p>
    pub fn get_sampled_requests_enabled(&self) -> &::std::option::Option<bool> {
        &self.sampled_requests_enabled
    }
    /// Consumes the builder and constructs a [`AwsWafv2VisibilityConfigDetails`](crate::types::AwsWafv2VisibilityConfigDetails).
    pub fn build(self) -> crate::types::AwsWafv2VisibilityConfigDetails {
        crate::types::AwsWafv2VisibilityConfigDetails {
            cloud_watch_metrics_enabled: self.cloud_watch_metrics_enabled,
            metric_name: self.metric_name,
            sampled_requests_enabled: self.sampled_requests_enabled,
        }
    }
}
