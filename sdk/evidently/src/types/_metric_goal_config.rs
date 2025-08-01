// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Use this structure to tell Evidently whether higher or lower values are desired for a metric that is used in an experiment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MetricGoalConfig {
    /// <p>A structure that contains details about the metric.</p>
    pub metric_definition: ::std::option::Option<crate::types::MetricDefinitionConfig>,
    /// <p><code>INCREASE</code> means that a variation with a higher number for this metric is performing better.</p>
    /// <p><code>DECREASE</code> means that a variation with a lower number for this metric is performing better.</p>
    pub desired_change: ::std::option::Option<crate::types::ChangeDirectionEnum>,
}
impl MetricGoalConfig {
    /// <p>A structure that contains details about the metric.</p>
    pub fn metric_definition(&self) -> ::std::option::Option<&crate::types::MetricDefinitionConfig> {
        self.metric_definition.as_ref()
    }
    /// <p><code>INCREASE</code> means that a variation with a higher number for this metric is performing better.</p>
    /// <p><code>DECREASE</code> means that a variation with a lower number for this metric is performing better.</p>
    pub fn desired_change(&self) -> ::std::option::Option<&crate::types::ChangeDirectionEnum> {
        self.desired_change.as_ref()
    }
}
impl MetricGoalConfig {
    /// Creates a new builder-style object to manufacture [`MetricGoalConfig`](crate::types::MetricGoalConfig).
    pub fn builder() -> crate::types::builders::MetricGoalConfigBuilder {
        crate::types::builders::MetricGoalConfigBuilder::default()
    }
}

/// A builder for [`MetricGoalConfig`](crate::types::MetricGoalConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MetricGoalConfigBuilder {
    pub(crate) metric_definition: ::std::option::Option<crate::types::MetricDefinitionConfig>,
    pub(crate) desired_change: ::std::option::Option<crate::types::ChangeDirectionEnum>,
}
impl MetricGoalConfigBuilder {
    /// <p>A structure that contains details about the metric.</p>
    /// This field is required.
    pub fn metric_definition(mut self, input: crate::types::MetricDefinitionConfig) -> Self {
        self.metric_definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains details about the metric.</p>
    pub fn set_metric_definition(mut self, input: ::std::option::Option<crate::types::MetricDefinitionConfig>) -> Self {
        self.metric_definition = input;
        self
    }
    /// <p>A structure that contains details about the metric.</p>
    pub fn get_metric_definition(&self) -> &::std::option::Option<crate::types::MetricDefinitionConfig> {
        &self.metric_definition
    }
    /// <p><code>INCREASE</code> means that a variation with a higher number for this metric is performing better.</p>
    /// <p><code>DECREASE</code> means that a variation with a lower number for this metric is performing better.</p>
    pub fn desired_change(mut self, input: crate::types::ChangeDirectionEnum) -> Self {
        self.desired_change = ::std::option::Option::Some(input);
        self
    }
    /// <p><code>INCREASE</code> means that a variation with a higher number for this metric is performing better.</p>
    /// <p><code>DECREASE</code> means that a variation with a lower number for this metric is performing better.</p>
    pub fn set_desired_change(mut self, input: ::std::option::Option<crate::types::ChangeDirectionEnum>) -> Self {
        self.desired_change = input;
        self
    }
    /// <p><code>INCREASE</code> means that a variation with a higher number for this metric is performing better.</p>
    /// <p><code>DECREASE</code> means that a variation with a lower number for this metric is performing better.</p>
    pub fn get_desired_change(&self) -> &::std::option::Option<crate::types::ChangeDirectionEnum> {
        &self.desired_change
    }
    /// Consumes the builder and constructs a [`MetricGoalConfig`](crate::types::MetricGoalConfig).
    pub fn build(self) -> crate::types::MetricGoalConfig {
        crate::types::MetricGoalConfig {
            metric_definition: self.metric_definition,
            desired_change: self.desired_change,
        }
    }
}
