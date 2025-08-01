// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Allows you to create a staged rollout of a job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JobExecutionsRolloutConfig {
    /// <p>The maximum number of things that will be notified of a pending job, per minute. This parameter allows you to create a staged rollout.</p>
    pub maximum_per_minute: ::std::option::Option<i32>,
    /// <p>The rate of increase for a job rollout. This parameter allows you to define an exponential rate for a job rollout.</p>
    pub exponential_rate: ::std::option::Option<crate::types::ExponentialRolloutRate>,
}
impl JobExecutionsRolloutConfig {
    /// <p>The maximum number of things that will be notified of a pending job, per minute. This parameter allows you to create a staged rollout.</p>
    pub fn maximum_per_minute(&self) -> ::std::option::Option<i32> {
        self.maximum_per_minute
    }
    /// <p>The rate of increase for a job rollout. This parameter allows you to define an exponential rate for a job rollout.</p>
    pub fn exponential_rate(&self) -> ::std::option::Option<&crate::types::ExponentialRolloutRate> {
        self.exponential_rate.as_ref()
    }
}
impl JobExecutionsRolloutConfig {
    /// Creates a new builder-style object to manufacture [`JobExecutionsRolloutConfig`](crate::types::JobExecutionsRolloutConfig).
    pub fn builder() -> crate::types::builders::JobExecutionsRolloutConfigBuilder {
        crate::types::builders::JobExecutionsRolloutConfigBuilder::default()
    }
}

/// A builder for [`JobExecutionsRolloutConfig`](crate::types::JobExecutionsRolloutConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JobExecutionsRolloutConfigBuilder {
    pub(crate) maximum_per_minute: ::std::option::Option<i32>,
    pub(crate) exponential_rate: ::std::option::Option<crate::types::ExponentialRolloutRate>,
}
impl JobExecutionsRolloutConfigBuilder {
    /// <p>The maximum number of things that will be notified of a pending job, per minute. This parameter allows you to create a staged rollout.</p>
    pub fn maximum_per_minute(mut self, input: i32) -> Self {
        self.maximum_per_minute = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of things that will be notified of a pending job, per minute. This parameter allows you to create a staged rollout.</p>
    pub fn set_maximum_per_minute(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_per_minute = input;
        self
    }
    /// <p>The maximum number of things that will be notified of a pending job, per minute. This parameter allows you to create a staged rollout.</p>
    pub fn get_maximum_per_minute(&self) -> &::std::option::Option<i32> {
        &self.maximum_per_minute
    }
    /// <p>The rate of increase for a job rollout. This parameter allows you to define an exponential rate for a job rollout.</p>
    pub fn exponential_rate(mut self, input: crate::types::ExponentialRolloutRate) -> Self {
        self.exponential_rate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The rate of increase for a job rollout. This parameter allows you to define an exponential rate for a job rollout.</p>
    pub fn set_exponential_rate(mut self, input: ::std::option::Option<crate::types::ExponentialRolloutRate>) -> Self {
        self.exponential_rate = input;
        self
    }
    /// <p>The rate of increase for a job rollout. This parameter allows you to define an exponential rate for a job rollout.</p>
    pub fn get_exponential_rate(&self) -> &::std::option::Option<crate::types::ExponentialRolloutRate> {
        &self.exponential_rate
    }
    /// Consumes the builder and constructs a [`JobExecutionsRolloutConfig`](crate::types::JobExecutionsRolloutConfig).
    pub fn build(self) -> crate::types::JobExecutionsRolloutConfig {
        crate::types::JobExecutionsRolloutConfig {
            maximum_per_minute: self.maximum_per_minute,
            exponential_rate: self.exponential_rate,
        }
    }
}
