// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the timeout configuration for a job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IoTJobTimeoutConfig {
    /// <p>The amount of time, in minutes, that devices have to complete the job. The timer starts when the job status is set to <code>IN_PROGRESS</code>. If the job status doesn't change to a terminal state before the time expires, then the job status is set to <code>TIMED_OUT</code>.</p>
    /// <p>The timeout interval must be between 1 minute and 7 days (10080 minutes).</p>
    pub in_progress_timeout_in_minutes: ::std::option::Option<i64>,
}
impl IoTJobTimeoutConfig {
    /// <p>The amount of time, in minutes, that devices have to complete the job. The timer starts when the job status is set to <code>IN_PROGRESS</code>. If the job status doesn't change to a terminal state before the time expires, then the job status is set to <code>TIMED_OUT</code>.</p>
    /// <p>The timeout interval must be between 1 minute and 7 days (10080 minutes).</p>
    pub fn in_progress_timeout_in_minutes(&self) -> ::std::option::Option<i64> {
        self.in_progress_timeout_in_minutes
    }
}
impl IoTJobTimeoutConfig {
    /// Creates a new builder-style object to manufacture [`IoTJobTimeoutConfig`](crate::types::IoTJobTimeoutConfig).
    pub fn builder() -> crate::types::builders::IoTJobTimeoutConfigBuilder {
        crate::types::builders::IoTJobTimeoutConfigBuilder::default()
    }
}

/// A builder for [`IoTJobTimeoutConfig`](crate::types::IoTJobTimeoutConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IoTJobTimeoutConfigBuilder {
    pub(crate) in_progress_timeout_in_minutes: ::std::option::Option<i64>,
}
impl IoTJobTimeoutConfigBuilder {
    /// <p>The amount of time, in minutes, that devices have to complete the job. The timer starts when the job status is set to <code>IN_PROGRESS</code>. If the job status doesn't change to a terminal state before the time expires, then the job status is set to <code>TIMED_OUT</code>.</p>
    /// <p>The timeout interval must be between 1 minute and 7 days (10080 minutes).</p>
    pub fn in_progress_timeout_in_minutes(mut self, input: i64) -> Self {
        self.in_progress_timeout_in_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time, in minutes, that devices have to complete the job. The timer starts when the job status is set to <code>IN_PROGRESS</code>. If the job status doesn't change to a terminal state before the time expires, then the job status is set to <code>TIMED_OUT</code>.</p>
    /// <p>The timeout interval must be between 1 minute and 7 days (10080 minutes).</p>
    pub fn set_in_progress_timeout_in_minutes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.in_progress_timeout_in_minutes = input;
        self
    }
    /// <p>The amount of time, in minutes, that devices have to complete the job. The timer starts when the job status is set to <code>IN_PROGRESS</code>. If the job status doesn't change to a terminal state before the time expires, then the job status is set to <code>TIMED_OUT</code>.</p>
    /// <p>The timeout interval must be between 1 minute and 7 days (10080 minutes).</p>
    pub fn get_in_progress_timeout_in_minutes(&self) -> &::std::option::Option<i64> {
        &self.in_progress_timeout_in_minutes
    }
    /// Consumes the builder and constructs a [`IoTJobTimeoutConfig`](crate::types::IoTJobTimeoutConfig).
    pub fn build(self) -> crate::types::IoTJobTimeoutConfig {
        crate::types::IoTJobTimeoutConfig {
            in_progress_timeout_in_minutes: self.in_progress_timeout_in_minutes,
        }
    }
}
