// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A <code>RetryPolicy</code> object that includes information about the retry policy settings, including the maximum age of an event, and the maximum number of times EventBridge Scheduler will try to deliver the event to a target.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RetryPolicy {
    /// <p>The maximum amount of time, in seconds, to continue to make retry attempts.</p>
    pub maximum_event_age_in_seconds: ::std::option::Option<i32>,
    /// <p>The maximum number of retry attempts to make before the request fails. Retry attempts with exponential backoff continue until either the maximum number of attempts is made or until the duration of the <code>MaximumEventAgeInSeconds</code> is reached.</p>
    pub maximum_retry_attempts: ::std::option::Option<i32>,
}
impl RetryPolicy {
    /// <p>The maximum amount of time, in seconds, to continue to make retry attempts.</p>
    pub fn maximum_event_age_in_seconds(&self) -> ::std::option::Option<i32> {
        self.maximum_event_age_in_seconds
    }
    /// <p>The maximum number of retry attempts to make before the request fails. Retry attempts with exponential backoff continue until either the maximum number of attempts is made or until the duration of the <code>MaximumEventAgeInSeconds</code> is reached.</p>
    pub fn maximum_retry_attempts(&self) -> ::std::option::Option<i32> {
        self.maximum_retry_attempts
    }
}
impl RetryPolicy {
    /// Creates a new builder-style object to manufacture [`RetryPolicy`](crate::types::RetryPolicy).
    pub fn builder() -> crate::types::builders::RetryPolicyBuilder {
        crate::types::builders::RetryPolicyBuilder::default()
    }
}

/// A builder for [`RetryPolicy`](crate::types::RetryPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RetryPolicyBuilder {
    pub(crate) maximum_event_age_in_seconds: ::std::option::Option<i32>,
    pub(crate) maximum_retry_attempts: ::std::option::Option<i32>,
}
impl RetryPolicyBuilder {
    /// <p>The maximum amount of time, in seconds, to continue to make retry attempts.</p>
    pub fn maximum_event_age_in_seconds(mut self, input: i32) -> Self {
        self.maximum_event_age_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of time, in seconds, to continue to make retry attempts.</p>
    pub fn set_maximum_event_age_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_event_age_in_seconds = input;
        self
    }
    /// <p>The maximum amount of time, in seconds, to continue to make retry attempts.</p>
    pub fn get_maximum_event_age_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.maximum_event_age_in_seconds
    }
    /// <p>The maximum number of retry attempts to make before the request fails. Retry attempts with exponential backoff continue until either the maximum number of attempts is made or until the duration of the <code>MaximumEventAgeInSeconds</code> is reached.</p>
    pub fn maximum_retry_attempts(mut self, input: i32) -> Self {
        self.maximum_retry_attempts = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of retry attempts to make before the request fails. Retry attempts with exponential backoff continue until either the maximum number of attempts is made or until the duration of the <code>MaximumEventAgeInSeconds</code> is reached.</p>
    pub fn set_maximum_retry_attempts(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_retry_attempts = input;
        self
    }
    /// <p>The maximum number of retry attempts to make before the request fails. Retry attempts with exponential backoff continue until either the maximum number of attempts is made or until the duration of the <code>MaximumEventAgeInSeconds</code> is reached.</p>
    pub fn get_maximum_retry_attempts(&self) -> &::std::option::Option<i32> {
        &self.maximum_retry_attempts
    }
    /// Consumes the builder and constructs a [`RetryPolicy`](crate::types::RetryPolicy).
    pub fn build(self) -> crate::types::RetryPolicy {
        crate::types::RetryPolicy {
            maximum_event_age_in_seconds: self.maximum_event_age_in_seconds,
            maximum_retry_attempts: self.maximum_retry_attempts,
        }
    }
}
