// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configures the timeout and maximum number of retries for processing a transform job invocation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModelClientConfig {
    /// <p>The timeout value in seconds for an invocation request. The default value is 600.</p>
    pub invocations_timeout_in_seconds: ::std::option::Option<i32>,
    /// <p>The maximum number of retries when invocation requests are failing. The default value is 3.</p>
    pub invocations_max_retries: ::std::option::Option<i32>,
}
impl ModelClientConfig {
    /// <p>The timeout value in seconds for an invocation request. The default value is 600.</p>
    pub fn invocations_timeout_in_seconds(&self) -> ::std::option::Option<i32> {
        self.invocations_timeout_in_seconds
    }
    /// <p>The maximum number of retries when invocation requests are failing. The default value is 3.</p>
    pub fn invocations_max_retries(&self) -> ::std::option::Option<i32> {
        self.invocations_max_retries
    }
}
impl ModelClientConfig {
    /// Creates a new builder-style object to manufacture [`ModelClientConfig`](crate::types::ModelClientConfig).
    pub fn builder() -> crate::types::builders::ModelClientConfigBuilder {
        crate::types::builders::ModelClientConfigBuilder::default()
    }
}

/// A builder for [`ModelClientConfig`](crate::types::ModelClientConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModelClientConfigBuilder {
    pub(crate) invocations_timeout_in_seconds: ::std::option::Option<i32>,
    pub(crate) invocations_max_retries: ::std::option::Option<i32>,
}
impl ModelClientConfigBuilder {
    /// <p>The timeout value in seconds for an invocation request. The default value is 600.</p>
    pub fn invocations_timeout_in_seconds(mut self, input: i32) -> Self {
        self.invocations_timeout_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timeout value in seconds for an invocation request. The default value is 600.</p>
    pub fn set_invocations_timeout_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.invocations_timeout_in_seconds = input;
        self
    }
    /// <p>The timeout value in seconds for an invocation request. The default value is 600.</p>
    pub fn get_invocations_timeout_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.invocations_timeout_in_seconds
    }
    /// <p>The maximum number of retries when invocation requests are failing. The default value is 3.</p>
    pub fn invocations_max_retries(mut self, input: i32) -> Self {
        self.invocations_max_retries = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of retries when invocation requests are failing. The default value is 3.</p>
    pub fn set_invocations_max_retries(mut self, input: ::std::option::Option<i32>) -> Self {
        self.invocations_max_retries = input;
        self
    }
    /// <p>The maximum number of retries when invocation requests are failing. The default value is 3.</p>
    pub fn get_invocations_max_retries(&self) -> &::std::option::Option<i32> {
        &self.invocations_max_retries
    }
    /// Consumes the builder and constructs a [`ModelClientConfig`](crate::types::ModelClientConfig).
    pub fn build(self) -> crate::types::ModelClientConfig {
        crate::types::ModelClientConfig {
            invocations_timeout_in_seconds: self.invocations_timeout_in_seconds,
            invocations_max_retries: self.invocations_max_retries,
        }
    }
}
