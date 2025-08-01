// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The <a href="https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html#invocation-eventsourcemapping-provisioned-mode"> provisioned mode</a> configuration for the event source. Use Provisioned Mode to customize the minimum and maximum number of event pollers for your event source. An event poller is a compute unit that provides approximately 5 MBps of throughput.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProvisionedPollerConfig {
    /// <p>The minimum number of event pollers this event source can scale down to.</p>
    pub minimum_pollers: ::std::option::Option<i32>,
    /// <p>The maximum number of event pollers this event source can scale up to.</p>
    pub maximum_pollers: ::std::option::Option<i32>,
}
impl ProvisionedPollerConfig {
    /// <p>The minimum number of event pollers this event source can scale down to.</p>
    pub fn minimum_pollers(&self) -> ::std::option::Option<i32> {
        self.minimum_pollers
    }
    /// <p>The maximum number of event pollers this event source can scale up to.</p>
    pub fn maximum_pollers(&self) -> ::std::option::Option<i32> {
        self.maximum_pollers
    }
}
impl ProvisionedPollerConfig {
    /// Creates a new builder-style object to manufacture [`ProvisionedPollerConfig`](crate::types::ProvisionedPollerConfig).
    pub fn builder() -> crate::types::builders::ProvisionedPollerConfigBuilder {
        crate::types::builders::ProvisionedPollerConfigBuilder::default()
    }
}

/// A builder for [`ProvisionedPollerConfig`](crate::types::ProvisionedPollerConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProvisionedPollerConfigBuilder {
    pub(crate) minimum_pollers: ::std::option::Option<i32>,
    pub(crate) maximum_pollers: ::std::option::Option<i32>,
}
impl ProvisionedPollerConfigBuilder {
    /// <p>The minimum number of event pollers this event source can scale down to.</p>
    pub fn minimum_pollers(mut self, input: i32) -> Self {
        self.minimum_pollers = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum number of event pollers this event source can scale down to.</p>
    pub fn set_minimum_pollers(mut self, input: ::std::option::Option<i32>) -> Self {
        self.minimum_pollers = input;
        self
    }
    /// <p>The minimum number of event pollers this event source can scale down to.</p>
    pub fn get_minimum_pollers(&self) -> &::std::option::Option<i32> {
        &self.minimum_pollers
    }
    /// <p>The maximum number of event pollers this event source can scale up to.</p>
    pub fn maximum_pollers(mut self, input: i32) -> Self {
        self.maximum_pollers = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of event pollers this event source can scale up to.</p>
    pub fn set_maximum_pollers(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_pollers = input;
        self
    }
    /// <p>The maximum number of event pollers this event source can scale up to.</p>
    pub fn get_maximum_pollers(&self) -> &::std::option::Option<i32> {
        &self.maximum_pollers
    }
    /// Consumes the builder and constructs a [`ProvisionedPollerConfig`](crate::types::ProvisionedPollerConfig).
    pub fn build(self) -> crate::types::ProvisionedPollerConfig {
        crate::types::ProvisionedPollerConfig {
            minimum_pollers: self.minimum_pollers,
            maximum_pollers: self.maximum_pollers,
        }
    }
}
