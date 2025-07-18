// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Shutdown event configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ShutdownEventConfiguration {
    /// <p>The time, in seconds, that OpsWorks Stacks waits after triggering a Shutdown event before shutting down an instance.</p>
    pub execution_timeout: ::std::option::Option<i32>,
    /// <p>Whether to enable Elastic Load Balancing connection draining. For more information, see <a href="https://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/TerminologyandKeyConcepts.html#conn-drain">Connection Draining</a></p>
    pub delay_until_elb_connections_drained: ::std::option::Option<bool>,
}
impl ShutdownEventConfiguration {
    /// <p>The time, in seconds, that OpsWorks Stacks waits after triggering a Shutdown event before shutting down an instance.</p>
    pub fn execution_timeout(&self) -> ::std::option::Option<i32> {
        self.execution_timeout
    }
    /// <p>Whether to enable Elastic Load Balancing connection draining. For more information, see <a href="https://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/TerminologyandKeyConcepts.html#conn-drain">Connection Draining</a></p>
    pub fn delay_until_elb_connections_drained(&self) -> ::std::option::Option<bool> {
        self.delay_until_elb_connections_drained
    }
}
impl ShutdownEventConfiguration {
    /// Creates a new builder-style object to manufacture [`ShutdownEventConfiguration`](crate::types::ShutdownEventConfiguration).
    pub fn builder() -> crate::types::builders::ShutdownEventConfigurationBuilder {
        crate::types::builders::ShutdownEventConfigurationBuilder::default()
    }
}

/// A builder for [`ShutdownEventConfiguration`](crate::types::ShutdownEventConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ShutdownEventConfigurationBuilder {
    pub(crate) execution_timeout: ::std::option::Option<i32>,
    pub(crate) delay_until_elb_connections_drained: ::std::option::Option<bool>,
}
impl ShutdownEventConfigurationBuilder {
    /// <p>The time, in seconds, that OpsWorks Stacks waits after triggering a Shutdown event before shutting down an instance.</p>
    pub fn execution_timeout(mut self, input: i32) -> Self {
        self.execution_timeout = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in seconds, that OpsWorks Stacks waits after triggering a Shutdown event before shutting down an instance.</p>
    pub fn set_execution_timeout(mut self, input: ::std::option::Option<i32>) -> Self {
        self.execution_timeout = input;
        self
    }
    /// <p>The time, in seconds, that OpsWorks Stacks waits after triggering a Shutdown event before shutting down an instance.</p>
    pub fn get_execution_timeout(&self) -> &::std::option::Option<i32> {
        &self.execution_timeout
    }
    /// <p>Whether to enable Elastic Load Balancing connection draining. For more information, see <a href="https://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/TerminologyandKeyConcepts.html#conn-drain">Connection Draining</a></p>
    pub fn delay_until_elb_connections_drained(mut self, input: bool) -> Self {
        self.delay_until_elb_connections_drained = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to enable Elastic Load Balancing connection draining. For more information, see <a href="https://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/TerminologyandKeyConcepts.html#conn-drain">Connection Draining</a></p>
    pub fn set_delay_until_elb_connections_drained(mut self, input: ::std::option::Option<bool>) -> Self {
        self.delay_until_elb_connections_drained = input;
        self
    }
    /// <p>Whether to enable Elastic Load Balancing connection draining. For more information, see <a href="https://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/TerminologyandKeyConcepts.html#conn-drain">Connection Draining</a></p>
    pub fn get_delay_until_elb_connections_drained(&self) -> &::std::option::Option<bool> {
        &self.delay_until_elb_connections_drained
    }
    /// Consumes the builder and constructs a [`ShutdownEventConfiguration`](crate::types::ShutdownEventConfiguration).
    pub fn build(self) -> crate::types::ShutdownEventConfiguration {
        crate::types::ShutdownEventConfiguration {
            execution_timeout: self.execution_timeout,
            delay_until_elb_connections_drained: self.delay_until_elb_connections_drained,
        }
    }
}
