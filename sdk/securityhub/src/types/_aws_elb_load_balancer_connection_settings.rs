// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains connection settings for the load balancer.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsElbLoadBalancerConnectionSettings {
    /// <p>The time, in seconds, that the connection can be idle (no data is sent over the connection) before it is closed by the load balancer.</p>
    pub idle_timeout: ::std::option::Option<i32>,
}
impl AwsElbLoadBalancerConnectionSettings {
    /// <p>The time, in seconds, that the connection can be idle (no data is sent over the connection) before it is closed by the load balancer.</p>
    pub fn idle_timeout(&self) -> ::std::option::Option<i32> {
        self.idle_timeout
    }
}
impl AwsElbLoadBalancerConnectionSettings {
    /// Creates a new builder-style object to manufacture [`AwsElbLoadBalancerConnectionSettings`](crate::types::AwsElbLoadBalancerConnectionSettings).
    pub fn builder() -> crate::types::builders::AwsElbLoadBalancerConnectionSettingsBuilder {
        crate::types::builders::AwsElbLoadBalancerConnectionSettingsBuilder::default()
    }
}

/// A builder for [`AwsElbLoadBalancerConnectionSettings`](crate::types::AwsElbLoadBalancerConnectionSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsElbLoadBalancerConnectionSettingsBuilder {
    pub(crate) idle_timeout: ::std::option::Option<i32>,
}
impl AwsElbLoadBalancerConnectionSettingsBuilder {
    /// <p>The time, in seconds, that the connection can be idle (no data is sent over the connection) before it is closed by the load balancer.</p>
    pub fn idle_timeout(mut self, input: i32) -> Self {
        self.idle_timeout = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in seconds, that the connection can be idle (no data is sent over the connection) before it is closed by the load balancer.</p>
    pub fn set_idle_timeout(mut self, input: ::std::option::Option<i32>) -> Self {
        self.idle_timeout = input;
        self
    }
    /// <p>The time, in seconds, that the connection can be idle (no data is sent over the connection) before it is closed by the load balancer.</p>
    pub fn get_idle_timeout(&self) -> &::std::option::Option<i32> {
        &self.idle_timeout
    }
    /// Consumes the builder and constructs a [`AwsElbLoadBalancerConnectionSettings`](crate::types::AwsElbLoadBalancerConnectionSettings).
    pub fn build(self) -> crate::types::AwsElbLoadBalancerConnectionSettings {
        crate::types::AwsElbLoadBalancerConnectionSettings {
            idle_timeout: self.idle_timeout,
        }
    }
}
