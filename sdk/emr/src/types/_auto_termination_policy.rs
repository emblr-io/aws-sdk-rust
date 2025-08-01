// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An auto-termination policy for an Amazon EMR cluster. An auto-termination policy defines the amount of idle time in seconds after which a cluster automatically terminates. For alternative cluster termination options, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-termination.html">Control cluster termination</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoTerminationPolicy {
    /// <p>Specifies the amount of idle time in seconds after which the cluster automatically terminates. You can specify a minimum of 60 seconds and a maximum of 604800 seconds (seven days).</p>
    pub idle_timeout: ::std::option::Option<i64>,
}
impl AutoTerminationPolicy {
    /// <p>Specifies the amount of idle time in seconds after which the cluster automatically terminates. You can specify a minimum of 60 seconds and a maximum of 604800 seconds (seven days).</p>
    pub fn idle_timeout(&self) -> ::std::option::Option<i64> {
        self.idle_timeout
    }
}
impl AutoTerminationPolicy {
    /// Creates a new builder-style object to manufacture [`AutoTerminationPolicy`](crate::types::AutoTerminationPolicy).
    pub fn builder() -> crate::types::builders::AutoTerminationPolicyBuilder {
        crate::types::builders::AutoTerminationPolicyBuilder::default()
    }
}

/// A builder for [`AutoTerminationPolicy`](crate::types::AutoTerminationPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoTerminationPolicyBuilder {
    pub(crate) idle_timeout: ::std::option::Option<i64>,
}
impl AutoTerminationPolicyBuilder {
    /// <p>Specifies the amount of idle time in seconds after which the cluster automatically terminates. You can specify a minimum of 60 seconds and a maximum of 604800 seconds (seven days).</p>
    pub fn idle_timeout(mut self, input: i64) -> Self {
        self.idle_timeout = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the amount of idle time in seconds after which the cluster automatically terminates. You can specify a minimum of 60 seconds and a maximum of 604800 seconds (seven days).</p>
    pub fn set_idle_timeout(mut self, input: ::std::option::Option<i64>) -> Self {
        self.idle_timeout = input;
        self
    }
    /// <p>Specifies the amount of idle time in seconds after which the cluster automatically terminates. You can specify a minimum of 60 seconds and a maximum of 604800 seconds (seven days).</p>
    pub fn get_idle_timeout(&self) -> &::std::option::Option<i64> {
        &self.idle_timeout
    }
    /// Consumes the builder and constructs a [`AutoTerminationPolicy`](crate::types::AutoTerminationPolicy).
    pub fn build(self) -> crate::types::AutoTerminationPolicy {
        crate::types::AutoTerminationPolicy {
            idle_timeout: self.idle_timeout,
        }
    }
}
