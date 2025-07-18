// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes whether monitoring is enabled for a Scheduled Instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScheduledInstancesMonitoring {
    /// <p>Indicates whether monitoring is enabled.</p>
    pub enabled: ::std::option::Option<bool>,
}
impl ScheduledInstancesMonitoring {
    /// <p>Indicates whether monitoring is enabled.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
}
impl ScheduledInstancesMonitoring {
    /// Creates a new builder-style object to manufacture [`ScheduledInstancesMonitoring`](crate::types::ScheduledInstancesMonitoring).
    pub fn builder() -> crate::types::builders::ScheduledInstancesMonitoringBuilder {
        crate::types::builders::ScheduledInstancesMonitoringBuilder::default()
    }
}

/// A builder for [`ScheduledInstancesMonitoring`](crate::types::ScheduledInstancesMonitoring).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScheduledInstancesMonitoringBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
}
impl ScheduledInstancesMonitoringBuilder {
    /// <p>Indicates whether monitoring is enabled.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether monitoring is enabled.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Indicates whether monitoring is enabled.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Consumes the builder and constructs a [`ScheduledInstancesMonitoring`](crate::types::ScheduledInstancesMonitoring).
    pub fn build(self) -> crate::types::ScheduledInstancesMonitoring {
        crate::types::ScheduledInstancesMonitoring { enabled: self.enabled }
    }
}
