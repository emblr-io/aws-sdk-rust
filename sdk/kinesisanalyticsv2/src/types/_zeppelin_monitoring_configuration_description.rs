// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The monitoring configuration for Apache Zeppelin within a Managed Service for Apache Flink Studio notebook.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ZeppelinMonitoringConfigurationDescription {
    /// <p>Describes the verbosity of the CloudWatch Logs for an application.</p>
    pub log_level: ::std::option::Option<crate::types::LogLevel>,
}
impl ZeppelinMonitoringConfigurationDescription {
    /// <p>Describes the verbosity of the CloudWatch Logs for an application.</p>
    pub fn log_level(&self) -> ::std::option::Option<&crate::types::LogLevel> {
        self.log_level.as_ref()
    }
}
impl ZeppelinMonitoringConfigurationDescription {
    /// Creates a new builder-style object to manufacture [`ZeppelinMonitoringConfigurationDescription`](crate::types::ZeppelinMonitoringConfigurationDescription).
    pub fn builder() -> crate::types::builders::ZeppelinMonitoringConfigurationDescriptionBuilder {
        crate::types::builders::ZeppelinMonitoringConfigurationDescriptionBuilder::default()
    }
}

/// A builder for [`ZeppelinMonitoringConfigurationDescription`](crate::types::ZeppelinMonitoringConfigurationDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ZeppelinMonitoringConfigurationDescriptionBuilder {
    pub(crate) log_level: ::std::option::Option<crate::types::LogLevel>,
}
impl ZeppelinMonitoringConfigurationDescriptionBuilder {
    /// <p>Describes the verbosity of the CloudWatch Logs for an application.</p>
    pub fn log_level(mut self, input: crate::types::LogLevel) -> Self {
        self.log_level = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the verbosity of the CloudWatch Logs for an application.</p>
    pub fn set_log_level(mut self, input: ::std::option::Option<crate::types::LogLevel>) -> Self {
        self.log_level = input;
        self
    }
    /// <p>Describes the verbosity of the CloudWatch Logs for an application.</p>
    pub fn get_log_level(&self) -> &::std::option::Option<crate::types::LogLevel> {
        &self.log_level
    }
    /// Consumes the builder and constructs a [`ZeppelinMonitoringConfigurationDescription`](crate::types::ZeppelinMonitoringConfigurationDescription).
    pub fn build(self) -> crate::types::ZeppelinMonitoringConfigurationDescription {
        crate::types::ZeppelinMonitoringConfigurationDescription { log_level: self.log_level }
    }
}
