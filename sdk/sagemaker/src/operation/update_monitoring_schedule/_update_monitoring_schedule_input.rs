// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateMonitoringScheduleInput {
    /// <p>The name of the monitoring schedule. The name must be unique within an Amazon Web Services Region within an Amazon Web Services account.</p>
    pub monitoring_schedule_name: ::std::option::Option<::std::string::String>,
    /// <p>The configuration object that specifies the monitoring schedule and defines the monitoring job.</p>
    pub monitoring_schedule_config: ::std::option::Option<crate::types::MonitoringScheduleConfig>,
}
impl UpdateMonitoringScheduleInput {
    /// <p>The name of the monitoring schedule. The name must be unique within an Amazon Web Services Region within an Amazon Web Services account.</p>
    pub fn monitoring_schedule_name(&self) -> ::std::option::Option<&str> {
        self.monitoring_schedule_name.as_deref()
    }
    /// <p>The configuration object that specifies the monitoring schedule and defines the monitoring job.</p>
    pub fn monitoring_schedule_config(&self) -> ::std::option::Option<&crate::types::MonitoringScheduleConfig> {
        self.monitoring_schedule_config.as_ref()
    }
}
impl UpdateMonitoringScheduleInput {
    /// Creates a new builder-style object to manufacture [`UpdateMonitoringScheduleInput`](crate::operation::update_monitoring_schedule::UpdateMonitoringScheduleInput).
    pub fn builder() -> crate::operation::update_monitoring_schedule::builders::UpdateMonitoringScheduleInputBuilder {
        crate::operation::update_monitoring_schedule::builders::UpdateMonitoringScheduleInputBuilder::default()
    }
}

/// A builder for [`UpdateMonitoringScheduleInput`](crate::operation::update_monitoring_schedule::UpdateMonitoringScheduleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateMonitoringScheduleInputBuilder {
    pub(crate) monitoring_schedule_name: ::std::option::Option<::std::string::String>,
    pub(crate) monitoring_schedule_config: ::std::option::Option<crate::types::MonitoringScheduleConfig>,
}
impl UpdateMonitoringScheduleInputBuilder {
    /// <p>The name of the monitoring schedule. The name must be unique within an Amazon Web Services Region within an Amazon Web Services account.</p>
    /// This field is required.
    pub fn monitoring_schedule_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.monitoring_schedule_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the monitoring schedule. The name must be unique within an Amazon Web Services Region within an Amazon Web Services account.</p>
    pub fn set_monitoring_schedule_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.monitoring_schedule_name = input;
        self
    }
    /// <p>The name of the monitoring schedule. The name must be unique within an Amazon Web Services Region within an Amazon Web Services account.</p>
    pub fn get_monitoring_schedule_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.monitoring_schedule_name
    }
    /// <p>The configuration object that specifies the monitoring schedule and defines the monitoring job.</p>
    /// This field is required.
    pub fn monitoring_schedule_config(mut self, input: crate::types::MonitoringScheduleConfig) -> Self {
        self.monitoring_schedule_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration object that specifies the monitoring schedule and defines the monitoring job.</p>
    pub fn set_monitoring_schedule_config(mut self, input: ::std::option::Option<crate::types::MonitoringScheduleConfig>) -> Self {
        self.monitoring_schedule_config = input;
        self
    }
    /// <p>The configuration object that specifies the monitoring schedule and defines the monitoring job.</p>
    pub fn get_monitoring_schedule_config(&self) -> &::std::option::Option<crate::types::MonitoringScheduleConfig> {
        &self.monitoring_schedule_config
    }
    /// Consumes the builder and constructs a [`UpdateMonitoringScheduleInput`](crate::operation::update_monitoring_schedule::UpdateMonitoringScheduleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_monitoring_schedule::UpdateMonitoringScheduleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_monitoring_schedule::UpdateMonitoringScheduleInput {
            monitoring_schedule_name: self.monitoring_schedule_name,
            monitoring_schedule_config: self.monitoring_schedule_config,
        })
    }
}
