// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartMonitoringScheduleInput {
    /// <p>The name of the schedule to start.</p>
    pub monitoring_schedule_name: ::std::option::Option<::std::string::String>,
}
impl StartMonitoringScheduleInput {
    /// <p>The name of the schedule to start.</p>
    pub fn monitoring_schedule_name(&self) -> ::std::option::Option<&str> {
        self.monitoring_schedule_name.as_deref()
    }
}
impl StartMonitoringScheduleInput {
    /// Creates a new builder-style object to manufacture [`StartMonitoringScheduleInput`](crate::operation::start_monitoring_schedule::StartMonitoringScheduleInput).
    pub fn builder() -> crate::operation::start_monitoring_schedule::builders::StartMonitoringScheduleInputBuilder {
        crate::operation::start_monitoring_schedule::builders::StartMonitoringScheduleInputBuilder::default()
    }
}

/// A builder for [`StartMonitoringScheduleInput`](crate::operation::start_monitoring_schedule::StartMonitoringScheduleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartMonitoringScheduleInputBuilder {
    pub(crate) monitoring_schedule_name: ::std::option::Option<::std::string::String>,
}
impl StartMonitoringScheduleInputBuilder {
    /// <p>The name of the schedule to start.</p>
    /// This field is required.
    pub fn monitoring_schedule_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.monitoring_schedule_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the schedule to start.</p>
    pub fn set_monitoring_schedule_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.monitoring_schedule_name = input;
        self
    }
    /// <p>The name of the schedule to start.</p>
    pub fn get_monitoring_schedule_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.monitoring_schedule_name
    }
    /// Consumes the builder and constructs a [`StartMonitoringScheduleInput`](crate::operation::start_monitoring_schedule::StartMonitoringScheduleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_monitoring_schedule::StartMonitoringScheduleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_monitoring_schedule::StartMonitoringScheduleInput {
            monitoring_schedule_name: self.monitoring_schedule_name,
        })
    }
}
