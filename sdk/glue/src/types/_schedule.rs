// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A scheduling object using a <code>cron</code> statement to schedule an event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Schedule {
    /// <p>A <code>cron</code> expression used to specify the schedule (see <a href="https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html">Time-Based Schedules for Jobs and Crawlers</a>. For example, to run something every day at 12:15 UTC, you would specify: <code>cron(15 12 * * ? *)</code>.</p>
    pub schedule_expression: ::std::option::Option<::std::string::String>,
    /// <p>The state of the schedule.</p>
    pub state: ::std::option::Option<crate::types::ScheduleState>,
}
impl Schedule {
    /// <p>A <code>cron</code> expression used to specify the schedule (see <a href="https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html">Time-Based Schedules for Jobs and Crawlers</a>. For example, to run something every day at 12:15 UTC, you would specify: <code>cron(15 12 * * ? *)</code>.</p>
    pub fn schedule_expression(&self) -> ::std::option::Option<&str> {
        self.schedule_expression.as_deref()
    }
    /// <p>The state of the schedule.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::ScheduleState> {
        self.state.as_ref()
    }
}
impl Schedule {
    /// Creates a new builder-style object to manufacture [`Schedule`](crate::types::Schedule).
    pub fn builder() -> crate::types::builders::ScheduleBuilder {
        crate::types::builders::ScheduleBuilder::default()
    }
}

/// A builder for [`Schedule`](crate::types::Schedule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScheduleBuilder {
    pub(crate) schedule_expression: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::ScheduleState>,
}
impl ScheduleBuilder {
    /// <p>A <code>cron</code> expression used to specify the schedule (see <a href="https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html">Time-Based Schedules for Jobs and Crawlers</a>. For example, to run something every day at 12:15 UTC, you would specify: <code>cron(15 12 * * ? *)</code>.</p>
    pub fn schedule_expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schedule_expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A <code>cron</code> expression used to specify the schedule (see <a href="https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html">Time-Based Schedules for Jobs and Crawlers</a>. For example, to run something every day at 12:15 UTC, you would specify: <code>cron(15 12 * * ? *)</code>.</p>
    pub fn set_schedule_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schedule_expression = input;
        self
    }
    /// <p>A <code>cron</code> expression used to specify the schedule (see <a href="https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html">Time-Based Schedules for Jobs and Crawlers</a>. For example, to run something every day at 12:15 UTC, you would specify: <code>cron(15 12 * * ? *)</code>.</p>
    pub fn get_schedule_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.schedule_expression
    }
    /// <p>The state of the schedule.</p>
    pub fn state(mut self, input: crate::types::ScheduleState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the schedule.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::ScheduleState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the schedule.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::ScheduleState> {
        &self.state
    }
    /// Consumes the builder and constructs a [`Schedule`](crate::types::Schedule).
    pub fn build(self) -> crate::types::Schedule {
        crate::types::Schedule {
            schedule_expression: self.schedule_expression,
            state: self.state,
        }
    }
}
