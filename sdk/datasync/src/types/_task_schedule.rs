// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configures your DataSync task to run on a <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">schedule</a> (at a minimum interval of 1 hour).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaskSchedule {
    /// <p>Specifies your task schedule by using a cron or rate expression.</p>
    /// <p>Use cron expressions for task schedules that run on a specific time and day. For example, the following cron expression creates a task schedule that runs at 8 AM on the first Wednesday of every month:</p>
    /// <p><code>cron(0 8 * * 3#1)</code></p>
    /// <p>Use rate expressions for task schedules that run on a regular interval. For example, the following rate expression creates a task schedule that runs every 12 hours:</p>
    /// <p><code>rate(12 hours)</code></p>
    /// <p>For information about cron and rate expression syntax, see the <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html"> <i>Amazon EventBridge User Guide</i> </a>.</p>
    pub schedule_expression: ::std::string::String,
    /// <p>Specifies whether to enable or disable your task schedule. Your schedule is enabled by default, but there can be situations where you need to disable it. For example, you might need to pause a recurring transfer to fix an issue with your task or perform maintenance on your storage system.</p>
    /// <p>DataSync might disable your schedule automatically if your task fails repeatedly with the same error. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/API_TaskScheduleDetails.html">TaskScheduleDetails</a>.</p>
    pub status: ::std::option::Option<crate::types::ScheduleStatus>,
}
impl TaskSchedule {
    /// <p>Specifies your task schedule by using a cron or rate expression.</p>
    /// <p>Use cron expressions for task schedules that run on a specific time and day. For example, the following cron expression creates a task schedule that runs at 8 AM on the first Wednesday of every month:</p>
    /// <p><code>cron(0 8 * * 3#1)</code></p>
    /// <p>Use rate expressions for task schedules that run on a regular interval. For example, the following rate expression creates a task schedule that runs every 12 hours:</p>
    /// <p><code>rate(12 hours)</code></p>
    /// <p>For information about cron and rate expression syntax, see the <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html"> <i>Amazon EventBridge User Guide</i> </a>.</p>
    pub fn schedule_expression(&self) -> &str {
        use std::ops::Deref;
        self.schedule_expression.deref()
    }
    /// <p>Specifies whether to enable or disable your task schedule. Your schedule is enabled by default, but there can be situations where you need to disable it. For example, you might need to pause a recurring transfer to fix an issue with your task or perform maintenance on your storage system.</p>
    /// <p>DataSync might disable your schedule automatically if your task fails repeatedly with the same error. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/API_TaskScheduleDetails.html">TaskScheduleDetails</a>.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ScheduleStatus> {
        self.status.as_ref()
    }
}
impl TaskSchedule {
    /// Creates a new builder-style object to manufacture [`TaskSchedule`](crate::types::TaskSchedule).
    pub fn builder() -> crate::types::builders::TaskScheduleBuilder {
        crate::types::builders::TaskScheduleBuilder::default()
    }
}

/// A builder for [`TaskSchedule`](crate::types::TaskSchedule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaskScheduleBuilder {
    pub(crate) schedule_expression: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ScheduleStatus>,
}
impl TaskScheduleBuilder {
    /// <p>Specifies your task schedule by using a cron or rate expression.</p>
    /// <p>Use cron expressions for task schedules that run on a specific time and day. For example, the following cron expression creates a task schedule that runs at 8 AM on the first Wednesday of every month:</p>
    /// <p><code>cron(0 8 * * 3#1)</code></p>
    /// <p>Use rate expressions for task schedules that run on a regular interval. For example, the following rate expression creates a task schedule that runs every 12 hours:</p>
    /// <p><code>rate(12 hours)</code></p>
    /// <p>For information about cron and rate expression syntax, see the <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html"> <i>Amazon EventBridge User Guide</i> </a>.</p>
    /// This field is required.
    pub fn schedule_expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schedule_expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies your task schedule by using a cron or rate expression.</p>
    /// <p>Use cron expressions for task schedules that run on a specific time and day. For example, the following cron expression creates a task schedule that runs at 8 AM on the first Wednesday of every month:</p>
    /// <p><code>cron(0 8 * * 3#1)</code></p>
    /// <p>Use rate expressions for task schedules that run on a regular interval. For example, the following rate expression creates a task schedule that runs every 12 hours:</p>
    /// <p><code>rate(12 hours)</code></p>
    /// <p>For information about cron and rate expression syntax, see the <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html"> <i>Amazon EventBridge User Guide</i> </a>.</p>
    pub fn set_schedule_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schedule_expression = input;
        self
    }
    /// <p>Specifies your task schedule by using a cron or rate expression.</p>
    /// <p>Use cron expressions for task schedules that run on a specific time and day. For example, the following cron expression creates a task schedule that runs at 8 AM on the first Wednesday of every month:</p>
    /// <p><code>cron(0 8 * * 3#1)</code></p>
    /// <p>Use rate expressions for task schedules that run on a regular interval. For example, the following rate expression creates a task schedule that runs every 12 hours:</p>
    /// <p><code>rate(12 hours)</code></p>
    /// <p>For information about cron and rate expression syntax, see the <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html"> <i>Amazon EventBridge User Guide</i> </a>.</p>
    pub fn get_schedule_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.schedule_expression
    }
    /// <p>Specifies whether to enable or disable your task schedule. Your schedule is enabled by default, but there can be situations where you need to disable it. For example, you might need to pause a recurring transfer to fix an issue with your task or perform maintenance on your storage system.</p>
    /// <p>DataSync might disable your schedule automatically if your task fails repeatedly with the same error. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/API_TaskScheduleDetails.html">TaskScheduleDetails</a>.</p>
    pub fn status(mut self, input: crate::types::ScheduleStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to enable or disable your task schedule. Your schedule is enabled by default, but there can be situations where you need to disable it. For example, you might need to pause a recurring transfer to fix an issue with your task or perform maintenance on your storage system.</p>
    /// <p>DataSync might disable your schedule automatically if your task fails repeatedly with the same error. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/API_TaskScheduleDetails.html">TaskScheduleDetails</a>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ScheduleStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Specifies whether to enable or disable your task schedule. Your schedule is enabled by default, but there can be situations where you need to disable it. For example, you might need to pause a recurring transfer to fix an issue with your task or perform maintenance on your storage system.</p>
    /// <p>DataSync might disable your schedule automatically if your task fails repeatedly with the same error. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/API_TaskScheduleDetails.html">TaskScheduleDetails</a>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ScheduleStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`TaskSchedule`](crate::types::TaskSchedule).
    /// This method will fail if any of the following fields are not set:
    /// - [`schedule_expression`](crate::types::builders::TaskScheduleBuilder::schedule_expression)
    pub fn build(self) -> ::std::result::Result<crate::types::TaskSchedule, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TaskSchedule {
            schedule_expression: self.schedule_expression.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "schedule_expression",
                    "schedule_expression was not specified but it is required when building TaskSchedule",
                )
            })?,
            status: self.status,
        })
    }
}
