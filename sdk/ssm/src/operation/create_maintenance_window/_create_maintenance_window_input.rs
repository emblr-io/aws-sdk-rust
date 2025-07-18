// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateMaintenanceWindowInput {
    /// <p>The name of the maintenance window.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>An optional description for the maintenance window. We recommend specifying a description to help you organize your maintenance windows.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The date and time, in ISO-8601 Extended format, for when you want the maintenance window to become active. <code>StartDate</code> allows you to delay activation of the maintenance window until the specified future date.</p><note>
    /// <p>When using a rate schedule, if you provide a start date that occurs in the past, the current date and time are used as the start date.</p>
    /// </note>
    pub start_date: ::std::option::Option<::std::string::String>,
    /// <p>The date and time, in ISO-8601 Extended format, for when you want the maintenance window to become inactive. <code>EndDate</code> allows you to set a date and time in the future when the maintenance window will no longer run.</p>
    pub end_date: ::std::option::Option<::std::string::String>,
    /// <p>The schedule of the maintenance window in the form of a cron or rate expression.</p>
    pub schedule: ::std::option::Option<::std::string::String>,
    /// <p>The time zone that the scheduled maintenance window executions are based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul". For more information, see the <a href="https://www.iana.org/time-zones">Time Zone Database</a> on the IANA website.</p>
    pub schedule_timezone: ::std::option::Option<::std::string::String>,
    /// <p>The number of days to wait after the date and time specified by a cron expression before running the maintenance window.</p>
    /// <p>For example, the following cron expression schedules a maintenance window to run on the third Tuesday of every month at 11:30 PM.</p>
    /// <p><code>cron(30 23 ? * TUE#3 *)</code></p>
    /// <p>If the schedule offset is <code>2</code>, the maintenance window won't run until two days later.</p>
    pub schedule_offset: ::std::option::Option<i32>,
    /// <p>The duration of the maintenance window in hours.</p>
    pub duration: ::std::option::Option<i32>,
    /// <p>The number of hours before the end of the maintenance window that Amazon Web Services Systems Manager stops scheduling new tasks for execution.</p>
    pub cutoff: ::std::option::Option<i32>,
    /// <p>Enables a maintenance window task to run on managed nodes, even if you haven't registered those nodes as targets. If enabled, then you must specify the unregistered managed nodes (by node ID) when you register a task with the maintenance window.</p>
    /// <p>If you don't enable this option, then you must specify previously-registered targets when you register a task with the maintenance window.</p>
    pub allow_unassociated_targets: ::std::option::Option<bool>,
    /// <p>User-provided idempotency token.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Optional metadata that you assign to a resource. Tags enable you to categorize a resource in different ways, such as by purpose, owner, or environment. For example, you might want to tag a maintenance window to identify the type of tasks it will run, the types of targets, and the environment it will run in. In this case, you could specify the following key-value pairs:</p>
    /// <ul>
    /// <li>
    /// <p><code>Key=TaskType,Value=AgentUpdate</code></p></li>
    /// <li>
    /// <p><code>Key=OS,Value=Windows</code></p></li>
    /// <li>
    /// <p><code>Key=Environment,Value=Production</code></p></li>
    /// </ul><note>
    /// <p>To add tags to an existing maintenance window, use the <code>AddTagsToResource</code> operation.</p>
    /// </note>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateMaintenanceWindowInput {
    /// <p>The name of the maintenance window.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>An optional description for the maintenance window. We recommend specifying a description to help you organize your maintenance windows.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The date and time, in ISO-8601 Extended format, for when you want the maintenance window to become active. <code>StartDate</code> allows you to delay activation of the maintenance window until the specified future date.</p><note>
    /// <p>When using a rate schedule, if you provide a start date that occurs in the past, the current date and time are used as the start date.</p>
    /// </note>
    pub fn start_date(&self) -> ::std::option::Option<&str> {
        self.start_date.as_deref()
    }
    /// <p>The date and time, in ISO-8601 Extended format, for when you want the maintenance window to become inactive. <code>EndDate</code> allows you to set a date and time in the future when the maintenance window will no longer run.</p>
    pub fn end_date(&self) -> ::std::option::Option<&str> {
        self.end_date.as_deref()
    }
    /// <p>The schedule of the maintenance window in the form of a cron or rate expression.</p>
    pub fn schedule(&self) -> ::std::option::Option<&str> {
        self.schedule.as_deref()
    }
    /// <p>The time zone that the scheduled maintenance window executions are based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul". For more information, see the <a href="https://www.iana.org/time-zones">Time Zone Database</a> on the IANA website.</p>
    pub fn schedule_timezone(&self) -> ::std::option::Option<&str> {
        self.schedule_timezone.as_deref()
    }
    /// <p>The number of days to wait after the date and time specified by a cron expression before running the maintenance window.</p>
    /// <p>For example, the following cron expression schedules a maintenance window to run on the third Tuesday of every month at 11:30 PM.</p>
    /// <p><code>cron(30 23 ? * TUE#3 *)</code></p>
    /// <p>If the schedule offset is <code>2</code>, the maintenance window won't run until two days later.</p>
    pub fn schedule_offset(&self) -> ::std::option::Option<i32> {
        self.schedule_offset
    }
    /// <p>The duration of the maintenance window in hours.</p>
    pub fn duration(&self) -> ::std::option::Option<i32> {
        self.duration
    }
    /// <p>The number of hours before the end of the maintenance window that Amazon Web Services Systems Manager stops scheduling new tasks for execution.</p>
    pub fn cutoff(&self) -> ::std::option::Option<i32> {
        self.cutoff
    }
    /// <p>Enables a maintenance window task to run on managed nodes, even if you haven't registered those nodes as targets. If enabled, then you must specify the unregistered managed nodes (by node ID) when you register a task with the maintenance window.</p>
    /// <p>If you don't enable this option, then you must specify previously-registered targets when you register a task with the maintenance window.</p>
    pub fn allow_unassociated_targets(&self) -> ::std::option::Option<bool> {
        self.allow_unassociated_targets
    }
    /// <p>User-provided idempotency token.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Optional metadata that you assign to a resource. Tags enable you to categorize a resource in different ways, such as by purpose, owner, or environment. For example, you might want to tag a maintenance window to identify the type of tasks it will run, the types of targets, and the environment it will run in. In this case, you could specify the following key-value pairs:</p>
    /// <ul>
    /// <li>
    /// <p><code>Key=TaskType,Value=AgentUpdate</code></p></li>
    /// <li>
    /// <p><code>Key=OS,Value=Windows</code></p></li>
    /// <li>
    /// <p><code>Key=Environment,Value=Production</code></p></li>
    /// </ul><note>
    /// <p>To add tags to an existing maintenance window, use the <code>AddTagsToResource</code> operation.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for CreateMaintenanceWindowInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateMaintenanceWindowInput");
        formatter.field("name", &self.name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("start_date", &self.start_date);
        formatter.field("end_date", &self.end_date);
        formatter.field("schedule", &self.schedule);
        formatter.field("schedule_timezone", &self.schedule_timezone);
        formatter.field("schedule_offset", &self.schedule_offset);
        formatter.field("duration", &self.duration);
        formatter.field("cutoff", &self.cutoff);
        formatter.field("allow_unassociated_targets", &self.allow_unassociated_targets);
        formatter.field("client_token", &self.client_token);
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
impl CreateMaintenanceWindowInput {
    /// Creates a new builder-style object to manufacture [`CreateMaintenanceWindowInput`](crate::operation::create_maintenance_window::CreateMaintenanceWindowInput).
    pub fn builder() -> crate::operation::create_maintenance_window::builders::CreateMaintenanceWindowInputBuilder {
        crate::operation::create_maintenance_window::builders::CreateMaintenanceWindowInputBuilder::default()
    }
}

/// A builder for [`CreateMaintenanceWindowInput`](crate::operation::create_maintenance_window::CreateMaintenanceWindowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateMaintenanceWindowInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) start_date: ::std::option::Option<::std::string::String>,
    pub(crate) end_date: ::std::option::Option<::std::string::String>,
    pub(crate) schedule: ::std::option::Option<::std::string::String>,
    pub(crate) schedule_timezone: ::std::option::Option<::std::string::String>,
    pub(crate) schedule_offset: ::std::option::Option<i32>,
    pub(crate) duration: ::std::option::Option<i32>,
    pub(crate) cutoff: ::std::option::Option<i32>,
    pub(crate) allow_unassociated_targets: ::std::option::Option<bool>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateMaintenanceWindowInputBuilder {
    /// <p>The name of the maintenance window.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the maintenance window.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the maintenance window.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>An optional description for the maintenance window. We recommend specifying a description to help you organize your maintenance windows.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional description for the maintenance window. We recommend specifying a description to help you organize your maintenance windows.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>An optional description for the maintenance window. We recommend specifying a description to help you organize your maintenance windows.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The date and time, in ISO-8601 Extended format, for when you want the maintenance window to become active. <code>StartDate</code> allows you to delay activation of the maintenance window until the specified future date.</p><note>
    /// <p>When using a rate schedule, if you provide a start date that occurs in the past, the current date and time are used as the start date.</p>
    /// </note>
    pub fn start_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time, in ISO-8601 Extended format, for when you want the maintenance window to become active. <code>StartDate</code> allows you to delay activation of the maintenance window until the specified future date.</p><note>
    /// <p>When using a rate schedule, if you provide a start date that occurs in the past, the current date and time are used as the start date.</p>
    /// </note>
    pub fn set_start_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_date = input;
        self
    }
    /// <p>The date and time, in ISO-8601 Extended format, for when you want the maintenance window to become active. <code>StartDate</code> allows you to delay activation of the maintenance window until the specified future date.</p><note>
    /// <p>When using a rate schedule, if you provide a start date that occurs in the past, the current date and time are used as the start date.</p>
    /// </note>
    pub fn get_start_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_date
    }
    /// <p>The date and time, in ISO-8601 Extended format, for when you want the maintenance window to become inactive. <code>EndDate</code> allows you to set a date and time in the future when the maintenance window will no longer run.</p>
    pub fn end_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.end_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time, in ISO-8601 Extended format, for when you want the maintenance window to become inactive. <code>EndDate</code> allows you to set a date and time in the future when the maintenance window will no longer run.</p>
    pub fn set_end_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.end_date = input;
        self
    }
    /// <p>The date and time, in ISO-8601 Extended format, for when you want the maintenance window to become inactive. <code>EndDate</code> allows you to set a date and time in the future when the maintenance window will no longer run.</p>
    pub fn get_end_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.end_date
    }
    /// <p>The schedule of the maintenance window in the form of a cron or rate expression.</p>
    /// This field is required.
    pub fn schedule(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schedule = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The schedule of the maintenance window in the form of a cron or rate expression.</p>
    pub fn set_schedule(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schedule = input;
        self
    }
    /// <p>The schedule of the maintenance window in the form of a cron or rate expression.</p>
    pub fn get_schedule(&self) -> &::std::option::Option<::std::string::String> {
        &self.schedule
    }
    /// <p>The time zone that the scheduled maintenance window executions are based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul". For more information, see the <a href="https://www.iana.org/time-zones">Time Zone Database</a> on the IANA website.</p>
    pub fn schedule_timezone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schedule_timezone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time zone that the scheduled maintenance window executions are based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul". For more information, see the <a href="https://www.iana.org/time-zones">Time Zone Database</a> on the IANA website.</p>
    pub fn set_schedule_timezone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schedule_timezone = input;
        self
    }
    /// <p>The time zone that the scheduled maintenance window executions are based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul". For more information, see the <a href="https://www.iana.org/time-zones">Time Zone Database</a> on the IANA website.</p>
    pub fn get_schedule_timezone(&self) -> &::std::option::Option<::std::string::String> {
        &self.schedule_timezone
    }
    /// <p>The number of days to wait after the date and time specified by a cron expression before running the maintenance window.</p>
    /// <p>For example, the following cron expression schedules a maintenance window to run on the third Tuesday of every month at 11:30 PM.</p>
    /// <p><code>cron(30 23 ? * TUE#3 *)</code></p>
    /// <p>If the schedule offset is <code>2</code>, the maintenance window won't run until two days later.</p>
    pub fn schedule_offset(mut self, input: i32) -> Self {
        self.schedule_offset = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of days to wait after the date and time specified by a cron expression before running the maintenance window.</p>
    /// <p>For example, the following cron expression schedules a maintenance window to run on the third Tuesday of every month at 11:30 PM.</p>
    /// <p><code>cron(30 23 ? * TUE#3 *)</code></p>
    /// <p>If the schedule offset is <code>2</code>, the maintenance window won't run until two days later.</p>
    pub fn set_schedule_offset(mut self, input: ::std::option::Option<i32>) -> Self {
        self.schedule_offset = input;
        self
    }
    /// <p>The number of days to wait after the date and time specified by a cron expression before running the maintenance window.</p>
    /// <p>For example, the following cron expression schedules a maintenance window to run on the third Tuesday of every month at 11:30 PM.</p>
    /// <p><code>cron(30 23 ? * TUE#3 *)</code></p>
    /// <p>If the schedule offset is <code>2</code>, the maintenance window won't run until two days later.</p>
    pub fn get_schedule_offset(&self) -> &::std::option::Option<i32> {
        &self.schedule_offset
    }
    /// <p>The duration of the maintenance window in hours.</p>
    /// This field is required.
    pub fn duration(mut self, input: i32) -> Self {
        self.duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration of the maintenance window in hours.</p>
    pub fn set_duration(mut self, input: ::std::option::Option<i32>) -> Self {
        self.duration = input;
        self
    }
    /// <p>The duration of the maintenance window in hours.</p>
    pub fn get_duration(&self) -> &::std::option::Option<i32> {
        &self.duration
    }
    /// <p>The number of hours before the end of the maintenance window that Amazon Web Services Systems Manager stops scheduling new tasks for execution.</p>
    /// This field is required.
    pub fn cutoff(mut self, input: i32) -> Self {
        self.cutoff = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of hours before the end of the maintenance window that Amazon Web Services Systems Manager stops scheduling new tasks for execution.</p>
    pub fn set_cutoff(mut self, input: ::std::option::Option<i32>) -> Self {
        self.cutoff = input;
        self
    }
    /// <p>The number of hours before the end of the maintenance window that Amazon Web Services Systems Manager stops scheduling new tasks for execution.</p>
    pub fn get_cutoff(&self) -> &::std::option::Option<i32> {
        &self.cutoff
    }
    /// <p>Enables a maintenance window task to run on managed nodes, even if you haven't registered those nodes as targets. If enabled, then you must specify the unregistered managed nodes (by node ID) when you register a task with the maintenance window.</p>
    /// <p>If you don't enable this option, then you must specify previously-registered targets when you register a task with the maintenance window.</p>
    /// This field is required.
    pub fn allow_unassociated_targets(mut self, input: bool) -> Self {
        self.allow_unassociated_targets = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables a maintenance window task to run on managed nodes, even if you haven't registered those nodes as targets. If enabled, then you must specify the unregistered managed nodes (by node ID) when you register a task with the maintenance window.</p>
    /// <p>If you don't enable this option, then you must specify previously-registered targets when you register a task with the maintenance window.</p>
    pub fn set_allow_unassociated_targets(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_unassociated_targets = input;
        self
    }
    /// <p>Enables a maintenance window task to run on managed nodes, even if you haven't registered those nodes as targets. If enabled, then you must specify the unregistered managed nodes (by node ID) when you register a task with the maintenance window.</p>
    /// <p>If you don't enable this option, then you must specify previously-registered targets when you register a task with the maintenance window.</p>
    pub fn get_allow_unassociated_targets(&self) -> &::std::option::Option<bool> {
        &self.allow_unassociated_targets
    }
    /// <p>User-provided idempotency token.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>User-provided idempotency token.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>User-provided idempotency token.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Optional metadata that you assign to a resource. Tags enable you to categorize a resource in different ways, such as by purpose, owner, or environment. For example, you might want to tag a maintenance window to identify the type of tasks it will run, the types of targets, and the environment it will run in. In this case, you could specify the following key-value pairs:</p>
    /// <ul>
    /// <li>
    /// <p><code>Key=TaskType,Value=AgentUpdate</code></p></li>
    /// <li>
    /// <p><code>Key=OS,Value=Windows</code></p></li>
    /// <li>
    /// <p><code>Key=Environment,Value=Production</code></p></li>
    /// </ul><note>
    /// <p>To add tags to an existing maintenance window, use the <code>AddTagsToResource</code> operation.</p>
    /// </note>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Optional metadata that you assign to a resource. Tags enable you to categorize a resource in different ways, such as by purpose, owner, or environment. For example, you might want to tag a maintenance window to identify the type of tasks it will run, the types of targets, and the environment it will run in. In this case, you could specify the following key-value pairs:</p>
    /// <ul>
    /// <li>
    /// <p><code>Key=TaskType,Value=AgentUpdate</code></p></li>
    /// <li>
    /// <p><code>Key=OS,Value=Windows</code></p></li>
    /// <li>
    /// <p><code>Key=Environment,Value=Production</code></p></li>
    /// </ul><note>
    /// <p>To add tags to an existing maintenance window, use the <code>AddTagsToResource</code> operation.</p>
    /// </note>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Optional metadata that you assign to a resource. Tags enable you to categorize a resource in different ways, such as by purpose, owner, or environment. For example, you might want to tag a maintenance window to identify the type of tasks it will run, the types of targets, and the environment it will run in. In this case, you could specify the following key-value pairs:</p>
    /// <ul>
    /// <li>
    /// <p><code>Key=TaskType,Value=AgentUpdate</code></p></li>
    /// <li>
    /// <p><code>Key=OS,Value=Windows</code></p></li>
    /// <li>
    /// <p><code>Key=Environment,Value=Production</code></p></li>
    /// </ul><note>
    /// <p>To add tags to an existing maintenance window, use the <code>AddTagsToResource</code> operation.</p>
    /// </note>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateMaintenanceWindowInput`](crate::operation::create_maintenance_window::CreateMaintenanceWindowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_maintenance_window::CreateMaintenanceWindowInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_maintenance_window::CreateMaintenanceWindowInput {
            name: self.name,
            description: self.description,
            start_date: self.start_date,
            end_date: self.end_date,
            schedule: self.schedule,
            schedule_timezone: self.schedule_timezone,
            schedule_offset: self.schedule_offset,
            duration: self.duration,
            cutoff: self.cutoff,
            allow_unassociated_targets: self.allow_unassociated_targets,
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
impl ::std::fmt::Debug for CreateMaintenanceWindowInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateMaintenanceWindowInputBuilder");
        formatter.field("name", &self.name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("start_date", &self.start_date);
        formatter.field("end_date", &self.end_date);
        formatter.field("schedule", &self.schedule);
        formatter.field("schedule_timezone", &self.schedule_timezone);
        formatter.field("schedule_offset", &self.schedule_offset);
        formatter.field("duration", &self.duration);
        formatter.field("cutoff", &self.cutoff);
        formatter.field("allow_unassociated_targets", &self.allow_unassociated_targets);
        formatter.field("client_token", &self.client_token);
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
