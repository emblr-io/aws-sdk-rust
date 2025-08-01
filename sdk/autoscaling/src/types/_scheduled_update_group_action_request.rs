// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes information used for one or more scheduled scaling action updates in a <a href="https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_BatchPutScheduledUpdateGroupAction.html">BatchPutScheduledUpdateGroupAction</a> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScheduledUpdateGroupActionRequest {
    /// <p>The name of the scaling action.</p>
    pub scheduled_action_name: ::std::option::Option<::std::string::String>,
    /// <p>The date and time for the action to start, in YYYY-MM-DDThh:mm:ssZ format in UTC/GMT only and in quotes (for example, <code>"2019-06-01T00:00:00Z"</code>).</p>
    /// <p>If you specify <code>Recurrence</code> and <code>StartTime</code>, Amazon EC2 Auto Scaling performs the action at this time, and then performs the action based on the specified recurrence.</p>
    /// <p>If you try to schedule the action in the past, Amazon EC2 Auto Scaling returns an error message.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time for the recurring schedule to end, in UTC.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The recurring schedule for the action, in Unix cron syntax format. This format consists of five fields separated by white spaces: \[Minute\] \[Hour\] \[Day_of_Month\] \[Month_of_Year\] \[Day_of_Week\]. The value must be in quotes (for example, "30 0 1 1,6,12 *"). For more information about this format, see Crontab.</p>
    /// <p>When <code>StartTime</code> and <code>EndTime</code> are specified with <code>Recurrence</code>, they form the boundaries of when the recurring action starts and stops.</p>
    /// <p>Cron expressions use Universal Coordinated Time (UTC) by default.</p>
    pub recurrence: ::std::option::Option<::std::string::String>,
    /// <p>The minimum size of the Auto Scaling group.</p>
    pub min_size: ::std::option::Option<i32>,
    /// <p>The maximum size of the Auto Scaling group.</p>
    pub max_size: ::std::option::Option<i32>,
    /// <p>The desired capacity is the initial capacity of the Auto Scaling group after the scheduled action runs and the capacity it attempts to maintain.</p>
    pub desired_capacity: ::std::option::Option<i32>,
    /// <p>Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default.</p>
    /// <p>Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as <code>Etc/GMT+9</code> or <code>Pacific/Tahiti</code>). For more information, see <a href="https://en.wikipedia.org/wiki/List_of_tz_database_time_zones">https://en.wikipedia.org/wiki/List_of_tz_database_time_zones</a>.</p>
    pub time_zone: ::std::option::Option<::std::string::String>,
}
impl ScheduledUpdateGroupActionRequest {
    /// <p>The name of the scaling action.</p>
    pub fn scheduled_action_name(&self) -> ::std::option::Option<&str> {
        self.scheduled_action_name.as_deref()
    }
    /// <p>The date and time for the action to start, in YYYY-MM-DDThh:mm:ssZ format in UTC/GMT only and in quotes (for example, <code>"2019-06-01T00:00:00Z"</code>).</p>
    /// <p>If you specify <code>Recurrence</code> and <code>StartTime</code>, Amazon EC2 Auto Scaling performs the action at this time, and then performs the action based on the specified recurrence.</p>
    /// <p>If you try to schedule the action in the past, Amazon EC2 Auto Scaling returns an error message.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The date and time for the recurring schedule to end, in UTC.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The recurring schedule for the action, in Unix cron syntax format. This format consists of five fields separated by white spaces: \[Minute\] \[Hour\] \[Day_of_Month\] \[Month_of_Year\] \[Day_of_Week\]. The value must be in quotes (for example, "30 0 1 1,6,12 *"). For more information about this format, see Crontab.</p>
    /// <p>When <code>StartTime</code> and <code>EndTime</code> are specified with <code>Recurrence</code>, they form the boundaries of when the recurring action starts and stops.</p>
    /// <p>Cron expressions use Universal Coordinated Time (UTC) by default.</p>
    pub fn recurrence(&self) -> ::std::option::Option<&str> {
        self.recurrence.as_deref()
    }
    /// <p>The minimum size of the Auto Scaling group.</p>
    pub fn min_size(&self) -> ::std::option::Option<i32> {
        self.min_size
    }
    /// <p>The maximum size of the Auto Scaling group.</p>
    pub fn max_size(&self) -> ::std::option::Option<i32> {
        self.max_size
    }
    /// <p>The desired capacity is the initial capacity of the Auto Scaling group after the scheduled action runs and the capacity it attempts to maintain.</p>
    pub fn desired_capacity(&self) -> ::std::option::Option<i32> {
        self.desired_capacity
    }
    /// <p>Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default.</p>
    /// <p>Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as <code>Etc/GMT+9</code> or <code>Pacific/Tahiti</code>). For more information, see <a href="https://en.wikipedia.org/wiki/List_of_tz_database_time_zones">https://en.wikipedia.org/wiki/List_of_tz_database_time_zones</a>.</p>
    pub fn time_zone(&self) -> ::std::option::Option<&str> {
        self.time_zone.as_deref()
    }
}
impl ScheduledUpdateGroupActionRequest {
    /// Creates a new builder-style object to manufacture [`ScheduledUpdateGroupActionRequest`](crate::types::ScheduledUpdateGroupActionRequest).
    pub fn builder() -> crate::types::builders::ScheduledUpdateGroupActionRequestBuilder {
        crate::types::builders::ScheduledUpdateGroupActionRequestBuilder::default()
    }
}

/// A builder for [`ScheduledUpdateGroupActionRequest`](crate::types::ScheduledUpdateGroupActionRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScheduledUpdateGroupActionRequestBuilder {
    pub(crate) scheduled_action_name: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) recurrence: ::std::option::Option<::std::string::String>,
    pub(crate) min_size: ::std::option::Option<i32>,
    pub(crate) max_size: ::std::option::Option<i32>,
    pub(crate) desired_capacity: ::std::option::Option<i32>,
    pub(crate) time_zone: ::std::option::Option<::std::string::String>,
}
impl ScheduledUpdateGroupActionRequestBuilder {
    /// <p>The name of the scaling action.</p>
    /// This field is required.
    pub fn scheduled_action_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scheduled_action_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the scaling action.</p>
    pub fn set_scheduled_action_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scheduled_action_name = input;
        self
    }
    /// <p>The name of the scaling action.</p>
    pub fn get_scheduled_action_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.scheduled_action_name
    }
    /// <p>The date and time for the action to start, in YYYY-MM-DDThh:mm:ssZ format in UTC/GMT only and in quotes (for example, <code>"2019-06-01T00:00:00Z"</code>).</p>
    /// <p>If you specify <code>Recurrence</code> and <code>StartTime</code>, Amazon EC2 Auto Scaling performs the action at this time, and then performs the action based on the specified recurrence.</p>
    /// <p>If you try to schedule the action in the past, Amazon EC2 Auto Scaling returns an error message.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time for the action to start, in YYYY-MM-DDThh:mm:ssZ format in UTC/GMT only and in quotes (for example, <code>"2019-06-01T00:00:00Z"</code>).</p>
    /// <p>If you specify <code>Recurrence</code> and <code>StartTime</code>, Amazon EC2 Auto Scaling performs the action at this time, and then performs the action based on the specified recurrence.</p>
    /// <p>If you try to schedule the action in the past, Amazon EC2 Auto Scaling returns an error message.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The date and time for the action to start, in YYYY-MM-DDThh:mm:ssZ format in UTC/GMT only and in quotes (for example, <code>"2019-06-01T00:00:00Z"</code>).</p>
    /// <p>If you specify <code>Recurrence</code> and <code>StartTime</code>, Amazon EC2 Auto Scaling performs the action at this time, and then performs the action based on the specified recurrence.</p>
    /// <p>If you try to schedule the action in the past, Amazon EC2 Auto Scaling returns an error message.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The date and time for the recurring schedule to end, in UTC.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time for the recurring schedule to end, in UTC.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The date and time for the recurring schedule to end, in UTC.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>The recurring schedule for the action, in Unix cron syntax format. This format consists of five fields separated by white spaces: \[Minute\] \[Hour\] \[Day_of_Month\] \[Month_of_Year\] \[Day_of_Week\]. The value must be in quotes (for example, "30 0 1 1,6,12 *"). For more information about this format, see Crontab.</p>
    /// <p>When <code>StartTime</code> and <code>EndTime</code> are specified with <code>Recurrence</code>, they form the boundaries of when the recurring action starts and stops.</p>
    /// <p>Cron expressions use Universal Coordinated Time (UTC) by default.</p>
    pub fn recurrence(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recurrence = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The recurring schedule for the action, in Unix cron syntax format. This format consists of five fields separated by white spaces: \[Minute\] \[Hour\] \[Day_of_Month\] \[Month_of_Year\] \[Day_of_Week\]. The value must be in quotes (for example, "30 0 1 1,6,12 *"). For more information about this format, see Crontab.</p>
    /// <p>When <code>StartTime</code> and <code>EndTime</code> are specified with <code>Recurrence</code>, they form the boundaries of when the recurring action starts and stops.</p>
    /// <p>Cron expressions use Universal Coordinated Time (UTC) by default.</p>
    pub fn set_recurrence(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recurrence = input;
        self
    }
    /// <p>The recurring schedule for the action, in Unix cron syntax format. This format consists of five fields separated by white spaces: \[Minute\] \[Hour\] \[Day_of_Month\] \[Month_of_Year\] \[Day_of_Week\]. The value must be in quotes (for example, "30 0 1 1,6,12 *"). For more information about this format, see Crontab.</p>
    /// <p>When <code>StartTime</code> and <code>EndTime</code> are specified with <code>Recurrence</code>, they form the boundaries of when the recurring action starts and stops.</p>
    /// <p>Cron expressions use Universal Coordinated Time (UTC) by default.</p>
    pub fn get_recurrence(&self) -> &::std::option::Option<::std::string::String> {
        &self.recurrence
    }
    /// <p>The minimum size of the Auto Scaling group.</p>
    pub fn min_size(mut self, input: i32) -> Self {
        self.min_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum size of the Auto Scaling group.</p>
    pub fn set_min_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_size = input;
        self
    }
    /// <p>The minimum size of the Auto Scaling group.</p>
    pub fn get_min_size(&self) -> &::std::option::Option<i32> {
        &self.min_size
    }
    /// <p>The maximum size of the Auto Scaling group.</p>
    pub fn max_size(mut self, input: i32) -> Self {
        self.max_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum size of the Auto Scaling group.</p>
    pub fn set_max_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_size = input;
        self
    }
    /// <p>The maximum size of the Auto Scaling group.</p>
    pub fn get_max_size(&self) -> &::std::option::Option<i32> {
        &self.max_size
    }
    /// <p>The desired capacity is the initial capacity of the Auto Scaling group after the scheduled action runs and the capacity it attempts to maintain.</p>
    pub fn desired_capacity(mut self, input: i32) -> Self {
        self.desired_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The desired capacity is the initial capacity of the Auto Scaling group after the scheduled action runs and the capacity it attempts to maintain.</p>
    pub fn set_desired_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.desired_capacity = input;
        self
    }
    /// <p>The desired capacity is the initial capacity of the Auto Scaling group after the scheduled action runs and the capacity it attempts to maintain.</p>
    pub fn get_desired_capacity(&self) -> &::std::option::Option<i32> {
        &self.desired_capacity
    }
    /// <p>Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default.</p>
    /// <p>Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as <code>Etc/GMT+9</code> or <code>Pacific/Tahiti</code>). For more information, see <a href="https://en.wikipedia.org/wiki/List_of_tz_database_time_zones">https://en.wikipedia.org/wiki/List_of_tz_database_time_zones</a>.</p>
    pub fn time_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.time_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default.</p>
    /// <p>Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as <code>Etc/GMT+9</code> or <code>Pacific/Tahiti</code>). For more information, see <a href="https://en.wikipedia.org/wiki/List_of_tz_database_time_zones">https://en.wikipedia.org/wiki/List_of_tz_database_time_zones</a>.</p>
    pub fn set_time_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.time_zone = input;
        self
    }
    /// <p>Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default.</p>
    /// <p>Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as <code>Etc/GMT+9</code> or <code>Pacific/Tahiti</code>). For more information, see <a href="https://en.wikipedia.org/wiki/List_of_tz_database_time_zones">https://en.wikipedia.org/wiki/List_of_tz_database_time_zones</a>.</p>
    pub fn get_time_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.time_zone
    }
    /// Consumes the builder and constructs a [`ScheduledUpdateGroupActionRequest`](crate::types::ScheduledUpdateGroupActionRequest).
    pub fn build(self) -> crate::types::ScheduledUpdateGroupActionRequest {
        crate::types::ScheduledUpdateGroupActionRequest {
            scheduled_action_name: self.scheduled_action_name,
            start_time: self.start_time,
            end_time: self.end_time,
            recurrence: self.recurrence,
            min_size: self.min_size,
            max_size: self.max_size,
            desired_capacity: self.desired_capacity,
            time_zone: self.time_zone,
        }
    }
}
