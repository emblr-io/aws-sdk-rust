// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A practice run configuration for a resource includes the Amazon CloudWatch alarms that you've specified for a practice run, as well as any blocked dates or blocked windows for the practice run. When a resource has a practice run configuration, ARC shifts traffic for the resource weekly for practice runs.</p>
/// <p>Practice runs are required for zonal autoshift. The zonal shifts that ARC starts for practice runs help you to ensure that shifting away traffic from an Availability Zone during an autoshift is safe for your application.</p>
/// <p>You can update or delete a practice run configuration. Before you delete a practice run configuration, you must disable zonal autoshift for the resource. A practice run configuration is required when zonal autoshift is enabled.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PracticeRunConfiguration {
    /// <p>The <i>blocking alarm</i> for practice runs is an optional alarm that you can specify that blocks practice runs when the alarm is in an <code>ALARM</code> state.</p>
    pub blocking_alarms: ::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>>,
    /// <p>The <i>outcome alarm</i> for practice runs is an alarm that you specify that ends a practice run when the alarm is in an <code>ALARM</code> state.</p>
    pub outcome_alarms: ::std::vec::Vec<crate::types::ControlCondition>,
    /// <p>An array of one or more windows of days and times that you can block ARC from starting practice runs for a resource.</p>
    /// <p>Specify the blocked windows in UTC, using the format <code>DAY:HH:MM-DAY:HH:MM</code>, separated by spaces. For example, <code>MON:18:30-MON:19:30 TUE:18:30-TUE:19:30</code>.</p>
    pub blocked_windows: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An array of one or more dates that you can specify when Amazon Web Services does not start practice runs for a resource.</p>
    /// <p>Specify blocked dates, in UTC, in the format <code>YYYY-MM-DD</code>, separated by spaces.</p>
    pub blocked_dates: ::std::vec::Vec<::std::string::String>,
}
impl PracticeRunConfiguration {
    /// <p>The <i>blocking alarm</i> for practice runs is an optional alarm that you can specify that blocks practice runs when the alarm is in an <code>ALARM</code> state.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.blocking_alarms.is_none()`.
    pub fn blocking_alarms(&self) -> &[crate::types::ControlCondition] {
        self.blocking_alarms.as_deref().unwrap_or_default()
    }
    /// <p>The <i>outcome alarm</i> for practice runs is an alarm that you specify that ends a practice run when the alarm is in an <code>ALARM</code> state.</p>
    pub fn outcome_alarms(&self) -> &[crate::types::ControlCondition] {
        use std::ops::Deref;
        self.outcome_alarms.deref()
    }
    /// <p>An array of one or more windows of days and times that you can block ARC from starting practice runs for a resource.</p>
    /// <p>Specify the blocked windows in UTC, using the format <code>DAY:HH:MM-DAY:HH:MM</code>, separated by spaces. For example, <code>MON:18:30-MON:19:30 TUE:18:30-TUE:19:30</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.blocked_windows.is_none()`.
    pub fn blocked_windows(&self) -> &[::std::string::String] {
        self.blocked_windows.as_deref().unwrap_or_default()
    }
    /// <p>An array of one or more dates that you can specify when Amazon Web Services does not start practice runs for a resource.</p>
    /// <p>Specify blocked dates, in UTC, in the format <code>YYYY-MM-DD</code>, separated by spaces.</p>
    pub fn blocked_dates(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.blocked_dates.deref()
    }
}
impl PracticeRunConfiguration {
    /// Creates a new builder-style object to manufacture [`PracticeRunConfiguration`](crate::types::PracticeRunConfiguration).
    pub fn builder() -> crate::types::builders::PracticeRunConfigurationBuilder {
        crate::types::builders::PracticeRunConfigurationBuilder::default()
    }
}

/// A builder for [`PracticeRunConfiguration`](crate::types::PracticeRunConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PracticeRunConfigurationBuilder {
    pub(crate) blocking_alarms: ::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>>,
    pub(crate) outcome_alarms: ::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>>,
    pub(crate) blocked_windows: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) blocked_dates: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl PracticeRunConfigurationBuilder {
    /// Appends an item to `blocking_alarms`.
    ///
    /// To override the contents of this collection use [`set_blocking_alarms`](Self::set_blocking_alarms).
    ///
    /// <p>The <i>blocking alarm</i> for practice runs is an optional alarm that you can specify that blocks practice runs when the alarm is in an <code>ALARM</code> state.</p>
    pub fn blocking_alarms(mut self, input: crate::types::ControlCondition) -> Self {
        let mut v = self.blocking_alarms.unwrap_or_default();
        v.push(input);
        self.blocking_alarms = ::std::option::Option::Some(v);
        self
    }
    /// <p>The <i>blocking alarm</i> for practice runs is an optional alarm that you can specify that blocks practice runs when the alarm is in an <code>ALARM</code> state.</p>
    pub fn set_blocking_alarms(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>>) -> Self {
        self.blocking_alarms = input;
        self
    }
    /// <p>The <i>blocking alarm</i> for practice runs is an optional alarm that you can specify that blocks practice runs when the alarm is in an <code>ALARM</code> state.</p>
    pub fn get_blocking_alarms(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>> {
        &self.blocking_alarms
    }
    /// Appends an item to `outcome_alarms`.
    ///
    /// To override the contents of this collection use [`set_outcome_alarms`](Self::set_outcome_alarms).
    ///
    /// <p>The <i>outcome alarm</i> for practice runs is an alarm that you specify that ends a practice run when the alarm is in an <code>ALARM</code> state.</p>
    pub fn outcome_alarms(mut self, input: crate::types::ControlCondition) -> Self {
        let mut v = self.outcome_alarms.unwrap_or_default();
        v.push(input);
        self.outcome_alarms = ::std::option::Option::Some(v);
        self
    }
    /// <p>The <i>outcome alarm</i> for practice runs is an alarm that you specify that ends a practice run when the alarm is in an <code>ALARM</code> state.</p>
    pub fn set_outcome_alarms(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>>) -> Self {
        self.outcome_alarms = input;
        self
    }
    /// <p>The <i>outcome alarm</i> for practice runs is an alarm that you specify that ends a practice run when the alarm is in an <code>ALARM</code> state.</p>
    pub fn get_outcome_alarms(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>> {
        &self.outcome_alarms
    }
    /// Appends an item to `blocked_windows`.
    ///
    /// To override the contents of this collection use [`set_blocked_windows`](Self::set_blocked_windows).
    ///
    /// <p>An array of one or more windows of days and times that you can block ARC from starting practice runs for a resource.</p>
    /// <p>Specify the blocked windows in UTC, using the format <code>DAY:HH:MM-DAY:HH:MM</code>, separated by spaces. For example, <code>MON:18:30-MON:19:30 TUE:18:30-TUE:19:30</code>.</p>
    pub fn blocked_windows(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.blocked_windows.unwrap_or_default();
        v.push(input.into());
        self.blocked_windows = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of one or more windows of days and times that you can block ARC from starting practice runs for a resource.</p>
    /// <p>Specify the blocked windows in UTC, using the format <code>DAY:HH:MM-DAY:HH:MM</code>, separated by spaces. For example, <code>MON:18:30-MON:19:30 TUE:18:30-TUE:19:30</code>.</p>
    pub fn set_blocked_windows(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.blocked_windows = input;
        self
    }
    /// <p>An array of one or more windows of days and times that you can block ARC from starting practice runs for a resource.</p>
    /// <p>Specify the blocked windows in UTC, using the format <code>DAY:HH:MM-DAY:HH:MM</code>, separated by spaces. For example, <code>MON:18:30-MON:19:30 TUE:18:30-TUE:19:30</code>.</p>
    pub fn get_blocked_windows(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.blocked_windows
    }
    /// Appends an item to `blocked_dates`.
    ///
    /// To override the contents of this collection use [`set_blocked_dates`](Self::set_blocked_dates).
    ///
    /// <p>An array of one or more dates that you can specify when Amazon Web Services does not start practice runs for a resource.</p>
    /// <p>Specify blocked dates, in UTC, in the format <code>YYYY-MM-DD</code>, separated by spaces.</p>
    pub fn blocked_dates(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.blocked_dates.unwrap_or_default();
        v.push(input.into());
        self.blocked_dates = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of one or more dates that you can specify when Amazon Web Services does not start practice runs for a resource.</p>
    /// <p>Specify blocked dates, in UTC, in the format <code>YYYY-MM-DD</code>, separated by spaces.</p>
    pub fn set_blocked_dates(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.blocked_dates = input;
        self
    }
    /// <p>An array of one or more dates that you can specify when Amazon Web Services does not start practice runs for a resource.</p>
    /// <p>Specify blocked dates, in UTC, in the format <code>YYYY-MM-DD</code>, separated by spaces.</p>
    pub fn get_blocked_dates(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.blocked_dates
    }
    /// Consumes the builder and constructs a [`PracticeRunConfiguration`](crate::types::PracticeRunConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`outcome_alarms`](crate::types::builders::PracticeRunConfigurationBuilder::outcome_alarms)
    pub fn build(self) -> ::std::result::Result<crate::types::PracticeRunConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PracticeRunConfiguration {
            blocking_alarms: self.blocking_alarms,
            outcome_alarms: self.outcome_alarms.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "outcome_alarms",
                    "outcome_alarms was not specified but it is required when building PracticeRunConfiguration",
                )
            })?,
            blocked_windows: self.blocked_windows,
            blocked_dates: self.blocked_dates.unwrap_or_default(),
        })
    }
}
