// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// List of actions that have been created in the schedule.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchScheduleActionCreateResult {
    /// List of actions that have been created in the schedule.
    pub schedule_actions: ::std::option::Option<::std::vec::Vec<crate::types::ScheduleAction>>,
}
impl BatchScheduleActionCreateResult {
    /// List of actions that have been created in the schedule.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.schedule_actions.is_none()`.
    pub fn schedule_actions(&self) -> &[crate::types::ScheduleAction] {
        self.schedule_actions.as_deref().unwrap_or_default()
    }
}
impl BatchScheduleActionCreateResult {
    /// Creates a new builder-style object to manufacture [`BatchScheduleActionCreateResult`](crate::types::BatchScheduleActionCreateResult).
    pub fn builder() -> crate::types::builders::BatchScheduleActionCreateResultBuilder {
        crate::types::builders::BatchScheduleActionCreateResultBuilder::default()
    }
}

/// A builder for [`BatchScheduleActionCreateResult`](crate::types::BatchScheduleActionCreateResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchScheduleActionCreateResultBuilder {
    pub(crate) schedule_actions: ::std::option::Option<::std::vec::Vec<crate::types::ScheduleAction>>,
}
impl BatchScheduleActionCreateResultBuilder {
    /// Appends an item to `schedule_actions`.
    ///
    /// To override the contents of this collection use [`set_schedule_actions`](Self::set_schedule_actions).
    ///
    /// List of actions that have been created in the schedule.
    pub fn schedule_actions(mut self, input: crate::types::ScheduleAction) -> Self {
        let mut v = self.schedule_actions.unwrap_or_default();
        v.push(input);
        self.schedule_actions = ::std::option::Option::Some(v);
        self
    }
    /// List of actions that have been created in the schedule.
    pub fn set_schedule_actions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ScheduleAction>>) -> Self {
        self.schedule_actions = input;
        self
    }
    /// List of actions that have been created in the schedule.
    pub fn get_schedule_actions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ScheduleAction>> {
        &self.schedule_actions
    }
    /// Consumes the builder and constructs a [`BatchScheduleActionCreateResult`](crate::types::BatchScheduleActionCreateResult).
    pub fn build(self) -> crate::types::BatchScheduleActionCreateResult {
        crate::types::BatchScheduleActionCreateResult {
            schedule_actions: self.schedule_actions,
        }
    }
}
