// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary of the mitigation action tasks.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetectMitigationActionsTaskSummary {
    /// <p>The unique identifier of the task.</p>
    pub task_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the task.</p>
    pub task_status: ::std::option::Option<crate::types::DetectMitigationActionsTaskStatus>,
    /// <p>The date the task started.</p>
    pub task_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date the task ended.</p>
    pub task_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Specifies the ML Detect findings to which the mitigation actions are applied.</p>
    pub target: ::std::option::Option<crate::types::DetectMitigationActionsTaskTarget>,
    /// <p>Specifies the time period of which violation events occurred between.</p>
    pub violation_event_occurrence_range: ::std::option::Option<crate::types::ViolationEventOccurrenceRange>,
    /// <p>Includes only active violations.</p>
    pub only_active_violations_included: bool,
    /// <p>Includes suppressed alerts.</p>
    pub suppressed_alerts_included: bool,
    /// <p>The definition of the actions.</p>
    pub actions_definition: ::std::option::Option<::std::vec::Vec<crate::types::MitigationAction>>,
    /// <p>The statistics of a mitigation action task.</p>
    pub task_statistics: ::std::option::Option<crate::types::DetectMitigationActionsTaskStatistics>,
}
impl DetectMitigationActionsTaskSummary {
    /// <p>The unique identifier of the task.</p>
    pub fn task_id(&self) -> ::std::option::Option<&str> {
        self.task_id.as_deref()
    }
    /// <p>The status of the task.</p>
    pub fn task_status(&self) -> ::std::option::Option<&crate::types::DetectMitigationActionsTaskStatus> {
        self.task_status.as_ref()
    }
    /// <p>The date the task started.</p>
    pub fn task_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.task_start_time.as_ref()
    }
    /// <p>The date the task ended.</p>
    pub fn task_end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.task_end_time.as_ref()
    }
    /// <p>Specifies the ML Detect findings to which the mitigation actions are applied.</p>
    pub fn target(&self) -> ::std::option::Option<&crate::types::DetectMitigationActionsTaskTarget> {
        self.target.as_ref()
    }
    /// <p>Specifies the time period of which violation events occurred between.</p>
    pub fn violation_event_occurrence_range(&self) -> ::std::option::Option<&crate::types::ViolationEventOccurrenceRange> {
        self.violation_event_occurrence_range.as_ref()
    }
    /// <p>Includes only active violations.</p>
    pub fn only_active_violations_included(&self) -> bool {
        self.only_active_violations_included
    }
    /// <p>Includes suppressed alerts.</p>
    pub fn suppressed_alerts_included(&self) -> bool {
        self.suppressed_alerts_included
    }
    /// <p>The definition of the actions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.actions_definition.is_none()`.
    pub fn actions_definition(&self) -> &[crate::types::MitigationAction] {
        self.actions_definition.as_deref().unwrap_or_default()
    }
    /// <p>The statistics of a mitigation action task.</p>
    pub fn task_statistics(&self) -> ::std::option::Option<&crate::types::DetectMitigationActionsTaskStatistics> {
        self.task_statistics.as_ref()
    }
}
impl DetectMitigationActionsTaskSummary {
    /// Creates a new builder-style object to manufacture [`DetectMitigationActionsTaskSummary`](crate::types::DetectMitigationActionsTaskSummary).
    pub fn builder() -> crate::types::builders::DetectMitigationActionsTaskSummaryBuilder {
        crate::types::builders::DetectMitigationActionsTaskSummaryBuilder::default()
    }
}

/// A builder for [`DetectMitigationActionsTaskSummary`](crate::types::DetectMitigationActionsTaskSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetectMitigationActionsTaskSummaryBuilder {
    pub(crate) task_id: ::std::option::Option<::std::string::String>,
    pub(crate) task_status: ::std::option::Option<crate::types::DetectMitigationActionsTaskStatus>,
    pub(crate) task_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) task_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) target: ::std::option::Option<crate::types::DetectMitigationActionsTaskTarget>,
    pub(crate) violation_event_occurrence_range: ::std::option::Option<crate::types::ViolationEventOccurrenceRange>,
    pub(crate) only_active_violations_included: ::std::option::Option<bool>,
    pub(crate) suppressed_alerts_included: ::std::option::Option<bool>,
    pub(crate) actions_definition: ::std::option::Option<::std::vec::Vec<crate::types::MitigationAction>>,
    pub(crate) task_statistics: ::std::option::Option<crate::types::DetectMitigationActionsTaskStatistics>,
}
impl DetectMitigationActionsTaskSummaryBuilder {
    /// <p>The unique identifier of the task.</p>
    pub fn task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the task.</p>
    pub fn set_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_id = input;
        self
    }
    /// <p>The unique identifier of the task.</p>
    pub fn get_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_id
    }
    /// <p>The status of the task.</p>
    pub fn task_status(mut self, input: crate::types::DetectMitigationActionsTaskStatus) -> Self {
        self.task_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the task.</p>
    pub fn set_task_status(mut self, input: ::std::option::Option<crate::types::DetectMitigationActionsTaskStatus>) -> Self {
        self.task_status = input;
        self
    }
    /// <p>The status of the task.</p>
    pub fn get_task_status(&self) -> &::std::option::Option<crate::types::DetectMitigationActionsTaskStatus> {
        &self.task_status
    }
    /// <p>The date the task started.</p>
    pub fn task_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.task_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date the task started.</p>
    pub fn set_task_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.task_start_time = input;
        self
    }
    /// <p>The date the task started.</p>
    pub fn get_task_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.task_start_time
    }
    /// <p>The date the task ended.</p>
    pub fn task_end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.task_end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date the task ended.</p>
    pub fn set_task_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.task_end_time = input;
        self
    }
    /// <p>The date the task ended.</p>
    pub fn get_task_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.task_end_time
    }
    /// <p>Specifies the ML Detect findings to which the mitigation actions are applied.</p>
    pub fn target(mut self, input: crate::types::DetectMitigationActionsTaskTarget) -> Self {
        self.target = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the ML Detect findings to which the mitigation actions are applied.</p>
    pub fn set_target(mut self, input: ::std::option::Option<crate::types::DetectMitigationActionsTaskTarget>) -> Self {
        self.target = input;
        self
    }
    /// <p>Specifies the ML Detect findings to which the mitigation actions are applied.</p>
    pub fn get_target(&self) -> &::std::option::Option<crate::types::DetectMitigationActionsTaskTarget> {
        &self.target
    }
    /// <p>Specifies the time period of which violation events occurred between.</p>
    pub fn violation_event_occurrence_range(mut self, input: crate::types::ViolationEventOccurrenceRange) -> Self {
        self.violation_event_occurrence_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the time period of which violation events occurred between.</p>
    pub fn set_violation_event_occurrence_range(mut self, input: ::std::option::Option<crate::types::ViolationEventOccurrenceRange>) -> Self {
        self.violation_event_occurrence_range = input;
        self
    }
    /// <p>Specifies the time period of which violation events occurred between.</p>
    pub fn get_violation_event_occurrence_range(&self) -> &::std::option::Option<crate::types::ViolationEventOccurrenceRange> {
        &self.violation_event_occurrence_range
    }
    /// <p>Includes only active violations.</p>
    pub fn only_active_violations_included(mut self, input: bool) -> Self {
        self.only_active_violations_included = ::std::option::Option::Some(input);
        self
    }
    /// <p>Includes only active violations.</p>
    pub fn set_only_active_violations_included(mut self, input: ::std::option::Option<bool>) -> Self {
        self.only_active_violations_included = input;
        self
    }
    /// <p>Includes only active violations.</p>
    pub fn get_only_active_violations_included(&self) -> &::std::option::Option<bool> {
        &self.only_active_violations_included
    }
    /// <p>Includes suppressed alerts.</p>
    pub fn suppressed_alerts_included(mut self, input: bool) -> Self {
        self.suppressed_alerts_included = ::std::option::Option::Some(input);
        self
    }
    /// <p>Includes suppressed alerts.</p>
    pub fn set_suppressed_alerts_included(mut self, input: ::std::option::Option<bool>) -> Self {
        self.suppressed_alerts_included = input;
        self
    }
    /// <p>Includes suppressed alerts.</p>
    pub fn get_suppressed_alerts_included(&self) -> &::std::option::Option<bool> {
        &self.suppressed_alerts_included
    }
    /// Appends an item to `actions_definition`.
    ///
    /// To override the contents of this collection use [`set_actions_definition`](Self::set_actions_definition).
    ///
    /// <p>The definition of the actions.</p>
    pub fn actions_definition(mut self, input: crate::types::MitigationAction) -> Self {
        let mut v = self.actions_definition.unwrap_or_default();
        v.push(input);
        self.actions_definition = ::std::option::Option::Some(v);
        self
    }
    /// <p>The definition of the actions.</p>
    pub fn set_actions_definition(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MitigationAction>>) -> Self {
        self.actions_definition = input;
        self
    }
    /// <p>The definition of the actions.</p>
    pub fn get_actions_definition(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MitigationAction>> {
        &self.actions_definition
    }
    /// <p>The statistics of a mitigation action task.</p>
    pub fn task_statistics(mut self, input: crate::types::DetectMitigationActionsTaskStatistics) -> Self {
        self.task_statistics = ::std::option::Option::Some(input);
        self
    }
    /// <p>The statistics of a mitigation action task.</p>
    pub fn set_task_statistics(mut self, input: ::std::option::Option<crate::types::DetectMitigationActionsTaskStatistics>) -> Self {
        self.task_statistics = input;
        self
    }
    /// <p>The statistics of a mitigation action task.</p>
    pub fn get_task_statistics(&self) -> &::std::option::Option<crate::types::DetectMitigationActionsTaskStatistics> {
        &self.task_statistics
    }
    /// Consumes the builder and constructs a [`DetectMitigationActionsTaskSummary`](crate::types::DetectMitigationActionsTaskSummary).
    pub fn build(self) -> crate::types::DetectMitigationActionsTaskSummary {
        crate::types::DetectMitigationActionsTaskSummary {
            task_id: self.task_id,
            task_status: self.task_status,
            task_start_time: self.task_start_time,
            task_end_time: self.task_end_time,
            target: self.target,
            violation_event_occurrence_range: self.violation_event_occurrence_range,
            only_active_violations_included: self.only_active_violations_included.unwrap_or_default(),
            suppressed_alerts_included: self.suppressed_alerts_included.unwrap_or_default(),
            actions_definition: self.actions_definition,
            task_statistics: self.task_statistics,
        }
    }
}
