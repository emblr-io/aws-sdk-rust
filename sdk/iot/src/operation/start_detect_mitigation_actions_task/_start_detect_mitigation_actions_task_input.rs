// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartDetectMitigationActionsTaskInput {
    /// <p>The unique identifier of the task.</p>
    pub task_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the ML Detect findings to which the mitigation actions are applied.</p>
    pub target: ::std::option::Option<crate::types::DetectMitigationActionsTaskTarget>,
    /// <p>The actions to be performed when a device has unexpected behavior.</p>
    pub actions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Specifies the time period of which violation events occurred between.</p>
    pub violation_event_occurrence_range: ::std::option::Option<crate::types::ViolationEventOccurrenceRange>,
    /// <p>Specifies to list only active violations.</p>
    pub include_only_active_violations: ::std::option::Option<bool>,
    /// <p>Specifies to include suppressed alerts.</p>
    pub include_suppressed_alerts: ::std::option::Option<bool>,
    /// <p>Each mitigation action task must have a unique client request token. If you try to create a new task with the same token as a task that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl StartDetectMitigationActionsTaskInput {
    /// <p>The unique identifier of the task.</p>
    pub fn task_id(&self) -> ::std::option::Option<&str> {
        self.task_id.as_deref()
    }
    /// <p>Specifies the ML Detect findings to which the mitigation actions are applied.</p>
    pub fn target(&self) -> ::std::option::Option<&crate::types::DetectMitigationActionsTaskTarget> {
        self.target.as_ref()
    }
    /// <p>The actions to be performed when a device has unexpected behavior.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.actions.is_none()`.
    pub fn actions(&self) -> &[::std::string::String] {
        self.actions.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the time period of which violation events occurred between.</p>
    pub fn violation_event_occurrence_range(&self) -> ::std::option::Option<&crate::types::ViolationEventOccurrenceRange> {
        self.violation_event_occurrence_range.as_ref()
    }
    /// <p>Specifies to list only active violations.</p>
    pub fn include_only_active_violations(&self) -> ::std::option::Option<bool> {
        self.include_only_active_violations
    }
    /// <p>Specifies to include suppressed alerts.</p>
    pub fn include_suppressed_alerts(&self) -> ::std::option::Option<bool> {
        self.include_suppressed_alerts
    }
    /// <p>Each mitigation action task must have a unique client request token. If you try to create a new task with the same token as a task that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl StartDetectMitigationActionsTaskInput {
    /// Creates a new builder-style object to manufacture [`StartDetectMitigationActionsTaskInput`](crate::operation::start_detect_mitigation_actions_task::StartDetectMitigationActionsTaskInput).
    pub fn builder() -> crate::operation::start_detect_mitigation_actions_task::builders::StartDetectMitigationActionsTaskInputBuilder {
        crate::operation::start_detect_mitigation_actions_task::builders::StartDetectMitigationActionsTaskInputBuilder::default()
    }
}

/// A builder for [`StartDetectMitigationActionsTaskInput`](crate::operation::start_detect_mitigation_actions_task::StartDetectMitigationActionsTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartDetectMitigationActionsTaskInputBuilder {
    pub(crate) task_id: ::std::option::Option<::std::string::String>,
    pub(crate) target: ::std::option::Option<crate::types::DetectMitigationActionsTaskTarget>,
    pub(crate) actions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) violation_event_occurrence_range: ::std::option::Option<crate::types::ViolationEventOccurrenceRange>,
    pub(crate) include_only_active_violations: ::std::option::Option<bool>,
    pub(crate) include_suppressed_alerts: ::std::option::Option<bool>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl StartDetectMitigationActionsTaskInputBuilder {
    /// <p>The unique identifier of the task.</p>
    /// This field is required.
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
    /// <p>Specifies the ML Detect findings to which the mitigation actions are applied.</p>
    /// This field is required.
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
    /// Appends an item to `actions`.
    ///
    /// To override the contents of this collection use [`set_actions`](Self::set_actions).
    ///
    /// <p>The actions to be performed when a device has unexpected behavior.</p>
    pub fn actions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.actions.unwrap_or_default();
        v.push(input.into());
        self.actions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The actions to be performed when a device has unexpected behavior.</p>
    pub fn set_actions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.actions = input;
        self
    }
    /// <p>The actions to be performed when a device has unexpected behavior.</p>
    pub fn get_actions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.actions
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
    /// <p>Specifies to list only active violations.</p>
    pub fn include_only_active_violations(mut self, input: bool) -> Self {
        self.include_only_active_violations = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies to list only active violations.</p>
    pub fn set_include_only_active_violations(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_only_active_violations = input;
        self
    }
    /// <p>Specifies to list only active violations.</p>
    pub fn get_include_only_active_violations(&self) -> &::std::option::Option<bool> {
        &self.include_only_active_violations
    }
    /// <p>Specifies to include suppressed alerts.</p>
    pub fn include_suppressed_alerts(mut self, input: bool) -> Self {
        self.include_suppressed_alerts = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies to include suppressed alerts.</p>
    pub fn set_include_suppressed_alerts(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_suppressed_alerts = input;
        self
    }
    /// <p>Specifies to include suppressed alerts.</p>
    pub fn get_include_suppressed_alerts(&self) -> &::std::option::Option<bool> {
        &self.include_suppressed_alerts
    }
    /// <p>Each mitigation action task must have a unique client request token. If you try to create a new task with the same token as a task that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    /// This field is required.
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Each mitigation action task must have a unique client request token. If you try to create a new task with the same token as a task that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>Each mitigation action task must have a unique client request token. If you try to create a new task with the same token as a task that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`StartDetectMitigationActionsTaskInput`](crate::operation::start_detect_mitigation_actions_task::StartDetectMitigationActionsTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_detect_mitigation_actions_task::StartDetectMitigationActionsTaskInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::start_detect_mitigation_actions_task::StartDetectMitigationActionsTaskInput {
                task_id: self.task_id,
                target: self.target,
                actions: self.actions,
                violation_event_occurrence_range: self.violation_event_occurrence_range,
                include_only_active_violations: self.include_only_active_violations,
                include_suppressed_alerts: self.include_suppressed_alerts,
                client_request_token: self.client_request_token,
            },
        )
    }
}
