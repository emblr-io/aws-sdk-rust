// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a decision made by the decider. A decision can be one of these types:</p>
/// <ul>
/// <li>
/// <p><code>CancelTimer</code> – Cancels a previously started timer and records a <code>TimerCanceled</code> event in the history.</p></li>
/// <li>
/// <p><code>CancelWorkflowExecution</code> – Closes the workflow execution and records a <code>WorkflowExecutionCanceled</code> event in the history.</p></li>
/// <li>
/// <p><code>CompleteWorkflowExecution</code> – Closes the workflow execution and records a <code>WorkflowExecutionCompleted</code> event in the history .</p></li>
/// <li>
/// <p><code>ContinueAsNewWorkflowExecution</code> – Closes the workflow execution and starts a new workflow execution of the same type using the same workflow ID and a unique run Id. A <code>WorkflowExecutionContinuedAsNew</code> event is recorded in the history.</p></li>
/// <li>
/// <p><code>FailWorkflowExecution</code> – Closes the workflow execution and records a <code>WorkflowExecutionFailed</code> event in the history.</p></li>
/// <li>
/// <p><code>RecordMarker</code> – Records a <code>MarkerRecorded</code> event in the history. Markers can be used for adding custom information in the history for instance to let deciders know that they don't need to look at the history beyond the marker event.</p></li>
/// <li>
/// <p><code>RequestCancelActivityTask</code> – Attempts to cancel a previously scheduled activity task. If the activity task was scheduled but has not been assigned to a worker, then it is canceled. If the activity task was already assigned to a worker, then the worker is informed that cancellation has been requested in the response to <code>RecordActivityTaskHeartbeat</code>.</p></li>
/// <li>
/// <p><code>RequestCancelExternalWorkflowExecution</code> – Requests that a request be made to cancel the specified external workflow execution and records a <code>RequestCancelExternalWorkflowExecutionInitiated</code> event in the history.</p></li>
/// <li>
/// <p><code>ScheduleActivityTask</code> – Schedules an activity task.</p></li>
/// <li>
/// <p><code>SignalExternalWorkflowExecution</code> – Requests a signal to be delivered to the specified external workflow execution and records a <code>SignalExternalWorkflowExecutionInitiated</code> event in the history.</p></li>
/// <li>
/// <p><code>StartChildWorkflowExecution</code> – Requests that a child workflow execution be started and records a <code>StartChildWorkflowExecutionInitiated</code> event in the history. The child workflow execution is a separate workflow execution with its own history.</p></li>
/// <li>
/// <p><code>StartTimer</code> – Starts a timer for this workflow execution and records a <code>TimerStarted</code> event in the history. This timer fires after the specified delay and record a <code>TimerFired</code> event.</p></li>
/// </ul>
/// <p><b>Access Control</b></p>
/// <p>If you grant permission to use <code>RespondDecisionTaskCompleted</code>, you can use IAM policies to express permissions for the list of decisions returned by this action as if they were members of the API. Treating decisions as a pseudo API maintains a uniform conceptual model and helps keep policies readable. For details and example IAM policies, see <a href="https://docs.aws.amazon.com/amazonswf/latest/developerguide/swf-dev-iam.html">Using IAM to Manage Access to Amazon SWF Workflows</a> in the <i>Amazon SWF Developer Guide</i>.</p>
/// <p><b>Decision Failure</b></p>
/// <p>Decisions can fail for several reasons</p>
/// <ul>
/// <li>
/// <p>The ordering of decisions should follow a logical flow. Some decisions might not make sense in the current context of the workflow execution and therefore fails.</p></li>
/// <li>
/// <p>A limit on your account was reached.</p></li>
/// <li>
/// <p>The decision lacks sufficient permissions.</p></li>
/// </ul>
/// <p>One of the following events might be added to the history to indicate an error. The event attribute's <code>cause</code> parameter indicates the cause. If <code>cause</code> is set to <code>OPERATION_NOT_PERMITTED</code>, the decision failed because it lacked sufficient permissions. For details and example IAM policies, see <a href="https://docs.aws.amazon.com/amazonswf/latest/developerguide/swf-dev-iam.html">Using IAM to Manage Access to Amazon SWF Workflows</a> in the <i>Amazon SWF Developer Guide</i>.</p>
/// <ul>
/// <li>
/// <p><code>ScheduleActivityTaskFailed</code> – A <code>ScheduleActivityTask</code> decision failed. This could happen if the activity type specified in the decision isn't registered, is in a deprecated state, or the decision isn't properly configured.</p></li>
/// <li>
/// <p><code>RequestCancelActivityTaskFailed</code> – A <code>RequestCancelActivityTask</code> decision failed. This could happen if there is no open activity task with the specified activityId.</p></li>
/// <li>
/// <p><code>StartTimerFailed</code> – A <code>StartTimer</code> decision failed. This could happen if there is another open timer with the same timerId.</p></li>
/// <li>
/// <p><code>CancelTimerFailed</code> – A <code>CancelTimer</code> decision failed. This could happen if there is no open timer with the specified timerId.</p></li>
/// <li>
/// <p><code>StartChildWorkflowExecutionFailed</code> – A <code>StartChildWorkflowExecution</code> decision failed. This could happen if the workflow type specified isn't registered, is deprecated, or the decision isn't properly configured.</p></li>
/// <li>
/// <p><code>SignalExternalWorkflowExecutionFailed</code> – A <code>SignalExternalWorkflowExecution</code> decision failed. This could happen if the <code>workflowID</code> specified in the decision was incorrect.</p></li>
/// <li>
/// <p><code>RequestCancelExternalWorkflowExecutionFailed</code> – A <code>RequestCancelExternalWorkflowExecution</code> decision failed. This could happen if the <code>workflowID</code> specified in the decision was incorrect.</p></li>
/// <li>
/// <p><code>CancelWorkflowExecutionFailed</code> – A <code>CancelWorkflowExecution</code> decision failed. This could happen if there is an unhandled decision task pending in the workflow execution.</p></li>
/// <li>
/// <p><code>CompleteWorkflowExecutionFailed</code> – A <code>CompleteWorkflowExecution</code> decision failed. This could happen if there is an unhandled decision task pending in the workflow execution.</p></li>
/// <li>
/// <p><code>ContinueAsNewWorkflowExecutionFailed</code> – A <code>ContinueAsNewWorkflowExecution</code> decision failed. This could happen if there is an unhandled decision task pending in the workflow execution or the ContinueAsNewWorkflowExecution decision was not configured correctly.</p></li>
/// <li>
/// <p><code>FailWorkflowExecutionFailed</code> – A <code>FailWorkflowExecution</code> decision failed. This could happen if there is an unhandled decision task pending in the workflow execution.</p></li>
/// </ul>
/// <p>The preceding error events might occur due to an error in the decider logic, which might put the workflow execution in an unstable state The cause field in the event structure for the error event indicates the cause of the error.</p><note>
/// <p>A workflow execution may be closed by the decider by returning one of the following decisions when completing a decision task: <code>CompleteWorkflowExecution</code>, <code>FailWorkflowExecution</code>, <code>CancelWorkflowExecution</code> and <code>ContinueAsNewWorkflowExecution</code>. An <code>UnhandledDecision</code> fault is returned if a workflow closing decision is specified and a signal or activity event had been added to the history while the decision task was being performed by the decider. Unlike the above situations which are logic issues, this fault is always possible because of race conditions in a distributed system. The right action here is to call <code>RespondDecisionTaskCompleted</code> without any decisions. This would result in another decision task with these new events included in the history. The decider should handle the new events and may decide to close the workflow execution.</p>
/// </note>
/// <p><b>How to Code a Decision</b></p>
/// <p>You code a decision by first setting the decision type field to one of the above decision values, and then set the corresponding attributes field shown below:</p>
/// <ul>
/// <li>
/// <p><code> <code>ScheduleActivityTaskDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>RequestCancelActivityTaskDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>CompleteWorkflowExecutionDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>FailWorkflowExecutionDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>CancelWorkflowExecutionDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>ContinueAsNewWorkflowExecutionDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>RecordMarkerDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>StartTimerDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>CancelTimerDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>SignalExternalWorkflowExecutionDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>RequestCancelExternalWorkflowExecutionDecisionAttributes</code> </code></p></li>
/// <li>
/// <p><code> <code>StartChildWorkflowExecutionDecisionAttributes</code> </code></p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Decision {
    /// <p>Specifies the type of the decision.</p>
    pub decision_type: crate::types::DecisionType,
    /// <p>Provides the details of the <code>ScheduleActivityTask</code> decision. It isn't set for other decision types.</p>
    pub schedule_activity_task_decision_attributes: ::std::option::Option<crate::types::ScheduleActivityTaskDecisionAttributes>,
    /// <p>Provides the details of the <code>RequestCancelActivityTask</code> decision. It isn't set for other decision types.</p>
    pub request_cancel_activity_task_decision_attributes: ::std::option::Option<crate::types::RequestCancelActivityTaskDecisionAttributes>,
    /// <p>Provides the details of the <code>CompleteWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub complete_workflow_execution_decision_attributes: ::std::option::Option<crate::types::CompleteWorkflowExecutionDecisionAttributes>,
    /// <p>Provides the details of the <code>FailWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fail_workflow_execution_decision_attributes: ::std::option::Option<crate::types::FailWorkflowExecutionDecisionAttributes>,
    /// <p>Provides the details of the <code>CancelWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub cancel_workflow_execution_decision_attributes: ::std::option::Option<crate::types::CancelWorkflowExecutionDecisionAttributes>,
    /// <p>Provides the details of the <code>ContinueAsNewWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub continue_as_new_workflow_execution_decision_attributes: ::std::option::Option<crate::types::ContinueAsNewWorkflowExecutionDecisionAttributes>,
    /// <p>Provides the details of the <code>RecordMarker</code> decision. It isn't set for other decision types.</p>
    pub record_marker_decision_attributes: ::std::option::Option<crate::types::RecordMarkerDecisionAttributes>,
    /// <p>Provides the details of the <code>StartTimer</code> decision. It isn't set for other decision types.</p>
    pub start_timer_decision_attributes: ::std::option::Option<crate::types::StartTimerDecisionAttributes>,
    /// <p>Provides the details of the <code>CancelTimer</code> decision. It isn't set for other decision types.</p>
    pub cancel_timer_decision_attributes: ::std::option::Option<crate::types::CancelTimerDecisionAttributes>,
    /// <p>Provides the details of the <code>SignalExternalWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub signal_external_workflow_execution_decision_attributes:
        ::std::option::Option<crate::types::SignalExternalWorkflowExecutionDecisionAttributes>,
    /// <p>Provides the details of the <code>RequestCancelExternalWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub request_cancel_external_workflow_execution_decision_attributes:
        ::std::option::Option<crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes>,
    /// <p>Provides the details of the <code>StartChildWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub start_child_workflow_execution_decision_attributes: ::std::option::Option<crate::types::StartChildWorkflowExecutionDecisionAttributes>,
    /// <p>Provides the details of the <code>ScheduleLambdaFunction</code> decision. It isn't set for other decision types.</p>
    pub schedule_lambda_function_decision_attributes: ::std::option::Option<crate::types::ScheduleLambdaFunctionDecisionAttributes>,
}
impl Decision {
    /// <p>Specifies the type of the decision.</p>
    pub fn decision_type(&self) -> &crate::types::DecisionType {
        &self.decision_type
    }
    /// <p>Provides the details of the <code>ScheduleActivityTask</code> decision. It isn't set for other decision types.</p>
    pub fn schedule_activity_task_decision_attributes(&self) -> ::std::option::Option<&crate::types::ScheduleActivityTaskDecisionAttributes> {
        self.schedule_activity_task_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>RequestCancelActivityTask</code> decision. It isn't set for other decision types.</p>
    pub fn request_cancel_activity_task_decision_attributes(
        &self,
    ) -> ::std::option::Option<&crate::types::RequestCancelActivityTaskDecisionAttributes> {
        self.request_cancel_activity_task_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>CompleteWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn complete_workflow_execution_decision_attributes(
        &self,
    ) -> ::std::option::Option<&crate::types::CompleteWorkflowExecutionDecisionAttributes> {
        self.complete_workflow_execution_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>FailWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn fail_workflow_execution_decision_attributes(&self) -> ::std::option::Option<&crate::types::FailWorkflowExecutionDecisionAttributes> {
        self.fail_workflow_execution_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>CancelWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn cancel_workflow_execution_decision_attributes(&self) -> ::std::option::Option<&crate::types::CancelWorkflowExecutionDecisionAttributes> {
        self.cancel_workflow_execution_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>ContinueAsNewWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn continue_as_new_workflow_execution_decision_attributes(
        &self,
    ) -> ::std::option::Option<&crate::types::ContinueAsNewWorkflowExecutionDecisionAttributes> {
        self.continue_as_new_workflow_execution_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>RecordMarker</code> decision. It isn't set for other decision types.</p>
    pub fn record_marker_decision_attributes(&self) -> ::std::option::Option<&crate::types::RecordMarkerDecisionAttributes> {
        self.record_marker_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>StartTimer</code> decision. It isn't set for other decision types.</p>
    pub fn start_timer_decision_attributes(&self) -> ::std::option::Option<&crate::types::StartTimerDecisionAttributes> {
        self.start_timer_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>CancelTimer</code> decision. It isn't set for other decision types.</p>
    pub fn cancel_timer_decision_attributes(&self) -> ::std::option::Option<&crate::types::CancelTimerDecisionAttributes> {
        self.cancel_timer_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>SignalExternalWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn signal_external_workflow_execution_decision_attributes(
        &self,
    ) -> ::std::option::Option<&crate::types::SignalExternalWorkflowExecutionDecisionAttributes> {
        self.signal_external_workflow_execution_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>RequestCancelExternalWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn request_cancel_external_workflow_execution_decision_attributes(
        &self,
    ) -> ::std::option::Option<&crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes> {
        self.request_cancel_external_workflow_execution_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>StartChildWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn start_child_workflow_execution_decision_attributes(
        &self,
    ) -> ::std::option::Option<&crate::types::StartChildWorkflowExecutionDecisionAttributes> {
        self.start_child_workflow_execution_decision_attributes.as_ref()
    }
    /// <p>Provides the details of the <code>ScheduleLambdaFunction</code> decision. It isn't set for other decision types.</p>
    pub fn schedule_lambda_function_decision_attributes(&self) -> ::std::option::Option<&crate::types::ScheduleLambdaFunctionDecisionAttributes> {
        self.schedule_lambda_function_decision_attributes.as_ref()
    }
}
impl Decision {
    /// Creates a new builder-style object to manufacture [`Decision`](crate::types::Decision).
    pub fn builder() -> crate::types::builders::DecisionBuilder {
        crate::types::builders::DecisionBuilder::default()
    }
}

/// A builder for [`Decision`](crate::types::Decision).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DecisionBuilder {
    pub(crate) decision_type: ::std::option::Option<crate::types::DecisionType>,
    pub(crate) schedule_activity_task_decision_attributes: ::std::option::Option<crate::types::ScheduleActivityTaskDecisionAttributes>,
    pub(crate) request_cancel_activity_task_decision_attributes: ::std::option::Option<crate::types::RequestCancelActivityTaskDecisionAttributes>,
    pub(crate) complete_workflow_execution_decision_attributes: ::std::option::Option<crate::types::CompleteWorkflowExecutionDecisionAttributes>,
    pub(crate) fail_workflow_execution_decision_attributes: ::std::option::Option<crate::types::FailWorkflowExecutionDecisionAttributes>,
    pub(crate) cancel_workflow_execution_decision_attributes: ::std::option::Option<crate::types::CancelWorkflowExecutionDecisionAttributes>,
    pub(crate) continue_as_new_workflow_execution_decision_attributes:
        ::std::option::Option<crate::types::ContinueAsNewWorkflowExecutionDecisionAttributes>,
    pub(crate) record_marker_decision_attributes: ::std::option::Option<crate::types::RecordMarkerDecisionAttributes>,
    pub(crate) start_timer_decision_attributes: ::std::option::Option<crate::types::StartTimerDecisionAttributes>,
    pub(crate) cancel_timer_decision_attributes: ::std::option::Option<crate::types::CancelTimerDecisionAttributes>,
    pub(crate) signal_external_workflow_execution_decision_attributes:
        ::std::option::Option<crate::types::SignalExternalWorkflowExecutionDecisionAttributes>,
    pub(crate) request_cancel_external_workflow_execution_decision_attributes:
        ::std::option::Option<crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes>,
    pub(crate) start_child_workflow_execution_decision_attributes: ::std::option::Option<crate::types::StartChildWorkflowExecutionDecisionAttributes>,
    pub(crate) schedule_lambda_function_decision_attributes: ::std::option::Option<crate::types::ScheduleLambdaFunctionDecisionAttributes>,
}
impl DecisionBuilder {
    /// <p>Specifies the type of the decision.</p>
    /// This field is required.
    pub fn decision_type(mut self, input: crate::types::DecisionType) -> Self {
        self.decision_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the type of the decision.</p>
    pub fn set_decision_type(mut self, input: ::std::option::Option<crate::types::DecisionType>) -> Self {
        self.decision_type = input;
        self
    }
    /// <p>Specifies the type of the decision.</p>
    pub fn get_decision_type(&self) -> &::std::option::Option<crate::types::DecisionType> {
        &self.decision_type
    }
    /// <p>Provides the details of the <code>ScheduleActivityTask</code> decision. It isn't set for other decision types.</p>
    pub fn schedule_activity_task_decision_attributes(mut self, input: crate::types::ScheduleActivityTaskDecisionAttributes) -> Self {
        self.schedule_activity_task_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>ScheduleActivityTask</code> decision. It isn't set for other decision types.</p>
    pub fn set_schedule_activity_task_decision_attributes(
        mut self,
        input: ::std::option::Option<crate::types::ScheduleActivityTaskDecisionAttributes>,
    ) -> Self {
        self.schedule_activity_task_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>ScheduleActivityTask</code> decision. It isn't set for other decision types.</p>
    pub fn get_schedule_activity_task_decision_attributes(&self) -> &::std::option::Option<crate::types::ScheduleActivityTaskDecisionAttributes> {
        &self.schedule_activity_task_decision_attributes
    }
    /// <p>Provides the details of the <code>RequestCancelActivityTask</code> decision. It isn't set for other decision types.</p>
    pub fn request_cancel_activity_task_decision_attributes(mut self, input: crate::types::RequestCancelActivityTaskDecisionAttributes) -> Self {
        self.request_cancel_activity_task_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>RequestCancelActivityTask</code> decision. It isn't set for other decision types.</p>
    pub fn set_request_cancel_activity_task_decision_attributes(
        mut self,
        input: ::std::option::Option<crate::types::RequestCancelActivityTaskDecisionAttributes>,
    ) -> Self {
        self.request_cancel_activity_task_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>RequestCancelActivityTask</code> decision. It isn't set for other decision types.</p>
    pub fn get_request_cancel_activity_task_decision_attributes(
        &self,
    ) -> &::std::option::Option<crate::types::RequestCancelActivityTaskDecisionAttributes> {
        &self.request_cancel_activity_task_decision_attributes
    }
    /// <p>Provides the details of the <code>CompleteWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn complete_workflow_execution_decision_attributes(mut self, input: crate::types::CompleteWorkflowExecutionDecisionAttributes) -> Self {
        self.complete_workflow_execution_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>CompleteWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn set_complete_workflow_execution_decision_attributes(
        mut self,
        input: ::std::option::Option<crate::types::CompleteWorkflowExecutionDecisionAttributes>,
    ) -> Self {
        self.complete_workflow_execution_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>CompleteWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn get_complete_workflow_execution_decision_attributes(
        &self,
    ) -> &::std::option::Option<crate::types::CompleteWorkflowExecutionDecisionAttributes> {
        &self.complete_workflow_execution_decision_attributes
    }
    /// <p>Provides the details of the <code>FailWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn fail_workflow_execution_decision_attributes(mut self, input: crate::types::FailWorkflowExecutionDecisionAttributes) -> Self {
        self.fail_workflow_execution_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>FailWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn set_fail_workflow_execution_decision_attributes(
        mut self,
        input: ::std::option::Option<crate::types::FailWorkflowExecutionDecisionAttributes>,
    ) -> Self {
        self.fail_workflow_execution_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>FailWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn get_fail_workflow_execution_decision_attributes(&self) -> &::std::option::Option<crate::types::FailWorkflowExecutionDecisionAttributes> {
        &self.fail_workflow_execution_decision_attributes
    }
    /// <p>Provides the details of the <code>CancelWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn cancel_workflow_execution_decision_attributes(mut self, input: crate::types::CancelWorkflowExecutionDecisionAttributes) -> Self {
        self.cancel_workflow_execution_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>CancelWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn set_cancel_workflow_execution_decision_attributes(
        mut self,
        input: ::std::option::Option<crate::types::CancelWorkflowExecutionDecisionAttributes>,
    ) -> Self {
        self.cancel_workflow_execution_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>CancelWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn get_cancel_workflow_execution_decision_attributes(
        &self,
    ) -> &::std::option::Option<crate::types::CancelWorkflowExecutionDecisionAttributes> {
        &self.cancel_workflow_execution_decision_attributes
    }
    /// <p>Provides the details of the <code>ContinueAsNewWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn continue_as_new_workflow_execution_decision_attributes(
        mut self,
        input: crate::types::ContinueAsNewWorkflowExecutionDecisionAttributes,
    ) -> Self {
        self.continue_as_new_workflow_execution_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>ContinueAsNewWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn set_continue_as_new_workflow_execution_decision_attributes(
        mut self,
        input: ::std::option::Option<crate::types::ContinueAsNewWorkflowExecutionDecisionAttributes>,
    ) -> Self {
        self.continue_as_new_workflow_execution_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>ContinueAsNewWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn get_continue_as_new_workflow_execution_decision_attributes(
        &self,
    ) -> &::std::option::Option<crate::types::ContinueAsNewWorkflowExecutionDecisionAttributes> {
        &self.continue_as_new_workflow_execution_decision_attributes
    }
    /// <p>Provides the details of the <code>RecordMarker</code> decision. It isn't set for other decision types.</p>
    pub fn record_marker_decision_attributes(mut self, input: crate::types::RecordMarkerDecisionAttributes) -> Self {
        self.record_marker_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>RecordMarker</code> decision. It isn't set for other decision types.</p>
    pub fn set_record_marker_decision_attributes(mut self, input: ::std::option::Option<crate::types::RecordMarkerDecisionAttributes>) -> Self {
        self.record_marker_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>RecordMarker</code> decision. It isn't set for other decision types.</p>
    pub fn get_record_marker_decision_attributes(&self) -> &::std::option::Option<crate::types::RecordMarkerDecisionAttributes> {
        &self.record_marker_decision_attributes
    }
    /// <p>Provides the details of the <code>StartTimer</code> decision. It isn't set for other decision types.</p>
    pub fn start_timer_decision_attributes(mut self, input: crate::types::StartTimerDecisionAttributes) -> Self {
        self.start_timer_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>StartTimer</code> decision. It isn't set for other decision types.</p>
    pub fn set_start_timer_decision_attributes(mut self, input: ::std::option::Option<crate::types::StartTimerDecisionAttributes>) -> Self {
        self.start_timer_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>StartTimer</code> decision. It isn't set for other decision types.</p>
    pub fn get_start_timer_decision_attributes(&self) -> &::std::option::Option<crate::types::StartTimerDecisionAttributes> {
        &self.start_timer_decision_attributes
    }
    /// <p>Provides the details of the <code>CancelTimer</code> decision. It isn't set for other decision types.</p>
    pub fn cancel_timer_decision_attributes(mut self, input: crate::types::CancelTimerDecisionAttributes) -> Self {
        self.cancel_timer_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>CancelTimer</code> decision. It isn't set for other decision types.</p>
    pub fn set_cancel_timer_decision_attributes(mut self, input: ::std::option::Option<crate::types::CancelTimerDecisionAttributes>) -> Self {
        self.cancel_timer_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>CancelTimer</code> decision. It isn't set for other decision types.</p>
    pub fn get_cancel_timer_decision_attributes(&self) -> &::std::option::Option<crate::types::CancelTimerDecisionAttributes> {
        &self.cancel_timer_decision_attributes
    }
    /// <p>Provides the details of the <code>SignalExternalWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn signal_external_workflow_execution_decision_attributes(
        mut self,
        input: crate::types::SignalExternalWorkflowExecutionDecisionAttributes,
    ) -> Self {
        self.signal_external_workflow_execution_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>SignalExternalWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn set_signal_external_workflow_execution_decision_attributes(
        mut self,
        input: ::std::option::Option<crate::types::SignalExternalWorkflowExecutionDecisionAttributes>,
    ) -> Self {
        self.signal_external_workflow_execution_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>SignalExternalWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn get_signal_external_workflow_execution_decision_attributes(
        &self,
    ) -> &::std::option::Option<crate::types::SignalExternalWorkflowExecutionDecisionAttributes> {
        &self.signal_external_workflow_execution_decision_attributes
    }
    /// <p>Provides the details of the <code>RequestCancelExternalWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn request_cancel_external_workflow_execution_decision_attributes(
        mut self,
        input: crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes,
    ) -> Self {
        self.request_cancel_external_workflow_execution_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>RequestCancelExternalWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn set_request_cancel_external_workflow_execution_decision_attributes(
        mut self,
        input: ::std::option::Option<crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes>,
    ) -> Self {
        self.request_cancel_external_workflow_execution_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>RequestCancelExternalWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn get_request_cancel_external_workflow_execution_decision_attributes(
        &self,
    ) -> &::std::option::Option<crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes> {
        &self.request_cancel_external_workflow_execution_decision_attributes
    }
    /// <p>Provides the details of the <code>StartChildWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn start_child_workflow_execution_decision_attributes(mut self, input: crate::types::StartChildWorkflowExecutionDecisionAttributes) -> Self {
        self.start_child_workflow_execution_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>StartChildWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn set_start_child_workflow_execution_decision_attributes(
        mut self,
        input: ::std::option::Option<crate::types::StartChildWorkflowExecutionDecisionAttributes>,
    ) -> Self {
        self.start_child_workflow_execution_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>StartChildWorkflowExecution</code> decision. It isn't set for other decision types.</p>
    pub fn get_start_child_workflow_execution_decision_attributes(
        &self,
    ) -> &::std::option::Option<crate::types::StartChildWorkflowExecutionDecisionAttributes> {
        &self.start_child_workflow_execution_decision_attributes
    }
    /// <p>Provides the details of the <code>ScheduleLambdaFunction</code> decision. It isn't set for other decision types.</p>
    pub fn schedule_lambda_function_decision_attributes(mut self, input: crate::types::ScheduleLambdaFunctionDecisionAttributes) -> Self {
        self.schedule_lambda_function_decision_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the details of the <code>ScheduleLambdaFunction</code> decision. It isn't set for other decision types.</p>
    pub fn set_schedule_lambda_function_decision_attributes(
        mut self,
        input: ::std::option::Option<crate::types::ScheduleLambdaFunctionDecisionAttributes>,
    ) -> Self {
        self.schedule_lambda_function_decision_attributes = input;
        self
    }
    /// <p>Provides the details of the <code>ScheduleLambdaFunction</code> decision. It isn't set for other decision types.</p>
    pub fn get_schedule_lambda_function_decision_attributes(&self) -> &::std::option::Option<crate::types::ScheduleLambdaFunctionDecisionAttributes> {
        &self.schedule_lambda_function_decision_attributes
    }
    /// Consumes the builder and constructs a [`Decision`](crate::types::Decision).
    /// This method will fail if any of the following fields are not set:
    /// - [`decision_type`](crate::types::builders::DecisionBuilder::decision_type)
    pub fn build(self) -> ::std::result::Result<crate::types::Decision, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Decision {
            decision_type: self.decision_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "decision_type",
                    "decision_type was not specified but it is required when building Decision",
                )
            })?,
            schedule_activity_task_decision_attributes: self.schedule_activity_task_decision_attributes,
            request_cancel_activity_task_decision_attributes: self.request_cancel_activity_task_decision_attributes,
            complete_workflow_execution_decision_attributes: self.complete_workflow_execution_decision_attributes,
            fail_workflow_execution_decision_attributes: self.fail_workflow_execution_decision_attributes,
            cancel_workflow_execution_decision_attributes: self.cancel_workflow_execution_decision_attributes,
            continue_as_new_workflow_execution_decision_attributes: self.continue_as_new_workflow_execution_decision_attributes,
            record_marker_decision_attributes: self.record_marker_decision_attributes,
            start_timer_decision_attributes: self.start_timer_decision_attributes,
            cancel_timer_decision_attributes: self.cancel_timer_decision_attributes,
            signal_external_workflow_execution_decision_attributes: self.signal_external_workflow_execution_decision_attributes,
            request_cancel_external_workflow_execution_decision_attributes: self.request_cancel_external_workflow_execution_decision_attributes,
            start_child_workflow_execution_decision_attributes: self.start_child_workflow_execution_decision_attributes,
            schedule_lambda_function_decision_attributes: self.schedule_lambda_function_decision_attributes,
        })
    }
}
