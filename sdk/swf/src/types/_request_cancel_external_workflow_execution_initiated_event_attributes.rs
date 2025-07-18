// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the details of the <code>RequestCancelExternalWorkflowExecutionInitiated</code> event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RequestCancelExternalWorkflowExecutionInitiatedEventAttributes {
    /// <p>The <code>workflowId</code> of the external workflow execution to be canceled.</p>
    pub workflow_id: ::std::string::String,
    /// <p>The <code>runId</code> of the external workflow execution to be canceled.</p>
    pub run_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the <code>DecisionTaskCompleted</code> event corresponding to the decision task that resulted in the <code>RequestCancelExternalWorkflowExecution</code> decision for this cancellation request. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub decision_task_completed_event_id: i64,
    /// <p>Data attached to the event that can be used by the decider in subsequent workflow tasks.</p>
    pub control: ::std::option::Option<::std::string::String>,
}
impl RequestCancelExternalWorkflowExecutionInitiatedEventAttributes {
    /// <p>The <code>workflowId</code> of the external workflow execution to be canceled.</p>
    pub fn workflow_id(&self) -> &str {
        use std::ops::Deref;
        self.workflow_id.deref()
    }
    /// <p>The <code>runId</code> of the external workflow execution to be canceled.</p>
    pub fn run_id(&self) -> ::std::option::Option<&str> {
        self.run_id.as_deref()
    }
    /// <p>The ID of the <code>DecisionTaskCompleted</code> event corresponding to the decision task that resulted in the <code>RequestCancelExternalWorkflowExecution</code> decision for this cancellation request. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn decision_task_completed_event_id(&self) -> i64 {
        self.decision_task_completed_event_id
    }
    /// <p>Data attached to the event that can be used by the decider in subsequent workflow tasks.</p>
    pub fn control(&self) -> ::std::option::Option<&str> {
        self.control.as_deref()
    }
}
impl RequestCancelExternalWorkflowExecutionInitiatedEventAttributes {
    /// Creates a new builder-style object to manufacture [`RequestCancelExternalWorkflowExecutionInitiatedEventAttributes`](crate::types::RequestCancelExternalWorkflowExecutionInitiatedEventAttributes).
    pub fn builder() -> crate::types::builders::RequestCancelExternalWorkflowExecutionInitiatedEventAttributesBuilder {
        crate::types::builders::RequestCancelExternalWorkflowExecutionInitiatedEventAttributesBuilder::default()
    }
}

/// A builder for [`RequestCancelExternalWorkflowExecutionInitiatedEventAttributes`](crate::types::RequestCancelExternalWorkflowExecutionInitiatedEventAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RequestCancelExternalWorkflowExecutionInitiatedEventAttributesBuilder {
    pub(crate) workflow_id: ::std::option::Option<::std::string::String>,
    pub(crate) run_id: ::std::option::Option<::std::string::String>,
    pub(crate) decision_task_completed_event_id: ::std::option::Option<i64>,
    pub(crate) control: ::std::option::Option<::std::string::String>,
}
impl RequestCancelExternalWorkflowExecutionInitiatedEventAttributesBuilder {
    /// <p>The <code>workflowId</code> of the external workflow execution to be canceled.</p>
    /// This field is required.
    pub fn workflow_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workflow_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>workflowId</code> of the external workflow execution to be canceled.</p>
    pub fn set_workflow_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workflow_id = input;
        self
    }
    /// <p>The <code>workflowId</code> of the external workflow execution to be canceled.</p>
    pub fn get_workflow_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workflow_id
    }
    /// <p>The <code>runId</code> of the external workflow execution to be canceled.</p>
    pub fn run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>runId</code> of the external workflow execution to be canceled.</p>
    pub fn set_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.run_id = input;
        self
    }
    /// <p>The <code>runId</code> of the external workflow execution to be canceled.</p>
    pub fn get_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.run_id
    }
    /// <p>The ID of the <code>DecisionTaskCompleted</code> event corresponding to the decision task that resulted in the <code>RequestCancelExternalWorkflowExecution</code> decision for this cancellation request. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    /// This field is required.
    pub fn decision_task_completed_event_id(mut self, input: i64) -> Self {
        self.decision_task_completed_event_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the <code>DecisionTaskCompleted</code> event corresponding to the decision task that resulted in the <code>RequestCancelExternalWorkflowExecution</code> decision for this cancellation request. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn set_decision_task_completed_event_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.decision_task_completed_event_id = input;
        self
    }
    /// <p>The ID of the <code>DecisionTaskCompleted</code> event corresponding to the decision task that resulted in the <code>RequestCancelExternalWorkflowExecution</code> decision for this cancellation request. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn get_decision_task_completed_event_id(&self) -> &::std::option::Option<i64> {
        &self.decision_task_completed_event_id
    }
    /// <p>Data attached to the event that can be used by the decider in subsequent workflow tasks.</p>
    pub fn control(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.control = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Data attached to the event that can be used by the decider in subsequent workflow tasks.</p>
    pub fn set_control(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.control = input;
        self
    }
    /// <p>Data attached to the event that can be used by the decider in subsequent workflow tasks.</p>
    pub fn get_control(&self) -> &::std::option::Option<::std::string::String> {
        &self.control
    }
    /// Consumes the builder and constructs a [`RequestCancelExternalWorkflowExecutionInitiatedEventAttributes`](crate::types::RequestCancelExternalWorkflowExecutionInitiatedEventAttributes).
    /// This method will fail if any of the following fields are not set:
    /// - [`workflow_id`](crate::types::builders::RequestCancelExternalWorkflowExecutionInitiatedEventAttributesBuilder::workflow_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::types::RequestCancelExternalWorkflowExecutionInitiatedEventAttributes,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::types::RequestCancelExternalWorkflowExecutionInitiatedEventAttributes {
            workflow_id: self.workflow_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "workflow_id",
                    "workflow_id was not specified but it is required when building RequestCancelExternalWorkflowExecutionInitiatedEventAttributes",
                )
            })?,
            run_id: self.run_id,
            decision_task_completed_event_id: self.decision_task_completed_event_id.unwrap_or_default(),
            control: self.control,
        })
    }
}
