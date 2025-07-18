// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the details of the <code>WorkflowExecutionCanceled</code> event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkflowExecutionCanceledEventAttributes {
    /// <p>The details of the cancellation.</p>
    pub details: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the <code>DecisionTaskCompleted</code> event corresponding to the decision task that resulted in the <code>CancelWorkflowExecution</code> decision for this cancellation request. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub decision_task_completed_event_id: i64,
}
impl WorkflowExecutionCanceledEventAttributes {
    /// <p>The details of the cancellation.</p>
    pub fn details(&self) -> ::std::option::Option<&str> {
        self.details.as_deref()
    }
    /// <p>The ID of the <code>DecisionTaskCompleted</code> event corresponding to the decision task that resulted in the <code>CancelWorkflowExecution</code> decision for this cancellation request. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn decision_task_completed_event_id(&self) -> i64 {
        self.decision_task_completed_event_id
    }
}
impl WorkflowExecutionCanceledEventAttributes {
    /// Creates a new builder-style object to manufacture [`WorkflowExecutionCanceledEventAttributes`](crate::types::WorkflowExecutionCanceledEventAttributes).
    pub fn builder() -> crate::types::builders::WorkflowExecutionCanceledEventAttributesBuilder {
        crate::types::builders::WorkflowExecutionCanceledEventAttributesBuilder::default()
    }
}

/// A builder for [`WorkflowExecutionCanceledEventAttributes`](crate::types::WorkflowExecutionCanceledEventAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkflowExecutionCanceledEventAttributesBuilder {
    pub(crate) details: ::std::option::Option<::std::string::String>,
    pub(crate) decision_task_completed_event_id: ::std::option::Option<i64>,
}
impl WorkflowExecutionCanceledEventAttributesBuilder {
    /// <p>The details of the cancellation.</p>
    pub fn details(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.details = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The details of the cancellation.</p>
    pub fn set_details(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.details = input;
        self
    }
    /// <p>The details of the cancellation.</p>
    pub fn get_details(&self) -> &::std::option::Option<::std::string::String> {
        &self.details
    }
    /// <p>The ID of the <code>DecisionTaskCompleted</code> event corresponding to the decision task that resulted in the <code>CancelWorkflowExecution</code> decision for this cancellation request. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    /// This field is required.
    pub fn decision_task_completed_event_id(mut self, input: i64) -> Self {
        self.decision_task_completed_event_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the <code>DecisionTaskCompleted</code> event corresponding to the decision task that resulted in the <code>CancelWorkflowExecution</code> decision for this cancellation request. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn set_decision_task_completed_event_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.decision_task_completed_event_id = input;
        self
    }
    /// <p>The ID of the <code>DecisionTaskCompleted</code> event corresponding to the decision task that resulted in the <code>CancelWorkflowExecution</code> decision for this cancellation request. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn get_decision_task_completed_event_id(&self) -> &::std::option::Option<i64> {
        &self.decision_task_completed_event_id
    }
    /// Consumes the builder and constructs a [`WorkflowExecutionCanceledEventAttributes`](crate::types::WorkflowExecutionCanceledEventAttributes).
    pub fn build(self) -> crate::types::WorkflowExecutionCanceledEventAttributes {
        crate::types::WorkflowExecutionCanceledEventAttributes {
            details: self.details,
            decision_task_completed_event_id: self.decision_task_completed_event_id.unwrap_or_default(),
        }
    }
}
