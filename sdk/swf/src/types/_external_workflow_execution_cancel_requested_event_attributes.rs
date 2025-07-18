// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the details of the <code>ExternalWorkflowExecutionCancelRequested</code> event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExternalWorkflowExecutionCancelRequestedEventAttributes {
    /// <p>The external workflow execution to which the cancellation request was delivered.</p>
    pub workflow_execution: ::std::option::Option<crate::types::WorkflowExecution>,
    /// <p>The ID of the <code>RequestCancelExternalWorkflowExecutionInitiated</code> event corresponding to the <code>RequestCancelExternalWorkflowExecution</code> decision to cancel this external workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub initiated_event_id: i64,
}
impl ExternalWorkflowExecutionCancelRequestedEventAttributes {
    /// <p>The external workflow execution to which the cancellation request was delivered.</p>
    pub fn workflow_execution(&self) -> ::std::option::Option<&crate::types::WorkflowExecution> {
        self.workflow_execution.as_ref()
    }
    /// <p>The ID of the <code>RequestCancelExternalWorkflowExecutionInitiated</code> event corresponding to the <code>RequestCancelExternalWorkflowExecution</code> decision to cancel this external workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn initiated_event_id(&self) -> i64 {
        self.initiated_event_id
    }
}
impl ExternalWorkflowExecutionCancelRequestedEventAttributes {
    /// Creates a new builder-style object to manufacture [`ExternalWorkflowExecutionCancelRequestedEventAttributes`](crate::types::ExternalWorkflowExecutionCancelRequestedEventAttributes).
    pub fn builder() -> crate::types::builders::ExternalWorkflowExecutionCancelRequestedEventAttributesBuilder {
        crate::types::builders::ExternalWorkflowExecutionCancelRequestedEventAttributesBuilder::default()
    }
}

/// A builder for [`ExternalWorkflowExecutionCancelRequestedEventAttributes`](crate::types::ExternalWorkflowExecutionCancelRequestedEventAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExternalWorkflowExecutionCancelRequestedEventAttributesBuilder {
    pub(crate) workflow_execution: ::std::option::Option<crate::types::WorkflowExecution>,
    pub(crate) initiated_event_id: ::std::option::Option<i64>,
}
impl ExternalWorkflowExecutionCancelRequestedEventAttributesBuilder {
    /// <p>The external workflow execution to which the cancellation request was delivered.</p>
    /// This field is required.
    pub fn workflow_execution(mut self, input: crate::types::WorkflowExecution) -> Self {
        self.workflow_execution = ::std::option::Option::Some(input);
        self
    }
    /// <p>The external workflow execution to which the cancellation request was delivered.</p>
    pub fn set_workflow_execution(mut self, input: ::std::option::Option<crate::types::WorkflowExecution>) -> Self {
        self.workflow_execution = input;
        self
    }
    /// <p>The external workflow execution to which the cancellation request was delivered.</p>
    pub fn get_workflow_execution(&self) -> &::std::option::Option<crate::types::WorkflowExecution> {
        &self.workflow_execution
    }
    /// <p>The ID of the <code>RequestCancelExternalWorkflowExecutionInitiated</code> event corresponding to the <code>RequestCancelExternalWorkflowExecution</code> decision to cancel this external workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    /// This field is required.
    pub fn initiated_event_id(mut self, input: i64) -> Self {
        self.initiated_event_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the <code>RequestCancelExternalWorkflowExecutionInitiated</code> event corresponding to the <code>RequestCancelExternalWorkflowExecution</code> decision to cancel this external workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn set_initiated_event_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.initiated_event_id = input;
        self
    }
    /// <p>The ID of the <code>RequestCancelExternalWorkflowExecutionInitiated</code> event corresponding to the <code>RequestCancelExternalWorkflowExecution</code> decision to cancel this external workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn get_initiated_event_id(&self) -> &::std::option::Option<i64> {
        &self.initiated_event_id
    }
    /// Consumes the builder and constructs a [`ExternalWorkflowExecutionCancelRequestedEventAttributes`](crate::types::ExternalWorkflowExecutionCancelRequestedEventAttributes).
    pub fn build(self) -> crate::types::ExternalWorkflowExecutionCancelRequestedEventAttributes {
        crate::types::ExternalWorkflowExecutionCancelRequestedEventAttributes {
            workflow_execution: self.workflow_execution,
            initiated_event_id: self.initiated_event_id.unwrap_or_default(),
        }
    }
}
