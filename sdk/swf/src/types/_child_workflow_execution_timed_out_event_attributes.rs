// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the details of the <code>ChildWorkflowExecutionTimedOut</code> event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChildWorkflowExecutionTimedOutEventAttributes {
    /// <p>The child workflow execution that timed out.</p>
    pub workflow_execution: ::std::option::Option<crate::types::WorkflowExecution>,
    /// <p>The type of the child workflow execution.</p>
    pub workflow_type: ::std::option::Option<crate::types::WorkflowType>,
    /// <p>The type of the timeout that caused the child workflow execution to time out.</p>
    pub timeout_type: crate::types::WorkflowExecutionTimeoutType,
    /// <p>The ID of the <code>StartChildWorkflowExecutionInitiated</code> event corresponding to the <code>StartChildWorkflowExecution</code> <code>Decision</code> to start this child workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub initiated_event_id: i64,
    /// <p>The ID of the <code>ChildWorkflowExecutionStarted</code> event recorded when this child workflow execution was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub started_event_id: i64,
}
impl ChildWorkflowExecutionTimedOutEventAttributes {
    /// <p>The child workflow execution that timed out.</p>
    pub fn workflow_execution(&self) -> ::std::option::Option<&crate::types::WorkflowExecution> {
        self.workflow_execution.as_ref()
    }
    /// <p>The type of the child workflow execution.</p>
    pub fn workflow_type(&self) -> ::std::option::Option<&crate::types::WorkflowType> {
        self.workflow_type.as_ref()
    }
    /// <p>The type of the timeout that caused the child workflow execution to time out.</p>
    pub fn timeout_type(&self) -> &crate::types::WorkflowExecutionTimeoutType {
        &self.timeout_type
    }
    /// <p>The ID of the <code>StartChildWorkflowExecutionInitiated</code> event corresponding to the <code>StartChildWorkflowExecution</code> <code>Decision</code> to start this child workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn initiated_event_id(&self) -> i64 {
        self.initiated_event_id
    }
    /// <p>The ID of the <code>ChildWorkflowExecutionStarted</code> event recorded when this child workflow execution was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn started_event_id(&self) -> i64 {
        self.started_event_id
    }
}
impl ChildWorkflowExecutionTimedOutEventAttributes {
    /// Creates a new builder-style object to manufacture [`ChildWorkflowExecutionTimedOutEventAttributes`](crate::types::ChildWorkflowExecutionTimedOutEventAttributes).
    pub fn builder() -> crate::types::builders::ChildWorkflowExecutionTimedOutEventAttributesBuilder {
        crate::types::builders::ChildWorkflowExecutionTimedOutEventAttributesBuilder::default()
    }
}

/// A builder for [`ChildWorkflowExecutionTimedOutEventAttributes`](crate::types::ChildWorkflowExecutionTimedOutEventAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChildWorkflowExecutionTimedOutEventAttributesBuilder {
    pub(crate) workflow_execution: ::std::option::Option<crate::types::WorkflowExecution>,
    pub(crate) workflow_type: ::std::option::Option<crate::types::WorkflowType>,
    pub(crate) timeout_type: ::std::option::Option<crate::types::WorkflowExecutionTimeoutType>,
    pub(crate) initiated_event_id: ::std::option::Option<i64>,
    pub(crate) started_event_id: ::std::option::Option<i64>,
}
impl ChildWorkflowExecutionTimedOutEventAttributesBuilder {
    /// <p>The child workflow execution that timed out.</p>
    /// This field is required.
    pub fn workflow_execution(mut self, input: crate::types::WorkflowExecution) -> Self {
        self.workflow_execution = ::std::option::Option::Some(input);
        self
    }
    /// <p>The child workflow execution that timed out.</p>
    pub fn set_workflow_execution(mut self, input: ::std::option::Option<crate::types::WorkflowExecution>) -> Self {
        self.workflow_execution = input;
        self
    }
    /// <p>The child workflow execution that timed out.</p>
    pub fn get_workflow_execution(&self) -> &::std::option::Option<crate::types::WorkflowExecution> {
        &self.workflow_execution
    }
    /// <p>The type of the child workflow execution.</p>
    /// This field is required.
    pub fn workflow_type(mut self, input: crate::types::WorkflowType) -> Self {
        self.workflow_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the child workflow execution.</p>
    pub fn set_workflow_type(mut self, input: ::std::option::Option<crate::types::WorkflowType>) -> Self {
        self.workflow_type = input;
        self
    }
    /// <p>The type of the child workflow execution.</p>
    pub fn get_workflow_type(&self) -> &::std::option::Option<crate::types::WorkflowType> {
        &self.workflow_type
    }
    /// <p>The type of the timeout that caused the child workflow execution to time out.</p>
    /// This field is required.
    pub fn timeout_type(mut self, input: crate::types::WorkflowExecutionTimeoutType) -> Self {
        self.timeout_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the timeout that caused the child workflow execution to time out.</p>
    pub fn set_timeout_type(mut self, input: ::std::option::Option<crate::types::WorkflowExecutionTimeoutType>) -> Self {
        self.timeout_type = input;
        self
    }
    /// <p>The type of the timeout that caused the child workflow execution to time out.</p>
    pub fn get_timeout_type(&self) -> &::std::option::Option<crate::types::WorkflowExecutionTimeoutType> {
        &self.timeout_type
    }
    /// <p>The ID of the <code>StartChildWorkflowExecutionInitiated</code> event corresponding to the <code>StartChildWorkflowExecution</code> <code>Decision</code> to start this child workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    /// This field is required.
    pub fn initiated_event_id(mut self, input: i64) -> Self {
        self.initiated_event_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the <code>StartChildWorkflowExecutionInitiated</code> event corresponding to the <code>StartChildWorkflowExecution</code> <code>Decision</code> to start this child workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn set_initiated_event_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.initiated_event_id = input;
        self
    }
    /// <p>The ID of the <code>StartChildWorkflowExecutionInitiated</code> event corresponding to the <code>StartChildWorkflowExecution</code> <code>Decision</code> to start this child workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn get_initiated_event_id(&self) -> &::std::option::Option<i64> {
        &self.initiated_event_id
    }
    /// <p>The ID of the <code>ChildWorkflowExecutionStarted</code> event recorded when this child workflow execution was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    /// This field is required.
    pub fn started_event_id(mut self, input: i64) -> Self {
        self.started_event_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the <code>ChildWorkflowExecutionStarted</code> event recorded when this child workflow execution was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn set_started_event_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.started_event_id = input;
        self
    }
    /// <p>The ID of the <code>ChildWorkflowExecutionStarted</code> event recorded when this child workflow execution was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn get_started_event_id(&self) -> &::std::option::Option<i64> {
        &self.started_event_id
    }
    /// Consumes the builder and constructs a [`ChildWorkflowExecutionTimedOutEventAttributes`](crate::types::ChildWorkflowExecutionTimedOutEventAttributes).
    /// This method will fail if any of the following fields are not set:
    /// - [`timeout_type`](crate::types::builders::ChildWorkflowExecutionTimedOutEventAttributesBuilder::timeout_type)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::ChildWorkflowExecutionTimedOutEventAttributes, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ChildWorkflowExecutionTimedOutEventAttributes {
            workflow_execution: self.workflow_execution,
            workflow_type: self.workflow_type,
            timeout_type: self.timeout_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "timeout_type",
                    "timeout_type was not specified but it is required when building ChildWorkflowExecutionTimedOutEventAttributes",
                )
            })?,
            initiated_event_id: self.initiated_event_id.unwrap_or_default(),
            started_event_id: self.started_event_id.unwrap_or_default(),
        })
    }
}
