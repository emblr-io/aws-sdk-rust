// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides details of <code>WorkflowExecutionStarted</code> event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkflowExecutionStartedEventAttributes {
    /// <p>The input provided to the workflow execution.</p>
    pub input: ::std::option::Option<::std::string::String>,
    /// <p>The maximum duration for this workflow execution.</p>
    /// <p>The duration is specified in seconds, an integer greater than or equal to <code>0</code>. You can use <code>NONE</code> to specify unlimited duration.</p>
    pub execution_start_to_close_timeout: ::std::option::Option<::std::string::String>,
    /// <p>The maximum duration of decision tasks for this workflow type.</p>
    /// <p>The duration is specified in seconds, an integer greater than or equal to <code>0</code>. You can use <code>NONE</code> to specify unlimited duration.</p>
    pub task_start_to_close_timeout: ::std::option::Option<::std::string::String>,
    /// <p>The policy to use for the child workflow executions if this workflow execution is terminated, by calling the <code>TerminateWorkflowExecution</code> action explicitly or due to an expired timeout.</p>
    /// <p>The supported child policies are:</p>
    /// <ul>
    /// <li>
    /// <p><code>TERMINATE</code> – The child executions are terminated.</p></li>
    /// <li>
    /// <p><code>REQUEST_CANCEL</code> – A request to cancel is attempted for each child execution by recording a <code>WorkflowExecutionCancelRequested</code> event in its history. It is up to the decider to take appropriate actions when it receives an execution history with this event.</p></li>
    /// <li>
    /// <p><code>ABANDON</code> – No action is taken. The child executions continue to run.</p></li>
    /// </ul>
    pub child_policy: crate::types::ChildPolicy,
    /// <p>The name of the task list for scheduling the decision tasks for this workflow execution.</p>
    pub task_list: ::std::option::Option<crate::types::TaskList>,
    /// <p>The priority of the decision tasks in the workflow execution.</p>
    pub task_priority: ::std::option::Option<::std::string::String>,
    /// <p>The workflow type of this execution.</p>
    pub workflow_type: ::std::option::Option<crate::types::WorkflowType>,
    /// <p>The list of tags associated with this workflow execution. An execution can have up to 5 tags.</p>
    pub tag_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>If this workflow execution was started due to a <code>ContinueAsNewWorkflowExecution</code> decision, then it contains the <code>runId</code> of the previous workflow execution that was closed and continued as this execution.</p>
    pub continued_execution_run_id: ::std::option::Option<::std::string::String>,
    /// <p>The source workflow execution that started this workflow execution. The member isn't set if the workflow execution was not started by a workflow.</p>
    pub parent_workflow_execution: ::std::option::Option<crate::types::WorkflowExecution>,
    /// <p>The ID of the <code>StartChildWorkflowExecutionInitiated</code> event corresponding to the <code>StartChildWorkflowExecution</code> <code>Decision</code> to start this workflow execution. The source event with this ID can be found in the history of the source workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub parent_initiated_event_id: i64,
    /// <p>The IAM role attached to the workflow execution.</p>
    pub lambda_role: ::std::option::Option<::std::string::String>,
}
impl WorkflowExecutionStartedEventAttributes {
    /// <p>The input provided to the workflow execution.</p>
    pub fn input(&self) -> ::std::option::Option<&str> {
        self.input.as_deref()
    }
    /// <p>The maximum duration for this workflow execution.</p>
    /// <p>The duration is specified in seconds, an integer greater than or equal to <code>0</code>. You can use <code>NONE</code> to specify unlimited duration.</p>
    pub fn execution_start_to_close_timeout(&self) -> ::std::option::Option<&str> {
        self.execution_start_to_close_timeout.as_deref()
    }
    /// <p>The maximum duration of decision tasks for this workflow type.</p>
    /// <p>The duration is specified in seconds, an integer greater than or equal to <code>0</code>. You can use <code>NONE</code> to specify unlimited duration.</p>
    pub fn task_start_to_close_timeout(&self) -> ::std::option::Option<&str> {
        self.task_start_to_close_timeout.as_deref()
    }
    /// <p>The policy to use for the child workflow executions if this workflow execution is terminated, by calling the <code>TerminateWorkflowExecution</code> action explicitly or due to an expired timeout.</p>
    /// <p>The supported child policies are:</p>
    /// <ul>
    /// <li>
    /// <p><code>TERMINATE</code> – The child executions are terminated.</p></li>
    /// <li>
    /// <p><code>REQUEST_CANCEL</code> – A request to cancel is attempted for each child execution by recording a <code>WorkflowExecutionCancelRequested</code> event in its history. It is up to the decider to take appropriate actions when it receives an execution history with this event.</p></li>
    /// <li>
    /// <p><code>ABANDON</code> – No action is taken. The child executions continue to run.</p></li>
    /// </ul>
    pub fn child_policy(&self) -> &crate::types::ChildPolicy {
        &self.child_policy
    }
    /// <p>The name of the task list for scheduling the decision tasks for this workflow execution.</p>
    pub fn task_list(&self) -> ::std::option::Option<&crate::types::TaskList> {
        self.task_list.as_ref()
    }
    /// <p>The priority of the decision tasks in the workflow execution.</p>
    pub fn task_priority(&self) -> ::std::option::Option<&str> {
        self.task_priority.as_deref()
    }
    /// <p>The workflow type of this execution.</p>
    pub fn workflow_type(&self) -> ::std::option::Option<&crate::types::WorkflowType> {
        self.workflow_type.as_ref()
    }
    /// <p>The list of tags associated with this workflow execution. An execution can have up to 5 tags.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_list.is_none()`.
    pub fn tag_list(&self) -> &[::std::string::String] {
        self.tag_list.as_deref().unwrap_or_default()
    }
    /// <p>If this workflow execution was started due to a <code>ContinueAsNewWorkflowExecution</code> decision, then it contains the <code>runId</code> of the previous workflow execution that was closed and continued as this execution.</p>
    pub fn continued_execution_run_id(&self) -> ::std::option::Option<&str> {
        self.continued_execution_run_id.as_deref()
    }
    /// <p>The source workflow execution that started this workflow execution. The member isn't set if the workflow execution was not started by a workflow.</p>
    pub fn parent_workflow_execution(&self) -> ::std::option::Option<&crate::types::WorkflowExecution> {
        self.parent_workflow_execution.as_ref()
    }
    /// <p>The ID of the <code>StartChildWorkflowExecutionInitiated</code> event corresponding to the <code>StartChildWorkflowExecution</code> <code>Decision</code> to start this workflow execution. The source event with this ID can be found in the history of the source workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn parent_initiated_event_id(&self) -> i64 {
        self.parent_initiated_event_id
    }
    /// <p>The IAM role attached to the workflow execution.</p>
    pub fn lambda_role(&self) -> ::std::option::Option<&str> {
        self.lambda_role.as_deref()
    }
}
impl WorkflowExecutionStartedEventAttributes {
    /// Creates a new builder-style object to manufacture [`WorkflowExecutionStartedEventAttributes`](crate::types::WorkflowExecutionStartedEventAttributes).
    pub fn builder() -> crate::types::builders::WorkflowExecutionStartedEventAttributesBuilder {
        crate::types::builders::WorkflowExecutionStartedEventAttributesBuilder::default()
    }
}

/// A builder for [`WorkflowExecutionStartedEventAttributes`](crate::types::WorkflowExecutionStartedEventAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkflowExecutionStartedEventAttributesBuilder {
    pub(crate) input: ::std::option::Option<::std::string::String>,
    pub(crate) execution_start_to_close_timeout: ::std::option::Option<::std::string::String>,
    pub(crate) task_start_to_close_timeout: ::std::option::Option<::std::string::String>,
    pub(crate) child_policy: ::std::option::Option<crate::types::ChildPolicy>,
    pub(crate) task_list: ::std::option::Option<crate::types::TaskList>,
    pub(crate) task_priority: ::std::option::Option<::std::string::String>,
    pub(crate) workflow_type: ::std::option::Option<crate::types::WorkflowType>,
    pub(crate) tag_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) continued_execution_run_id: ::std::option::Option<::std::string::String>,
    pub(crate) parent_workflow_execution: ::std::option::Option<crate::types::WorkflowExecution>,
    pub(crate) parent_initiated_event_id: ::std::option::Option<i64>,
    pub(crate) lambda_role: ::std::option::Option<::std::string::String>,
}
impl WorkflowExecutionStartedEventAttributesBuilder {
    /// <p>The input provided to the workflow execution.</p>
    pub fn input(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The input provided to the workflow execution.</p>
    pub fn set_input(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input = input;
        self
    }
    /// <p>The input provided to the workflow execution.</p>
    pub fn get_input(&self) -> &::std::option::Option<::std::string::String> {
        &self.input
    }
    /// <p>The maximum duration for this workflow execution.</p>
    /// <p>The duration is specified in seconds, an integer greater than or equal to <code>0</code>. You can use <code>NONE</code> to specify unlimited duration.</p>
    pub fn execution_start_to_close_timeout(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_start_to_close_timeout = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The maximum duration for this workflow execution.</p>
    /// <p>The duration is specified in seconds, an integer greater than or equal to <code>0</code>. You can use <code>NONE</code> to specify unlimited duration.</p>
    pub fn set_execution_start_to_close_timeout(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_start_to_close_timeout = input;
        self
    }
    /// <p>The maximum duration for this workflow execution.</p>
    /// <p>The duration is specified in seconds, an integer greater than or equal to <code>0</code>. You can use <code>NONE</code> to specify unlimited duration.</p>
    pub fn get_execution_start_to_close_timeout(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_start_to_close_timeout
    }
    /// <p>The maximum duration of decision tasks for this workflow type.</p>
    /// <p>The duration is specified in seconds, an integer greater than or equal to <code>0</code>. You can use <code>NONE</code> to specify unlimited duration.</p>
    pub fn task_start_to_close_timeout(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_start_to_close_timeout = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The maximum duration of decision tasks for this workflow type.</p>
    /// <p>The duration is specified in seconds, an integer greater than or equal to <code>0</code>. You can use <code>NONE</code> to specify unlimited duration.</p>
    pub fn set_task_start_to_close_timeout(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_start_to_close_timeout = input;
        self
    }
    /// <p>The maximum duration of decision tasks for this workflow type.</p>
    /// <p>The duration is specified in seconds, an integer greater than or equal to <code>0</code>. You can use <code>NONE</code> to specify unlimited duration.</p>
    pub fn get_task_start_to_close_timeout(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_start_to_close_timeout
    }
    /// <p>The policy to use for the child workflow executions if this workflow execution is terminated, by calling the <code>TerminateWorkflowExecution</code> action explicitly or due to an expired timeout.</p>
    /// <p>The supported child policies are:</p>
    /// <ul>
    /// <li>
    /// <p><code>TERMINATE</code> – The child executions are terminated.</p></li>
    /// <li>
    /// <p><code>REQUEST_CANCEL</code> – A request to cancel is attempted for each child execution by recording a <code>WorkflowExecutionCancelRequested</code> event in its history. It is up to the decider to take appropriate actions when it receives an execution history with this event.</p></li>
    /// <li>
    /// <p><code>ABANDON</code> – No action is taken. The child executions continue to run.</p></li>
    /// </ul>
    /// This field is required.
    pub fn child_policy(mut self, input: crate::types::ChildPolicy) -> Self {
        self.child_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The policy to use for the child workflow executions if this workflow execution is terminated, by calling the <code>TerminateWorkflowExecution</code> action explicitly or due to an expired timeout.</p>
    /// <p>The supported child policies are:</p>
    /// <ul>
    /// <li>
    /// <p><code>TERMINATE</code> – The child executions are terminated.</p></li>
    /// <li>
    /// <p><code>REQUEST_CANCEL</code> – A request to cancel is attempted for each child execution by recording a <code>WorkflowExecutionCancelRequested</code> event in its history. It is up to the decider to take appropriate actions when it receives an execution history with this event.</p></li>
    /// <li>
    /// <p><code>ABANDON</code> – No action is taken. The child executions continue to run.</p></li>
    /// </ul>
    pub fn set_child_policy(mut self, input: ::std::option::Option<crate::types::ChildPolicy>) -> Self {
        self.child_policy = input;
        self
    }
    /// <p>The policy to use for the child workflow executions if this workflow execution is terminated, by calling the <code>TerminateWorkflowExecution</code> action explicitly or due to an expired timeout.</p>
    /// <p>The supported child policies are:</p>
    /// <ul>
    /// <li>
    /// <p><code>TERMINATE</code> – The child executions are terminated.</p></li>
    /// <li>
    /// <p><code>REQUEST_CANCEL</code> – A request to cancel is attempted for each child execution by recording a <code>WorkflowExecutionCancelRequested</code> event in its history. It is up to the decider to take appropriate actions when it receives an execution history with this event.</p></li>
    /// <li>
    /// <p><code>ABANDON</code> – No action is taken. The child executions continue to run.</p></li>
    /// </ul>
    pub fn get_child_policy(&self) -> &::std::option::Option<crate::types::ChildPolicy> {
        &self.child_policy
    }
    /// <p>The name of the task list for scheduling the decision tasks for this workflow execution.</p>
    /// This field is required.
    pub fn task_list(mut self, input: crate::types::TaskList) -> Self {
        self.task_list = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the task list for scheduling the decision tasks for this workflow execution.</p>
    pub fn set_task_list(mut self, input: ::std::option::Option<crate::types::TaskList>) -> Self {
        self.task_list = input;
        self
    }
    /// <p>The name of the task list for scheduling the decision tasks for this workflow execution.</p>
    pub fn get_task_list(&self) -> &::std::option::Option<crate::types::TaskList> {
        &self.task_list
    }
    /// <p>The priority of the decision tasks in the workflow execution.</p>
    pub fn task_priority(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_priority = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The priority of the decision tasks in the workflow execution.</p>
    pub fn set_task_priority(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_priority = input;
        self
    }
    /// <p>The priority of the decision tasks in the workflow execution.</p>
    pub fn get_task_priority(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_priority
    }
    /// <p>The workflow type of this execution.</p>
    /// This field is required.
    pub fn workflow_type(mut self, input: crate::types::WorkflowType) -> Self {
        self.workflow_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The workflow type of this execution.</p>
    pub fn set_workflow_type(mut self, input: ::std::option::Option<crate::types::WorkflowType>) -> Self {
        self.workflow_type = input;
        self
    }
    /// <p>The workflow type of this execution.</p>
    pub fn get_workflow_type(&self) -> &::std::option::Option<crate::types::WorkflowType> {
        &self.workflow_type
    }
    /// Appends an item to `tag_list`.
    ///
    /// To override the contents of this collection use [`set_tag_list`](Self::set_tag_list).
    ///
    /// <p>The list of tags associated with this workflow execution. An execution can have up to 5 tags.</p>
    pub fn tag_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.tag_list.unwrap_or_default();
        v.push(input.into());
        self.tag_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of tags associated with this workflow execution. An execution can have up to 5 tags.</p>
    pub fn set_tag_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.tag_list = input;
        self
    }
    /// <p>The list of tags associated with this workflow execution. An execution can have up to 5 tags.</p>
    pub fn get_tag_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.tag_list
    }
    /// <p>If this workflow execution was started due to a <code>ContinueAsNewWorkflowExecution</code> decision, then it contains the <code>runId</code> of the previous workflow execution that was closed and continued as this execution.</p>
    pub fn continued_execution_run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.continued_execution_run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If this workflow execution was started due to a <code>ContinueAsNewWorkflowExecution</code> decision, then it contains the <code>runId</code> of the previous workflow execution that was closed and continued as this execution.</p>
    pub fn set_continued_execution_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.continued_execution_run_id = input;
        self
    }
    /// <p>If this workflow execution was started due to a <code>ContinueAsNewWorkflowExecution</code> decision, then it contains the <code>runId</code> of the previous workflow execution that was closed and continued as this execution.</p>
    pub fn get_continued_execution_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.continued_execution_run_id
    }
    /// <p>The source workflow execution that started this workflow execution. The member isn't set if the workflow execution was not started by a workflow.</p>
    pub fn parent_workflow_execution(mut self, input: crate::types::WorkflowExecution) -> Self {
        self.parent_workflow_execution = ::std::option::Option::Some(input);
        self
    }
    /// <p>The source workflow execution that started this workflow execution. The member isn't set if the workflow execution was not started by a workflow.</p>
    pub fn set_parent_workflow_execution(mut self, input: ::std::option::Option<crate::types::WorkflowExecution>) -> Self {
        self.parent_workflow_execution = input;
        self
    }
    /// <p>The source workflow execution that started this workflow execution. The member isn't set if the workflow execution was not started by a workflow.</p>
    pub fn get_parent_workflow_execution(&self) -> &::std::option::Option<crate::types::WorkflowExecution> {
        &self.parent_workflow_execution
    }
    /// <p>The ID of the <code>StartChildWorkflowExecutionInitiated</code> event corresponding to the <code>StartChildWorkflowExecution</code> <code>Decision</code> to start this workflow execution. The source event with this ID can be found in the history of the source workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn parent_initiated_event_id(mut self, input: i64) -> Self {
        self.parent_initiated_event_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the <code>StartChildWorkflowExecutionInitiated</code> event corresponding to the <code>StartChildWorkflowExecution</code> <code>Decision</code> to start this workflow execution. The source event with this ID can be found in the history of the source workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn set_parent_initiated_event_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.parent_initiated_event_id = input;
        self
    }
    /// <p>The ID of the <code>StartChildWorkflowExecutionInitiated</code> event corresponding to the <code>StartChildWorkflowExecution</code> <code>Decision</code> to start this workflow execution. The source event with this ID can be found in the history of the source workflow execution. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn get_parent_initiated_event_id(&self) -> &::std::option::Option<i64> {
        &self.parent_initiated_event_id
    }
    /// <p>The IAM role attached to the workflow execution.</p>
    pub fn lambda_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lambda_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role attached to the workflow execution.</p>
    pub fn set_lambda_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lambda_role = input;
        self
    }
    /// <p>The IAM role attached to the workflow execution.</p>
    pub fn get_lambda_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.lambda_role
    }
    /// Consumes the builder and constructs a [`WorkflowExecutionStartedEventAttributes`](crate::types::WorkflowExecutionStartedEventAttributes).
    /// This method will fail if any of the following fields are not set:
    /// - [`child_policy`](crate::types::builders::WorkflowExecutionStartedEventAttributesBuilder::child_policy)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::WorkflowExecutionStartedEventAttributes, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::WorkflowExecutionStartedEventAttributes {
            input: self.input,
            execution_start_to_close_timeout: self.execution_start_to_close_timeout,
            task_start_to_close_timeout: self.task_start_to_close_timeout,
            child_policy: self.child_policy.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "child_policy",
                    "child_policy was not specified but it is required when building WorkflowExecutionStartedEventAttributes",
                )
            })?,
            task_list: self.task_list,
            task_priority: self.task_priority,
            workflow_type: self.workflow_type,
            tag_list: self.tag_list,
            continued_execution_run_id: self.continued_execution_run_id,
            parent_workflow_execution: self.parent_workflow_execution,
            parent_initiated_event_id: self.parent_initiated_event_id.unwrap_or_default(),
            lambda_role: self.lambda_role,
        })
    }
}
