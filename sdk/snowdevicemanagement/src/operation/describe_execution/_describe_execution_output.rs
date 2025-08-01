// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeExecutionOutput {
    /// <p>The ID of the task being executed on the device.</p>
    pub task_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the execution.</p>
    pub execution_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the managed device that the task is being executed on.</p>
    pub managed_device_id: ::std::option::Option<::std::string::String>,
    /// <p>The current state of the execution.</p>
    pub state: ::std::option::Option<crate::types::ExecutionState>,
    /// <p>When the execution began.</p>
    pub started_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>When the status of the execution was last updated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeExecutionOutput {
    /// <p>The ID of the task being executed on the device.</p>
    pub fn task_id(&self) -> ::std::option::Option<&str> {
        self.task_id.as_deref()
    }
    /// <p>The ID of the execution.</p>
    pub fn execution_id(&self) -> ::std::option::Option<&str> {
        self.execution_id.as_deref()
    }
    /// <p>The ID of the managed device that the task is being executed on.</p>
    pub fn managed_device_id(&self) -> ::std::option::Option<&str> {
        self.managed_device_id.as_deref()
    }
    /// <p>The current state of the execution.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::ExecutionState> {
        self.state.as_ref()
    }
    /// <p>When the execution began.</p>
    pub fn started_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.started_at.as_ref()
    }
    /// <p>When the status of the execution was last updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeExecutionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeExecutionOutput {
    /// Creates a new builder-style object to manufacture [`DescribeExecutionOutput`](crate::operation::describe_execution::DescribeExecutionOutput).
    pub fn builder() -> crate::operation::describe_execution::builders::DescribeExecutionOutputBuilder {
        crate::operation::describe_execution::builders::DescribeExecutionOutputBuilder::default()
    }
}

/// A builder for [`DescribeExecutionOutput`](crate::operation::describe_execution::DescribeExecutionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeExecutionOutputBuilder {
    pub(crate) task_id: ::std::option::Option<::std::string::String>,
    pub(crate) execution_id: ::std::option::Option<::std::string::String>,
    pub(crate) managed_device_id: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::ExecutionState>,
    pub(crate) started_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeExecutionOutputBuilder {
    /// <p>The ID of the task being executed on the device.</p>
    pub fn task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the task being executed on the device.</p>
    pub fn set_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_id = input;
        self
    }
    /// <p>The ID of the task being executed on the device.</p>
    pub fn get_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_id
    }
    /// <p>The ID of the execution.</p>
    pub fn execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the execution.</p>
    pub fn set_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_id = input;
        self
    }
    /// <p>The ID of the execution.</p>
    pub fn get_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_id
    }
    /// <p>The ID of the managed device that the task is being executed on.</p>
    pub fn managed_device_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.managed_device_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the managed device that the task is being executed on.</p>
    pub fn set_managed_device_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.managed_device_id = input;
        self
    }
    /// <p>The ID of the managed device that the task is being executed on.</p>
    pub fn get_managed_device_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.managed_device_id
    }
    /// <p>The current state of the execution.</p>
    pub fn state(mut self, input: crate::types::ExecutionState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current state of the execution.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::ExecutionState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The current state of the execution.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::ExecutionState> {
        &self.state
    }
    /// <p>When the execution began.</p>
    pub fn started_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.started_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the execution began.</p>
    pub fn set_started_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.started_at = input;
        self
    }
    /// <p>When the execution began.</p>
    pub fn get_started_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.started_at
    }
    /// <p>When the status of the execution was last updated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the status of the execution was last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>When the status of the execution was last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeExecutionOutput`](crate::operation::describe_execution::DescribeExecutionOutput).
    pub fn build(self) -> crate::operation::describe_execution::DescribeExecutionOutput {
        crate::operation::describe_execution::DescribeExecutionOutput {
            task_id: self.task_id,
            execution_id: self.execution_id,
            managed_device_id: self.managed_device_id,
            state: self.state,
            started_at: self.started_at,
            last_updated_at: self.last_updated_at,
            _request_id: self._request_id,
        }
    }
}
