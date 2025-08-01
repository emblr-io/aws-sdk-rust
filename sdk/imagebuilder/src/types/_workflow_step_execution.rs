// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains runtime details for an instance of a workflow that ran for the associated image build version.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkflowStepExecution {
    /// <p>Uniquely identifies the workflow step that ran for the associated image build version.</p>
    pub step_execution_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the image build version that ran the workflow.</p>
    pub image_build_version_arn: ::std::option::Option<::std::string::String>,
    /// <p>Uniquely identifies the runtime instance of the workflow that contains the workflow step that ran for the associated image build version.</p>
    pub workflow_execution_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the workflow resource that ran.</p>
    pub workflow_build_version_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the workflow step.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the step action.</p>
    pub action: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp when the workflow step started.</p>
    pub start_time: ::std::option::Option<::std::string::String>,
}
impl WorkflowStepExecution {
    /// <p>Uniquely identifies the workflow step that ran for the associated image build version.</p>
    pub fn step_execution_id(&self) -> ::std::option::Option<&str> {
        self.step_execution_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the image build version that ran the workflow.</p>
    pub fn image_build_version_arn(&self) -> ::std::option::Option<&str> {
        self.image_build_version_arn.as_deref()
    }
    /// <p>Uniquely identifies the runtime instance of the workflow that contains the workflow step that ran for the associated image build version.</p>
    pub fn workflow_execution_id(&self) -> ::std::option::Option<&str> {
        self.workflow_execution_id.as_deref()
    }
    /// <p>The ARN of the workflow resource that ran.</p>
    pub fn workflow_build_version_arn(&self) -> ::std::option::Option<&str> {
        self.workflow_build_version_arn.as_deref()
    }
    /// <p>The name of the workflow step.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The name of the step action.</p>
    pub fn action(&self) -> ::std::option::Option<&str> {
        self.action.as_deref()
    }
    /// <p>The timestamp when the workflow step started.</p>
    pub fn start_time(&self) -> ::std::option::Option<&str> {
        self.start_time.as_deref()
    }
}
impl WorkflowStepExecution {
    /// Creates a new builder-style object to manufacture [`WorkflowStepExecution`](crate::types::WorkflowStepExecution).
    pub fn builder() -> crate::types::builders::WorkflowStepExecutionBuilder {
        crate::types::builders::WorkflowStepExecutionBuilder::default()
    }
}

/// A builder for [`WorkflowStepExecution`](crate::types::WorkflowStepExecution).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkflowStepExecutionBuilder {
    pub(crate) step_execution_id: ::std::option::Option<::std::string::String>,
    pub(crate) image_build_version_arn: ::std::option::Option<::std::string::String>,
    pub(crate) workflow_execution_id: ::std::option::Option<::std::string::String>,
    pub(crate) workflow_build_version_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) action: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<::std::string::String>,
}
impl WorkflowStepExecutionBuilder {
    /// <p>Uniquely identifies the workflow step that ran for the associated image build version.</p>
    pub fn step_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.step_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Uniquely identifies the workflow step that ran for the associated image build version.</p>
    pub fn set_step_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.step_execution_id = input;
        self
    }
    /// <p>Uniquely identifies the workflow step that ran for the associated image build version.</p>
    pub fn get_step_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.step_execution_id
    }
    /// <p>The Amazon Resource Name (ARN) of the image build version that ran the workflow.</p>
    pub fn image_build_version_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_build_version_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image build version that ran the workflow.</p>
    pub fn set_image_build_version_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_build_version_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image build version that ran the workflow.</p>
    pub fn get_image_build_version_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_build_version_arn
    }
    /// <p>Uniquely identifies the runtime instance of the workflow that contains the workflow step that ran for the associated image build version.</p>
    pub fn workflow_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workflow_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Uniquely identifies the runtime instance of the workflow that contains the workflow step that ran for the associated image build version.</p>
    pub fn set_workflow_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workflow_execution_id = input;
        self
    }
    /// <p>Uniquely identifies the runtime instance of the workflow that contains the workflow step that ran for the associated image build version.</p>
    pub fn get_workflow_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workflow_execution_id
    }
    /// <p>The ARN of the workflow resource that ran.</p>
    pub fn workflow_build_version_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workflow_build_version_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the workflow resource that ran.</p>
    pub fn set_workflow_build_version_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workflow_build_version_arn = input;
        self
    }
    /// <p>The ARN of the workflow resource that ran.</p>
    pub fn get_workflow_build_version_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.workflow_build_version_arn
    }
    /// <p>The name of the workflow step.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the workflow step.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the workflow step.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The name of the step action.</p>
    pub fn action(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the step action.</p>
    pub fn set_action(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action = input;
        self
    }
    /// <p>The name of the step action.</p>
    pub fn get_action(&self) -> &::std::option::Option<::std::string::String> {
        &self.action
    }
    /// <p>The timestamp when the workflow step started.</p>
    pub fn start_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The timestamp when the workflow step started.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The timestamp when the workflow step started.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_time
    }
    /// Consumes the builder and constructs a [`WorkflowStepExecution`](crate::types::WorkflowStepExecution).
    pub fn build(self) -> crate::types::WorkflowStepExecution {
        crate::types::WorkflowStepExecution {
            step_execution_id: self.step_execution_id,
            image_build_version_arn: self.image_build_version_arn,
            workflow_execution_id: self.workflow_execution_id,
            workflow_build_version_arn: self.workflow_build_version_arn,
            name: self.name,
            action: self.action,
            start_time: self.start_time,
        }
    }
}
