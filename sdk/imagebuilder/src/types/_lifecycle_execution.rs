// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains metadata from a runtime instance of a lifecycle policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LifecycleExecution {
    /// <p>Identifies the lifecycle policy runtime instance.</p>
    pub lifecycle_execution_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the lifecycle policy that ran.</p>
    pub lifecycle_policy_arn: ::std::option::Option<::std::string::String>,
    /// <p>Contains information about associated resources that are identified for action by the runtime instance of the lifecycle policy.</p>
    pub resources_impacted_summary: ::std::option::Option<crate::types::LifecycleExecutionResourcesImpactedSummary>,
    /// <p>Runtime state that reports if the policy action ran successfully, failed, or was skipped.</p>
    pub state: ::std::option::Option<crate::types::LifecycleExecutionState>,
    /// <p>The timestamp when the lifecycle runtime instance started.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp when the lifecycle runtime instance completed.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl LifecycleExecution {
    /// <p>Identifies the lifecycle policy runtime instance.</p>
    pub fn lifecycle_execution_id(&self) -> ::std::option::Option<&str> {
        self.lifecycle_execution_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the lifecycle policy that ran.</p>
    pub fn lifecycle_policy_arn(&self) -> ::std::option::Option<&str> {
        self.lifecycle_policy_arn.as_deref()
    }
    /// <p>Contains information about associated resources that are identified for action by the runtime instance of the lifecycle policy.</p>
    pub fn resources_impacted_summary(&self) -> ::std::option::Option<&crate::types::LifecycleExecutionResourcesImpactedSummary> {
        self.resources_impacted_summary.as_ref()
    }
    /// <p>Runtime state that reports if the policy action ran successfully, failed, or was skipped.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::LifecycleExecutionState> {
        self.state.as_ref()
    }
    /// <p>The timestamp when the lifecycle runtime instance started.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The timestamp when the lifecycle runtime instance completed.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
}
impl LifecycleExecution {
    /// Creates a new builder-style object to manufacture [`LifecycleExecution`](crate::types::LifecycleExecution).
    pub fn builder() -> crate::types::builders::LifecycleExecutionBuilder {
        crate::types::builders::LifecycleExecutionBuilder::default()
    }
}

/// A builder for [`LifecycleExecution`](crate::types::LifecycleExecution).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LifecycleExecutionBuilder {
    pub(crate) lifecycle_execution_id: ::std::option::Option<::std::string::String>,
    pub(crate) lifecycle_policy_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resources_impacted_summary: ::std::option::Option<crate::types::LifecycleExecutionResourcesImpactedSummary>,
    pub(crate) state: ::std::option::Option<crate::types::LifecycleExecutionState>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl LifecycleExecutionBuilder {
    /// <p>Identifies the lifecycle policy runtime instance.</p>
    pub fn lifecycle_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifies the lifecycle policy runtime instance.</p>
    pub fn set_lifecycle_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_execution_id = input;
        self
    }
    /// <p>Identifies the lifecycle policy runtime instance.</p>
    pub fn get_lifecycle_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_execution_id
    }
    /// <p>The Amazon Resource Name (ARN) of the lifecycle policy that ran.</p>
    pub fn lifecycle_policy_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_policy_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the lifecycle policy that ran.</p>
    pub fn set_lifecycle_policy_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_policy_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the lifecycle policy that ran.</p>
    pub fn get_lifecycle_policy_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_policy_arn
    }
    /// <p>Contains information about associated resources that are identified for action by the runtime instance of the lifecycle policy.</p>
    pub fn resources_impacted_summary(mut self, input: crate::types::LifecycleExecutionResourcesImpactedSummary) -> Self {
        self.resources_impacted_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about associated resources that are identified for action by the runtime instance of the lifecycle policy.</p>
    pub fn set_resources_impacted_summary(mut self, input: ::std::option::Option<crate::types::LifecycleExecutionResourcesImpactedSummary>) -> Self {
        self.resources_impacted_summary = input;
        self
    }
    /// <p>Contains information about associated resources that are identified for action by the runtime instance of the lifecycle policy.</p>
    pub fn get_resources_impacted_summary(&self) -> &::std::option::Option<crate::types::LifecycleExecutionResourcesImpactedSummary> {
        &self.resources_impacted_summary
    }
    /// <p>Runtime state that reports if the policy action ran successfully, failed, or was skipped.</p>
    pub fn state(mut self, input: crate::types::LifecycleExecutionState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>Runtime state that reports if the policy action ran successfully, failed, or was skipped.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::LifecycleExecutionState>) -> Self {
        self.state = input;
        self
    }
    /// <p>Runtime state that reports if the policy action ran successfully, failed, or was skipped.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::LifecycleExecutionState> {
        &self.state
    }
    /// <p>The timestamp when the lifecycle runtime instance started.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the lifecycle runtime instance started.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The timestamp when the lifecycle runtime instance started.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The timestamp when the lifecycle runtime instance completed.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the lifecycle runtime instance completed.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The timestamp when the lifecycle runtime instance completed.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Consumes the builder and constructs a [`LifecycleExecution`](crate::types::LifecycleExecution).
    pub fn build(self) -> crate::types::LifecycleExecution {
        crate::types::LifecycleExecution {
            lifecycle_execution_id: self.lifecycle_execution_id,
            lifecycle_policy_arn: self.lifecycle_policy_arn,
            resources_impacted_summary: self.resources_impacted_summary,
            state: self.state,
            start_time: self.start_time,
            end_time: self.end_time,
        }
    }
}
