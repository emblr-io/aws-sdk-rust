// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This represents a step in a cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Step {
    /// <p>The identifier of the cluster step.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the cluster step.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Hadoop job configuration of the cluster step.</p>
    pub config: ::std::option::Option<crate::types::HadoopStepConfig>,
    /// <p>The action to take when the cluster step fails. Possible values are <code>TERMINATE_CLUSTER</code>, <code>CANCEL_AND_WAIT</code>, and <code>CONTINUE</code>. <code>TERMINATE_JOB_FLOW</code> is provided for backward compatibility. We recommend using <code>TERMINATE_CLUSTER</code> instead.</p>
    /// <p>If a cluster's <code>StepConcurrencyLevel</code> is greater than <code>1</code>, do not use <code>AddJobFlowSteps</code> to submit a step with this parameter set to <code>CANCEL_AND_WAIT</code> or <code>TERMINATE_CLUSTER</code>. The step is not submitted and the action fails with a message that the <code>ActionOnFailure</code> setting is not valid.</p>
    /// <p>If you change a cluster's <code>StepConcurrencyLevel</code> to be greater than 1 while a step is running, the <code>ActionOnFailure</code> parameter may not behave as you expect. In this case, for a step that fails with this parameter set to <code>CANCEL_AND_WAIT</code>, pending steps and the running step are not canceled; for a step that fails with this parameter set to <code>TERMINATE_CLUSTER</code>, the cluster does not terminate.</p>
    pub action_on_failure: ::std::option::Option<crate::types::ActionOnFailure>,
    /// <p>The current execution status details of the cluster step.</p>
    pub status: ::std::option::Option<crate::types::StepStatus>,
    /// <p>The Amazon Resource Name (ARN) of the runtime role for a step on the cluster. The runtime role can be a cross-account IAM role. The runtime role ARN is a combination of account ID, role name, and role type using the following format: <code>arn:partition:service:region:account:resource</code>.</p>
    /// <p>For example, <code>arn:aws:IAM::1234567890:role/ReadOnly</code> is a correctly formatted runtime role ARN.</p>
    pub execution_role_arn: ::std::option::Option<::std::string::String>,
}
impl Step {
    /// <p>The identifier of the cluster step.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The name of the cluster step.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Hadoop job configuration of the cluster step.</p>
    pub fn config(&self) -> ::std::option::Option<&crate::types::HadoopStepConfig> {
        self.config.as_ref()
    }
    /// <p>The action to take when the cluster step fails. Possible values are <code>TERMINATE_CLUSTER</code>, <code>CANCEL_AND_WAIT</code>, and <code>CONTINUE</code>. <code>TERMINATE_JOB_FLOW</code> is provided for backward compatibility. We recommend using <code>TERMINATE_CLUSTER</code> instead.</p>
    /// <p>If a cluster's <code>StepConcurrencyLevel</code> is greater than <code>1</code>, do not use <code>AddJobFlowSteps</code> to submit a step with this parameter set to <code>CANCEL_AND_WAIT</code> or <code>TERMINATE_CLUSTER</code>. The step is not submitted and the action fails with a message that the <code>ActionOnFailure</code> setting is not valid.</p>
    /// <p>If you change a cluster's <code>StepConcurrencyLevel</code> to be greater than 1 while a step is running, the <code>ActionOnFailure</code> parameter may not behave as you expect. In this case, for a step that fails with this parameter set to <code>CANCEL_AND_WAIT</code>, pending steps and the running step are not canceled; for a step that fails with this parameter set to <code>TERMINATE_CLUSTER</code>, the cluster does not terminate.</p>
    pub fn action_on_failure(&self) -> ::std::option::Option<&crate::types::ActionOnFailure> {
        self.action_on_failure.as_ref()
    }
    /// <p>The current execution status details of the cluster step.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::StepStatus> {
        self.status.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the runtime role for a step on the cluster. The runtime role can be a cross-account IAM role. The runtime role ARN is a combination of account ID, role name, and role type using the following format: <code>arn:partition:service:region:account:resource</code>.</p>
    /// <p>For example, <code>arn:aws:IAM::1234567890:role/ReadOnly</code> is a correctly formatted runtime role ARN.</p>
    pub fn execution_role_arn(&self) -> ::std::option::Option<&str> {
        self.execution_role_arn.as_deref()
    }
}
impl Step {
    /// Creates a new builder-style object to manufacture [`Step`](crate::types::Step).
    pub fn builder() -> crate::types::builders::StepBuilder {
        crate::types::builders::StepBuilder::default()
    }
}

/// A builder for [`Step`](crate::types::Step).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StepBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) config: ::std::option::Option<crate::types::HadoopStepConfig>,
    pub(crate) action_on_failure: ::std::option::Option<crate::types::ActionOnFailure>,
    pub(crate) status: ::std::option::Option<crate::types::StepStatus>,
    pub(crate) execution_role_arn: ::std::option::Option<::std::string::String>,
}
impl StepBuilder {
    /// <p>The identifier of the cluster step.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the cluster step.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the cluster step.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the cluster step.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cluster step.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the cluster step.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Hadoop job configuration of the cluster step.</p>
    pub fn config(mut self, input: crate::types::HadoopStepConfig) -> Self {
        self.config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Hadoop job configuration of the cluster step.</p>
    pub fn set_config(mut self, input: ::std::option::Option<crate::types::HadoopStepConfig>) -> Self {
        self.config = input;
        self
    }
    /// <p>The Hadoop job configuration of the cluster step.</p>
    pub fn get_config(&self) -> &::std::option::Option<crate::types::HadoopStepConfig> {
        &self.config
    }
    /// <p>The action to take when the cluster step fails. Possible values are <code>TERMINATE_CLUSTER</code>, <code>CANCEL_AND_WAIT</code>, and <code>CONTINUE</code>. <code>TERMINATE_JOB_FLOW</code> is provided for backward compatibility. We recommend using <code>TERMINATE_CLUSTER</code> instead.</p>
    /// <p>If a cluster's <code>StepConcurrencyLevel</code> is greater than <code>1</code>, do not use <code>AddJobFlowSteps</code> to submit a step with this parameter set to <code>CANCEL_AND_WAIT</code> or <code>TERMINATE_CLUSTER</code>. The step is not submitted and the action fails with a message that the <code>ActionOnFailure</code> setting is not valid.</p>
    /// <p>If you change a cluster's <code>StepConcurrencyLevel</code> to be greater than 1 while a step is running, the <code>ActionOnFailure</code> parameter may not behave as you expect. In this case, for a step that fails with this parameter set to <code>CANCEL_AND_WAIT</code>, pending steps and the running step are not canceled; for a step that fails with this parameter set to <code>TERMINATE_CLUSTER</code>, the cluster does not terminate.</p>
    pub fn action_on_failure(mut self, input: crate::types::ActionOnFailure) -> Self {
        self.action_on_failure = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action to take when the cluster step fails. Possible values are <code>TERMINATE_CLUSTER</code>, <code>CANCEL_AND_WAIT</code>, and <code>CONTINUE</code>. <code>TERMINATE_JOB_FLOW</code> is provided for backward compatibility. We recommend using <code>TERMINATE_CLUSTER</code> instead.</p>
    /// <p>If a cluster's <code>StepConcurrencyLevel</code> is greater than <code>1</code>, do not use <code>AddJobFlowSteps</code> to submit a step with this parameter set to <code>CANCEL_AND_WAIT</code> or <code>TERMINATE_CLUSTER</code>. The step is not submitted and the action fails with a message that the <code>ActionOnFailure</code> setting is not valid.</p>
    /// <p>If you change a cluster's <code>StepConcurrencyLevel</code> to be greater than 1 while a step is running, the <code>ActionOnFailure</code> parameter may not behave as you expect. In this case, for a step that fails with this parameter set to <code>CANCEL_AND_WAIT</code>, pending steps and the running step are not canceled; for a step that fails with this parameter set to <code>TERMINATE_CLUSTER</code>, the cluster does not terminate.</p>
    pub fn set_action_on_failure(mut self, input: ::std::option::Option<crate::types::ActionOnFailure>) -> Self {
        self.action_on_failure = input;
        self
    }
    /// <p>The action to take when the cluster step fails. Possible values are <code>TERMINATE_CLUSTER</code>, <code>CANCEL_AND_WAIT</code>, and <code>CONTINUE</code>. <code>TERMINATE_JOB_FLOW</code> is provided for backward compatibility. We recommend using <code>TERMINATE_CLUSTER</code> instead.</p>
    /// <p>If a cluster's <code>StepConcurrencyLevel</code> is greater than <code>1</code>, do not use <code>AddJobFlowSteps</code> to submit a step with this parameter set to <code>CANCEL_AND_WAIT</code> or <code>TERMINATE_CLUSTER</code>. The step is not submitted and the action fails with a message that the <code>ActionOnFailure</code> setting is not valid.</p>
    /// <p>If you change a cluster's <code>StepConcurrencyLevel</code> to be greater than 1 while a step is running, the <code>ActionOnFailure</code> parameter may not behave as you expect. In this case, for a step that fails with this parameter set to <code>CANCEL_AND_WAIT</code>, pending steps and the running step are not canceled; for a step that fails with this parameter set to <code>TERMINATE_CLUSTER</code>, the cluster does not terminate.</p>
    pub fn get_action_on_failure(&self) -> &::std::option::Option<crate::types::ActionOnFailure> {
        &self.action_on_failure
    }
    /// <p>The current execution status details of the cluster step.</p>
    pub fn status(mut self, input: crate::types::StepStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current execution status details of the cluster step.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::StepStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current execution status details of the cluster step.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::StepStatus> {
        &self.status
    }
    /// <p>The Amazon Resource Name (ARN) of the runtime role for a step on the cluster. The runtime role can be a cross-account IAM role. The runtime role ARN is a combination of account ID, role name, and role type using the following format: <code>arn:partition:service:region:account:resource</code>.</p>
    /// <p>For example, <code>arn:aws:IAM::1234567890:role/ReadOnly</code> is a correctly formatted runtime role ARN.</p>
    pub fn execution_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the runtime role for a step on the cluster. The runtime role can be a cross-account IAM role. The runtime role ARN is a combination of account ID, role name, and role type using the following format: <code>arn:partition:service:region:account:resource</code>.</p>
    /// <p>For example, <code>arn:aws:IAM::1234567890:role/ReadOnly</code> is a correctly formatted runtime role ARN.</p>
    pub fn set_execution_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the runtime role for a step on the cluster. The runtime role can be a cross-account IAM role. The runtime role ARN is a combination of account ID, role name, and role type using the following format: <code>arn:partition:service:region:account:resource</code>.</p>
    /// <p>For example, <code>arn:aws:IAM::1234567890:role/ReadOnly</code> is a correctly formatted runtime role ARN.</p>
    pub fn get_execution_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_role_arn
    }
    /// Consumes the builder and constructs a [`Step`](crate::types::Step).
    pub fn build(self) -> crate::types::Step {
        crate::types::Step {
            id: self.id,
            name: self.name,
            config: self.config,
            action_on_failure: self.action_on_failure,
            status: self.status,
            execution_role_arn: self.execution_role_arn,
        }
    }
}
