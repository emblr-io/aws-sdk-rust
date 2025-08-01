// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeModelQualityJobDefinitionOutput {
    /// <p>The Amazon Resource Name (ARN) of the model quality job.</p>
    pub job_definition_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the quality job definition. The name must be unique within an Amazon Web Services Region in the Amazon Web Services account.</p>
    pub job_definition_name: ::std::option::Option<::std::string::String>,
    /// <p>The time at which the model quality job was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The baseline configuration for a model quality job.</p>
    pub model_quality_baseline_config: ::std::option::Option<crate::types::ModelQualityBaselineConfig>,
    /// <p>Configures the model quality job to run a specified Docker container image.</p>
    pub model_quality_app_specification: ::std::option::Option<crate::types::ModelQualityAppSpecification>,
    /// <p>Inputs for the model quality job.</p>
    pub model_quality_job_input: ::std::option::Option<crate::types::ModelQualityJobInput>,
    /// <p>The output configuration for monitoring jobs.</p>
    pub model_quality_job_output_config: ::std::option::Option<crate::types::MonitoringOutputConfig>,
    /// <p>Identifies the resources to deploy for a monitoring job.</p>
    pub job_resources: ::std::option::Option<crate::types::MonitoringResources>,
    /// <p>Networking options for a model quality job.</p>
    pub network_config: ::std::option::Option<crate::types::MonitoringNetworkConfig>,
    /// <p>The Amazon Resource Name (ARN) of an IAM role that Amazon SageMaker AI can assume to perform tasks on your behalf.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>A time limit for how long the monitoring job is allowed to run before stopping.</p>
    pub stopping_condition: ::std::option::Option<crate::types::MonitoringStoppingCondition>,
    _request_id: Option<String>,
}
impl DescribeModelQualityJobDefinitionOutput {
    /// <p>The Amazon Resource Name (ARN) of the model quality job.</p>
    pub fn job_definition_arn(&self) -> ::std::option::Option<&str> {
        self.job_definition_arn.as_deref()
    }
    /// <p>The name of the quality job definition. The name must be unique within an Amazon Web Services Region in the Amazon Web Services account.</p>
    pub fn job_definition_name(&self) -> ::std::option::Option<&str> {
        self.job_definition_name.as_deref()
    }
    /// <p>The time at which the model quality job was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The baseline configuration for a model quality job.</p>
    pub fn model_quality_baseline_config(&self) -> ::std::option::Option<&crate::types::ModelQualityBaselineConfig> {
        self.model_quality_baseline_config.as_ref()
    }
    /// <p>Configures the model quality job to run a specified Docker container image.</p>
    pub fn model_quality_app_specification(&self) -> ::std::option::Option<&crate::types::ModelQualityAppSpecification> {
        self.model_quality_app_specification.as_ref()
    }
    /// <p>Inputs for the model quality job.</p>
    pub fn model_quality_job_input(&self) -> ::std::option::Option<&crate::types::ModelQualityJobInput> {
        self.model_quality_job_input.as_ref()
    }
    /// <p>The output configuration for monitoring jobs.</p>
    pub fn model_quality_job_output_config(&self) -> ::std::option::Option<&crate::types::MonitoringOutputConfig> {
        self.model_quality_job_output_config.as_ref()
    }
    /// <p>Identifies the resources to deploy for a monitoring job.</p>
    pub fn job_resources(&self) -> ::std::option::Option<&crate::types::MonitoringResources> {
        self.job_resources.as_ref()
    }
    /// <p>Networking options for a model quality job.</p>
    pub fn network_config(&self) -> ::std::option::Option<&crate::types::MonitoringNetworkConfig> {
        self.network_config.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that Amazon SageMaker AI can assume to perform tasks on your behalf.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>A time limit for how long the monitoring job is allowed to run before stopping.</p>
    pub fn stopping_condition(&self) -> ::std::option::Option<&crate::types::MonitoringStoppingCondition> {
        self.stopping_condition.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeModelQualityJobDefinitionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeModelQualityJobDefinitionOutput {
    /// Creates a new builder-style object to manufacture [`DescribeModelQualityJobDefinitionOutput`](crate::operation::describe_model_quality_job_definition::DescribeModelQualityJobDefinitionOutput).
    pub fn builder() -> crate::operation::describe_model_quality_job_definition::builders::DescribeModelQualityJobDefinitionOutputBuilder {
        crate::operation::describe_model_quality_job_definition::builders::DescribeModelQualityJobDefinitionOutputBuilder::default()
    }
}

/// A builder for [`DescribeModelQualityJobDefinitionOutput`](crate::operation::describe_model_quality_job_definition::DescribeModelQualityJobDefinitionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeModelQualityJobDefinitionOutputBuilder {
    pub(crate) job_definition_arn: ::std::option::Option<::std::string::String>,
    pub(crate) job_definition_name: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) model_quality_baseline_config: ::std::option::Option<crate::types::ModelQualityBaselineConfig>,
    pub(crate) model_quality_app_specification: ::std::option::Option<crate::types::ModelQualityAppSpecification>,
    pub(crate) model_quality_job_input: ::std::option::Option<crate::types::ModelQualityJobInput>,
    pub(crate) model_quality_job_output_config: ::std::option::Option<crate::types::MonitoringOutputConfig>,
    pub(crate) job_resources: ::std::option::Option<crate::types::MonitoringResources>,
    pub(crate) network_config: ::std::option::Option<crate::types::MonitoringNetworkConfig>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) stopping_condition: ::std::option::Option<crate::types::MonitoringStoppingCondition>,
    _request_id: Option<String>,
}
impl DescribeModelQualityJobDefinitionOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the model quality job.</p>
    /// This field is required.
    pub fn job_definition_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_definition_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the model quality job.</p>
    pub fn set_job_definition_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_definition_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the model quality job.</p>
    pub fn get_job_definition_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_definition_arn
    }
    /// <p>The name of the quality job definition. The name must be unique within an Amazon Web Services Region in the Amazon Web Services account.</p>
    /// This field is required.
    pub fn job_definition_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_definition_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the quality job definition. The name must be unique within an Amazon Web Services Region in the Amazon Web Services account.</p>
    pub fn set_job_definition_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_definition_name = input;
        self
    }
    /// <p>The name of the quality job definition. The name must be unique within an Amazon Web Services Region in the Amazon Web Services account.</p>
    pub fn get_job_definition_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_definition_name
    }
    /// <p>The time at which the model quality job was created.</p>
    /// This field is required.
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the model quality job was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time at which the model quality job was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The baseline configuration for a model quality job.</p>
    pub fn model_quality_baseline_config(mut self, input: crate::types::ModelQualityBaselineConfig) -> Self {
        self.model_quality_baseline_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The baseline configuration for a model quality job.</p>
    pub fn set_model_quality_baseline_config(mut self, input: ::std::option::Option<crate::types::ModelQualityBaselineConfig>) -> Self {
        self.model_quality_baseline_config = input;
        self
    }
    /// <p>The baseline configuration for a model quality job.</p>
    pub fn get_model_quality_baseline_config(&self) -> &::std::option::Option<crate::types::ModelQualityBaselineConfig> {
        &self.model_quality_baseline_config
    }
    /// <p>Configures the model quality job to run a specified Docker container image.</p>
    /// This field is required.
    pub fn model_quality_app_specification(mut self, input: crate::types::ModelQualityAppSpecification) -> Self {
        self.model_quality_app_specification = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configures the model quality job to run a specified Docker container image.</p>
    pub fn set_model_quality_app_specification(mut self, input: ::std::option::Option<crate::types::ModelQualityAppSpecification>) -> Self {
        self.model_quality_app_specification = input;
        self
    }
    /// <p>Configures the model quality job to run a specified Docker container image.</p>
    pub fn get_model_quality_app_specification(&self) -> &::std::option::Option<crate::types::ModelQualityAppSpecification> {
        &self.model_quality_app_specification
    }
    /// <p>Inputs for the model quality job.</p>
    /// This field is required.
    pub fn model_quality_job_input(mut self, input: crate::types::ModelQualityJobInput) -> Self {
        self.model_quality_job_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>Inputs for the model quality job.</p>
    pub fn set_model_quality_job_input(mut self, input: ::std::option::Option<crate::types::ModelQualityJobInput>) -> Self {
        self.model_quality_job_input = input;
        self
    }
    /// <p>Inputs for the model quality job.</p>
    pub fn get_model_quality_job_input(&self) -> &::std::option::Option<crate::types::ModelQualityJobInput> {
        &self.model_quality_job_input
    }
    /// <p>The output configuration for monitoring jobs.</p>
    /// This field is required.
    pub fn model_quality_job_output_config(mut self, input: crate::types::MonitoringOutputConfig) -> Self {
        self.model_quality_job_output_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The output configuration for monitoring jobs.</p>
    pub fn set_model_quality_job_output_config(mut self, input: ::std::option::Option<crate::types::MonitoringOutputConfig>) -> Self {
        self.model_quality_job_output_config = input;
        self
    }
    /// <p>The output configuration for monitoring jobs.</p>
    pub fn get_model_quality_job_output_config(&self) -> &::std::option::Option<crate::types::MonitoringOutputConfig> {
        &self.model_quality_job_output_config
    }
    /// <p>Identifies the resources to deploy for a monitoring job.</p>
    /// This field is required.
    pub fn job_resources(mut self, input: crate::types::MonitoringResources) -> Self {
        self.job_resources = ::std::option::Option::Some(input);
        self
    }
    /// <p>Identifies the resources to deploy for a monitoring job.</p>
    pub fn set_job_resources(mut self, input: ::std::option::Option<crate::types::MonitoringResources>) -> Self {
        self.job_resources = input;
        self
    }
    /// <p>Identifies the resources to deploy for a monitoring job.</p>
    pub fn get_job_resources(&self) -> &::std::option::Option<crate::types::MonitoringResources> {
        &self.job_resources
    }
    /// <p>Networking options for a model quality job.</p>
    pub fn network_config(mut self, input: crate::types::MonitoringNetworkConfig) -> Self {
        self.network_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Networking options for a model quality job.</p>
    pub fn set_network_config(mut self, input: ::std::option::Option<crate::types::MonitoringNetworkConfig>) -> Self {
        self.network_config = input;
        self
    }
    /// <p>Networking options for a model quality job.</p>
    pub fn get_network_config(&self) -> &::std::option::Option<crate::types::MonitoringNetworkConfig> {
        &self.network_config
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that Amazon SageMaker AI can assume to perform tasks on your behalf.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that Amazon SageMaker AI can assume to perform tasks on your behalf.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that Amazon SageMaker AI can assume to perform tasks on your behalf.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>A time limit for how long the monitoring job is allowed to run before stopping.</p>
    pub fn stopping_condition(mut self, input: crate::types::MonitoringStoppingCondition) -> Self {
        self.stopping_condition = ::std::option::Option::Some(input);
        self
    }
    /// <p>A time limit for how long the monitoring job is allowed to run before stopping.</p>
    pub fn set_stopping_condition(mut self, input: ::std::option::Option<crate::types::MonitoringStoppingCondition>) -> Self {
        self.stopping_condition = input;
        self
    }
    /// <p>A time limit for how long the monitoring job is allowed to run before stopping.</p>
    pub fn get_stopping_condition(&self) -> &::std::option::Option<crate::types::MonitoringStoppingCondition> {
        &self.stopping_condition
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeModelQualityJobDefinitionOutput`](crate::operation::describe_model_quality_job_definition::DescribeModelQualityJobDefinitionOutput).
    pub fn build(self) -> crate::operation::describe_model_quality_job_definition::DescribeModelQualityJobDefinitionOutput {
        crate::operation::describe_model_quality_job_definition::DescribeModelQualityJobDefinitionOutput {
            job_definition_arn: self.job_definition_arn,
            job_definition_name: self.job_definition_name,
            creation_time: self.creation_time,
            model_quality_baseline_config: self.model_quality_baseline_config,
            model_quality_app_specification: self.model_quality_app_specification,
            model_quality_job_input: self.model_quality_job_input,
            model_quality_job_output_config: self.model_quality_job_output_config,
            job_resources: self.job_resources,
            network_config: self.network_config,
            role_arn: self.role_arn,
            stopping_condition: self.stopping_condition,
            _request_id: self._request_id,
        }
    }
}
