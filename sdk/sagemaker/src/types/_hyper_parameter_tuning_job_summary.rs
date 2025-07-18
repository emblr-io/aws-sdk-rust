// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides summary information about a hyperparameter tuning job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HyperParameterTuningJobSummary {
    /// <p>The name of the tuning job.</p>
    pub hyper_parameter_tuning_job_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the tuning job.</p>
    pub hyper_parameter_tuning_job_arn: ::std::option::Option<::std::string::String>,
    /// <p>The status of the tuning job.</p>
    pub hyper_parameter_tuning_job_status: ::std::option::Option<crate::types::HyperParameterTuningJobStatus>,
    /// <p>Specifies the search strategy hyperparameter tuning uses to choose which hyperparameters to evaluate at each iteration.</p>
    pub strategy: ::std::option::Option<crate::types::HyperParameterTuningJobStrategyType>,
    /// <p>The date and time that the tuning job was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the tuning job ended.</p>
    pub hyper_parameter_tuning_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the tuning job was modified.</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_TrainingJobStatusCounters.html">TrainingJobStatusCounters</a> object that specifies the numbers of training jobs, categorized by status, that this tuning job launched.</p>
    pub training_job_status_counters: ::std::option::Option<crate::types::TrainingJobStatusCounters>,
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ObjectiveStatusCounters.html">ObjectiveStatusCounters</a> object that specifies the numbers of training jobs, categorized by objective metric status, that this tuning job launched.</p>
    pub objective_status_counters: ::std::option::Option<crate::types::ObjectiveStatusCounters>,
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ResourceLimits.html">ResourceLimits</a> object that specifies the maximum number of training jobs and parallel training jobs allowed for this tuning job.</p>
    pub resource_limits: ::std::option::Option<crate::types::ResourceLimits>,
}
impl HyperParameterTuningJobSummary {
    /// <p>The name of the tuning job.</p>
    pub fn hyper_parameter_tuning_job_name(&self) -> ::std::option::Option<&str> {
        self.hyper_parameter_tuning_job_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the tuning job.</p>
    pub fn hyper_parameter_tuning_job_arn(&self) -> ::std::option::Option<&str> {
        self.hyper_parameter_tuning_job_arn.as_deref()
    }
    /// <p>The status of the tuning job.</p>
    pub fn hyper_parameter_tuning_job_status(&self) -> ::std::option::Option<&crate::types::HyperParameterTuningJobStatus> {
        self.hyper_parameter_tuning_job_status.as_ref()
    }
    /// <p>Specifies the search strategy hyperparameter tuning uses to choose which hyperparameters to evaluate at each iteration.</p>
    pub fn strategy(&self) -> ::std::option::Option<&crate::types::HyperParameterTuningJobStrategyType> {
        self.strategy.as_ref()
    }
    /// <p>The date and time that the tuning job was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The date and time that the tuning job ended.</p>
    pub fn hyper_parameter_tuning_end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.hyper_parameter_tuning_end_time.as_ref()
    }
    /// <p>The date and time that the tuning job was modified.</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_TrainingJobStatusCounters.html">TrainingJobStatusCounters</a> object that specifies the numbers of training jobs, categorized by status, that this tuning job launched.</p>
    pub fn training_job_status_counters(&self) -> ::std::option::Option<&crate::types::TrainingJobStatusCounters> {
        self.training_job_status_counters.as_ref()
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ObjectiveStatusCounters.html">ObjectiveStatusCounters</a> object that specifies the numbers of training jobs, categorized by objective metric status, that this tuning job launched.</p>
    pub fn objective_status_counters(&self) -> ::std::option::Option<&crate::types::ObjectiveStatusCounters> {
        self.objective_status_counters.as_ref()
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ResourceLimits.html">ResourceLimits</a> object that specifies the maximum number of training jobs and parallel training jobs allowed for this tuning job.</p>
    pub fn resource_limits(&self) -> ::std::option::Option<&crate::types::ResourceLimits> {
        self.resource_limits.as_ref()
    }
}
impl HyperParameterTuningJobSummary {
    /// Creates a new builder-style object to manufacture [`HyperParameterTuningJobSummary`](crate::types::HyperParameterTuningJobSummary).
    pub fn builder() -> crate::types::builders::HyperParameterTuningJobSummaryBuilder {
        crate::types::builders::HyperParameterTuningJobSummaryBuilder::default()
    }
}

/// A builder for [`HyperParameterTuningJobSummary`](crate::types::HyperParameterTuningJobSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HyperParameterTuningJobSummaryBuilder {
    pub(crate) hyper_parameter_tuning_job_name: ::std::option::Option<::std::string::String>,
    pub(crate) hyper_parameter_tuning_job_arn: ::std::option::Option<::std::string::String>,
    pub(crate) hyper_parameter_tuning_job_status: ::std::option::Option<crate::types::HyperParameterTuningJobStatus>,
    pub(crate) strategy: ::std::option::Option<crate::types::HyperParameterTuningJobStrategyType>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) hyper_parameter_tuning_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) training_job_status_counters: ::std::option::Option<crate::types::TrainingJobStatusCounters>,
    pub(crate) objective_status_counters: ::std::option::Option<crate::types::ObjectiveStatusCounters>,
    pub(crate) resource_limits: ::std::option::Option<crate::types::ResourceLimits>,
}
impl HyperParameterTuningJobSummaryBuilder {
    /// <p>The name of the tuning job.</p>
    /// This field is required.
    pub fn hyper_parameter_tuning_job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hyper_parameter_tuning_job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the tuning job.</p>
    pub fn set_hyper_parameter_tuning_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hyper_parameter_tuning_job_name = input;
        self
    }
    /// <p>The name of the tuning job.</p>
    pub fn get_hyper_parameter_tuning_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.hyper_parameter_tuning_job_name
    }
    /// <p>The Amazon Resource Name (ARN) of the tuning job.</p>
    /// This field is required.
    pub fn hyper_parameter_tuning_job_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hyper_parameter_tuning_job_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the tuning job.</p>
    pub fn set_hyper_parameter_tuning_job_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hyper_parameter_tuning_job_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the tuning job.</p>
    pub fn get_hyper_parameter_tuning_job_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.hyper_parameter_tuning_job_arn
    }
    /// <p>The status of the tuning job.</p>
    /// This field is required.
    pub fn hyper_parameter_tuning_job_status(mut self, input: crate::types::HyperParameterTuningJobStatus) -> Self {
        self.hyper_parameter_tuning_job_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the tuning job.</p>
    pub fn set_hyper_parameter_tuning_job_status(mut self, input: ::std::option::Option<crate::types::HyperParameterTuningJobStatus>) -> Self {
        self.hyper_parameter_tuning_job_status = input;
        self
    }
    /// <p>The status of the tuning job.</p>
    pub fn get_hyper_parameter_tuning_job_status(&self) -> &::std::option::Option<crate::types::HyperParameterTuningJobStatus> {
        &self.hyper_parameter_tuning_job_status
    }
    /// <p>Specifies the search strategy hyperparameter tuning uses to choose which hyperparameters to evaluate at each iteration.</p>
    /// This field is required.
    pub fn strategy(mut self, input: crate::types::HyperParameterTuningJobStrategyType) -> Self {
        self.strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the search strategy hyperparameter tuning uses to choose which hyperparameters to evaluate at each iteration.</p>
    pub fn set_strategy(mut self, input: ::std::option::Option<crate::types::HyperParameterTuningJobStrategyType>) -> Self {
        self.strategy = input;
        self
    }
    /// <p>Specifies the search strategy hyperparameter tuning uses to choose which hyperparameters to evaluate at each iteration.</p>
    pub fn get_strategy(&self) -> &::std::option::Option<crate::types::HyperParameterTuningJobStrategyType> {
        &self.strategy
    }
    /// <p>The date and time that the tuning job was created.</p>
    /// This field is required.
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the tuning job was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The date and time that the tuning job was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The date and time that the tuning job ended.</p>
    pub fn hyper_parameter_tuning_end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.hyper_parameter_tuning_end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the tuning job ended.</p>
    pub fn set_hyper_parameter_tuning_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.hyper_parameter_tuning_end_time = input;
        self
    }
    /// <p>The date and time that the tuning job ended.</p>
    pub fn get_hyper_parameter_tuning_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.hyper_parameter_tuning_end_time
    }
    /// <p>The date and time that the tuning job was modified.</p>
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the tuning job was modified.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The date and time that the tuning job was modified.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_TrainingJobStatusCounters.html">TrainingJobStatusCounters</a> object that specifies the numbers of training jobs, categorized by status, that this tuning job launched.</p>
    /// This field is required.
    pub fn training_job_status_counters(mut self, input: crate::types::TrainingJobStatusCounters) -> Self {
        self.training_job_status_counters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_TrainingJobStatusCounters.html">TrainingJobStatusCounters</a> object that specifies the numbers of training jobs, categorized by status, that this tuning job launched.</p>
    pub fn set_training_job_status_counters(mut self, input: ::std::option::Option<crate::types::TrainingJobStatusCounters>) -> Self {
        self.training_job_status_counters = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_TrainingJobStatusCounters.html">TrainingJobStatusCounters</a> object that specifies the numbers of training jobs, categorized by status, that this tuning job launched.</p>
    pub fn get_training_job_status_counters(&self) -> &::std::option::Option<crate::types::TrainingJobStatusCounters> {
        &self.training_job_status_counters
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ObjectiveStatusCounters.html">ObjectiveStatusCounters</a> object that specifies the numbers of training jobs, categorized by objective metric status, that this tuning job launched.</p>
    /// This field is required.
    pub fn objective_status_counters(mut self, input: crate::types::ObjectiveStatusCounters) -> Self {
        self.objective_status_counters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ObjectiveStatusCounters.html">ObjectiveStatusCounters</a> object that specifies the numbers of training jobs, categorized by objective metric status, that this tuning job launched.</p>
    pub fn set_objective_status_counters(mut self, input: ::std::option::Option<crate::types::ObjectiveStatusCounters>) -> Self {
        self.objective_status_counters = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ObjectiveStatusCounters.html">ObjectiveStatusCounters</a> object that specifies the numbers of training jobs, categorized by objective metric status, that this tuning job launched.</p>
    pub fn get_objective_status_counters(&self) -> &::std::option::Option<crate::types::ObjectiveStatusCounters> {
        &self.objective_status_counters
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ResourceLimits.html">ResourceLimits</a> object that specifies the maximum number of training jobs and parallel training jobs allowed for this tuning job.</p>
    pub fn resource_limits(mut self, input: crate::types::ResourceLimits) -> Self {
        self.resource_limits = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ResourceLimits.html">ResourceLimits</a> object that specifies the maximum number of training jobs and parallel training jobs allowed for this tuning job.</p>
    pub fn set_resource_limits(mut self, input: ::std::option::Option<crate::types::ResourceLimits>) -> Self {
        self.resource_limits = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ResourceLimits.html">ResourceLimits</a> object that specifies the maximum number of training jobs and parallel training jobs allowed for this tuning job.</p>
    pub fn get_resource_limits(&self) -> &::std::option::Option<crate::types::ResourceLimits> {
        &self.resource_limits
    }
    /// Consumes the builder and constructs a [`HyperParameterTuningJobSummary`](crate::types::HyperParameterTuningJobSummary).
    pub fn build(self) -> crate::types::HyperParameterTuningJobSummary {
        crate::types::HyperParameterTuningJobSummary {
            hyper_parameter_tuning_job_name: self.hyper_parameter_tuning_job_name,
            hyper_parameter_tuning_job_arn: self.hyper_parameter_tuning_job_arn,
            hyper_parameter_tuning_job_status: self.hyper_parameter_tuning_job_status,
            strategy: self.strategy,
            creation_time: self.creation_time,
            hyper_parameter_tuning_end_time: self.hyper_parameter_tuning_end_time,
            last_modified_time: self.last_modified_time,
            training_job_status_counters: self.training_job_status_counters,
            objective_status_counters: self.objective_status_counters,
            resource_limits: self.resource_limits,
        }
    }
}
