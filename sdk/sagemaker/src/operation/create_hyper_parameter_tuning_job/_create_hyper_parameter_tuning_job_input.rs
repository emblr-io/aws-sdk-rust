// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateHyperParameterTuningJobInput {
    /// <p>The name of the tuning job. This name is the prefix for the names of all training jobs that this tuning job launches. The name must be unique within the same Amazon Web Services account and Amazon Web Services Region. The name must have 1 to 32 characters. Valid characters are a-z, A-Z, 0-9, and : + = @ _ % - (hyphen). The name is not case sensitive.</p>
    pub hyper_parameter_tuning_job_name: ::std::option::Option<::std::string::String>,
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html">HyperParameterTuningJobConfig</a> object that describes the tuning job, including the search strategy, the objective metric used to evaluate training jobs, ranges of parameters to search, and resource limits for the tuning job. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-how-it-works.html">How Hyperparameter Tuning Works</a>.</p>
    pub hyper_parameter_tuning_job_config: ::std::option::Option<crate::types::HyperParameterTuningJobConfig>,
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html">HyperParameterTrainingJobDefinition</a> object that describes the training jobs that this tuning job launches, including static hyperparameters, input data configuration, output data configuration, resource configuration, and stopping condition.</p>
    pub training_job_definition: ::std::option::Option<crate::types::HyperParameterTrainingJobDefinition>,
    /// <p>A list of the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html">HyperParameterTrainingJobDefinition</a> objects launched for this tuning job.</p>
    pub training_job_definitions: ::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTrainingJobDefinition>>,
    /// <p>Specifies the configuration for starting the hyperparameter tuning job using one or more previous tuning jobs as a starting point. The results of previous tuning jobs are used to inform which combinations of hyperparameters to search over in the new tuning job.</p>
    /// <p>All training jobs launched by the new hyperparameter tuning job are evaluated by using the objective metric. If you specify <code>IDENTICAL_DATA_AND_ALGORITHM</code> as the <code>WarmStartType</code> value for the warm start configuration, the training job that performs the best in the new tuning job is compared to the best training jobs from the parent tuning jobs. From these, the training job that performs the best as measured by the objective metric is returned as the overall best training job.</p><note>
    /// <p>All training jobs launched by parent hyperparameter tuning jobs and the new hyperparameter tuning jobs count against the limit of training jobs for the tuning job.</p>
    /// </note>
    pub warm_start_config: ::std::option::Option<crate::types::HyperParameterTuningJobWarmStartConfig>,
    /// <p>An array of key-value pairs. You can use tags to categorize your Amazon Web Services resources in different ways, for example, by purpose, owner, or environment. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services Resources</a>.</p>
    /// <p>Tags that you specify for the tuning job are also added to all training jobs that the tuning job launches.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>Configures SageMaker Automatic model tuning (AMT) to automatically find optimal parameters for the following fields:</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html#sagemaker-Type-HyperParameterTuningJobConfig-ParameterRanges">ParameterRanges</a>: The names and ranges of parameters that a hyperparameter tuning job can optimize.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ResourceLimits.html">ResourceLimits</a>: The maximum resources that can be used for a training job. These resources include the maximum number of training jobs, the maximum runtime of a tuning job, and the maximum number of training jobs to run at the same time.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html#sagemaker-Type-HyperParameterTuningJobConfig-TrainingJobEarlyStoppingType">TrainingJobEarlyStoppingType</a>: A flag that specifies whether or not to use early stopping for training jobs launched by a hyperparameter tuning job.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html#sagemaker-Type-HyperParameterTrainingJobDefinition-RetryStrategy">RetryStrategy</a>: The number of times to retry a training job.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html">Strategy</a>: Specifies how hyperparameter tuning chooses the combinations of hyperparameter values to use for the training jobs that it launches.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ConvergenceDetected.html">ConvergenceDetected</a>: A flag to indicate that Automatic model tuning (AMT) has detected model convergence.</p></li>
    /// </ul>
    pub autotune: ::std::option::Option<crate::types::Autotune>,
}
impl CreateHyperParameterTuningJobInput {
    /// <p>The name of the tuning job. This name is the prefix for the names of all training jobs that this tuning job launches. The name must be unique within the same Amazon Web Services account and Amazon Web Services Region. The name must have 1 to 32 characters. Valid characters are a-z, A-Z, 0-9, and : + = @ _ % - (hyphen). The name is not case sensitive.</p>
    pub fn hyper_parameter_tuning_job_name(&self) -> ::std::option::Option<&str> {
        self.hyper_parameter_tuning_job_name.as_deref()
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html">HyperParameterTuningJobConfig</a> object that describes the tuning job, including the search strategy, the objective metric used to evaluate training jobs, ranges of parameters to search, and resource limits for the tuning job. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-how-it-works.html">How Hyperparameter Tuning Works</a>.</p>
    pub fn hyper_parameter_tuning_job_config(&self) -> ::std::option::Option<&crate::types::HyperParameterTuningJobConfig> {
        self.hyper_parameter_tuning_job_config.as_ref()
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html">HyperParameterTrainingJobDefinition</a> object that describes the training jobs that this tuning job launches, including static hyperparameters, input data configuration, output data configuration, resource configuration, and stopping condition.</p>
    pub fn training_job_definition(&self) -> ::std::option::Option<&crate::types::HyperParameterTrainingJobDefinition> {
        self.training_job_definition.as_ref()
    }
    /// <p>A list of the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html">HyperParameterTrainingJobDefinition</a> objects launched for this tuning job.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.training_job_definitions.is_none()`.
    pub fn training_job_definitions(&self) -> &[crate::types::HyperParameterTrainingJobDefinition] {
        self.training_job_definitions.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the configuration for starting the hyperparameter tuning job using one or more previous tuning jobs as a starting point. The results of previous tuning jobs are used to inform which combinations of hyperparameters to search over in the new tuning job.</p>
    /// <p>All training jobs launched by the new hyperparameter tuning job are evaluated by using the objective metric. If you specify <code>IDENTICAL_DATA_AND_ALGORITHM</code> as the <code>WarmStartType</code> value for the warm start configuration, the training job that performs the best in the new tuning job is compared to the best training jobs from the parent tuning jobs. From these, the training job that performs the best as measured by the objective metric is returned as the overall best training job.</p><note>
    /// <p>All training jobs launched by parent hyperparameter tuning jobs and the new hyperparameter tuning jobs count against the limit of training jobs for the tuning job.</p>
    /// </note>
    pub fn warm_start_config(&self) -> ::std::option::Option<&crate::types::HyperParameterTuningJobWarmStartConfig> {
        self.warm_start_config.as_ref()
    }
    /// <p>An array of key-value pairs. You can use tags to categorize your Amazon Web Services resources in different ways, for example, by purpose, owner, or environment. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services Resources</a>.</p>
    /// <p>Tags that you specify for the tuning job are also added to all training jobs that the tuning job launches.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>Configures SageMaker Automatic model tuning (AMT) to automatically find optimal parameters for the following fields:</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html#sagemaker-Type-HyperParameterTuningJobConfig-ParameterRanges">ParameterRanges</a>: The names and ranges of parameters that a hyperparameter tuning job can optimize.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ResourceLimits.html">ResourceLimits</a>: The maximum resources that can be used for a training job. These resources include the maximum number of training jobs, the maximum runtime of a tuning job, and the maximum number of training jobs to run at the same time.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html#sagemaker-Type-HyperParameterTuningJobConfig-TrainingJobEarlyStoppingType">TrainingJobEarlyStoppingType</a>: A flag that specifies whether or not to use early stopping for training jobs launched by a hyperparameter tuning job.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html#sagemaker-Type-HyperParameterTrainingJobDefinition-RetryStrategy">RetryStrategy</a>: The number of times to retry a training job.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html">Strategy</a>: Specifies how hyperparameter tuning chooses the combinations of hyperparameter values to use for the training jobs that it launches.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ConvergenceDetected.html">ConvergenceDetected</a>: A flag to indicate that Automatic model tuning (AMT) has detected model convergence.</p></li>
    /// </ul>
    pub fn autotune(&self) -> ::std::option::Option<&crate::types::Autotune> {
        self.autotune.as_ref()
    }
}
impl CreateHyperParameterTuningJobInput {
    /// Creates a new builder-style object to manufacture [`CreateHyperParameterTuningJobInput`](crate::operation::create_hyper_parameter_tuning_job::CreateHyperParameterTuningJobInput).
    pub fn builder() -> crate::operation::create_hyper_parameter_tuning_job::builders::CreateHyperParameterTuningJobInputBuilder {
        crate::operation::create_hyper_parameter_tuning_job::builders::CreateHyperParameterTuningJobInputBuilder::default()
    }
}

/// A builder for [`CreateHyperParameterTuningJobInput`](crate::operation::create_hyper_parameter_tuning_job::CreateHyperParameterTuningJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateHyperParameterTuningJobInputBuilder {
    pub(crate) hyper_parameter_tuning_job_name: ::std::option::Option<::std::string::String>,
    pub(crate) hyper_parameter_tuning_job_config: ::std::option::Option<crate::types::HyperParameterTuningJobConfig>,
    pub(crate) training_job_definition: ::std::option::Option<crate::types::HyperParameterTrainingJobDefinition>,
    pub(crate) training_job_definitions: ::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTrainingJobDefinition>>,
    pub(crate) warm_start_config: ::std::option::Option<crate::types::HyperParameterTuningJobWarmStartConfig>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) autotune: ::std::option::Option<crate::types::Autotune>,
}
impl CreateHyperParameterTuningJobInputBuilder {
    /// <p>The name of the tuning job. This name is the prefix for the names of all training jobs that this tuning job launches. The name must be unique within the same Amazon Web Services account and Amazon Web Services Region. The name must have 1 to 32 characters. Valid characters are a-z, A-Z, 0-9, and : + = @ _ % - (hyphen). The name is not case sensitive.</p>
    /// This field is required.
    pub fn hyper_parameter_tuning_job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hyper_parameter_tuning_job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the tuning job. This name is the prefix for the names of all training jobs that this tuning job launches. The name must be unique within the same Amazon Web Services account and Amazon Web Services Region. The name must have 1 to 32 characters. Valid characters are a-z, A-Z, 0-9, and : + = @ _ % - (hyphen). The name is not case sensitive.</p>
    pub fn set_hyper_parameter_tuning_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hyper_parameter_tuning_job_name = input;
        self
    }
    /// <p>The name of the tuning job. This name is the prefix for the names of all training jobs that this tuning job launches. The name must be unique within the same Amazon Web Services account and Amazon Web Services Region. The name must have 1 to 32 characters. Valid characters are a-z, A-Z, 0-9, and : + = @ _ % - (hyphen). The name is not case sensitive.</p>
    pub fn get_hyper_parameter_tuning_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.hyper_parameter_tuning_job_name
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html">HyperParameterTuningJobConfig</a> object that describes the tuning job, including the search strategy, the objective metric used to evaluate training jobs, ranges of parameters to search, and resource limits for the tuning job. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-how-it-works.html">How Hyperparameter Tuning Works</a>.</p>
    /// This field is required.
    pub fn hyper_parameter_tuning_job_config(mut self, input: crate::types::HyperParameterTuningJobConfig) -> Self {
        self.hyper_parameter_tuning_job_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html">HyperParameterTuningJobConfig</a> object that describes the tuning job, including the search strategy, the objective metric used to evaluate training jobs, ranges of parameters to search, and resource limits for the tuning job. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-how-it-works.html">How Hyperparameter Tuning Works</a>.</p>
    pub fn set_hyper_parameter_tuning_job_config(mut self, input: ::std::option::Option<crate::types::HyperParameterTuningJobConfig>) -> Self {
        self.hyper_parameter_tuning_job_config = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html">HyperParameterTuningJobConfig</a> object that describes the tuning job, including the search strategy, the objective metric used to evaluate training jobs, ranges of parameters to search, and resource limits for the tuning job. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-how-it-works.html">How Hyperparameter Tuning Works</a>.</p>
    pub fn get_hyper_parameter_tuning_job_config(&self) -> &::std::option::Option<crate::types::HyperParameterTuningJobConfig> {
        &self.hyper_parameter_tuning_job_config
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html">HyperParameterTrainingJobDefinition</a> object that describes the training jobs that this tuning job launches, including static hyperparameters, input data configuration, output data configuration, resource configuration, and stopping condition.</p>
    pub fn training_job_definition(mut self, input: crate::types::HyperParameterTrainingJobDefinition) -> Self {
        self.training_job_definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html">HyperParameterTrainingJobDefinition</a> object that describes the training jobs that this tuning job launches, including static hyperparameters, input data configuration, output data configuration, resource configuration, and stopping condition.</p>
    pub fn set_training_job_definition(mut self, input: ::std::option::Option<crate::types::HyperParameterTrainingJobDefinition>) -> Self {
        self.training_job_definition = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html">HyperParameterTrainingJobDefinition</a> object that describes the training jobs that this tuning job launches, including static hyperparameters, input data configuration, output data configuration, resource configuration, and stopping condition.</p>
    pub fn get_training_job_definition(&self) -> &::std::option::Option<crate::types::HyperParameterTrainingJobDefinition> {
        &self.training_job_definition
    }
    /// Appends an item to `training_job_definitions`.
    ///
    /// To override the contents of this collection use [`set_training_job_definitions`](Self::set_training_job_definitions).
    ///
    /// <p>A list of the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html">HyperParameterTrainingJobDefinition</a> objects launched for this tuning job.</p>
    pub fn training_job_definitions(mut self, input: crate::types::HyperParameterTrainingJobDefinition) -> Self {
        let mut v = self.training_job_definitions.unwrap_or_default();
        v.push(input);
        self.training_job_definitions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html">HyperParameterTrainingJobDefinition</a> objects launched for this tuning job.</p>
    pub fn set_training_job_definitions(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTrainingJobDefinition>>,
    ) -> Self {
        self.training_job_definitions = input;
        self
    }
    /// <p>A list of the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html">HyperParameterTrainingJobDefinition</a> objects launched for this tuning job.</p>
    pub fn get_training_job_definitions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTrainingJobDefinition>> {
        &self.training_job_definitions
    }
    /// <p>Specifies the configuration for starting the hyperparameter tuning job using one or more previous tuning jobs as a starting point. The results of previous tuning jobs are used to inform which combinations of hyperparameters to search over in the new tuning job.</p>
    /// <p>All training jobs launched by the new hyperparameter tuning job are evaluated by using the objective metric. If you specify <code>IDENTICAL_DATA_AND_ALGORITHM</code> as the <code>WarmStartType</code> value for the warm start configuration, the training job that performs the best in the new tuning job is compared to the best training jobs from the parent tuning jobs. From these, the training job that performs the best as measured by the objective metric is returned as the overall best training job.</p><note>
    /// <p>All training jobs launched by parent hyperparameter tuning jobs and the new hyperparameter tuning jobs count against the limit of training jobs for the tuning job.</p>
    /// </note>
    pub fn warm_start_config(mut self, input: crate::types::HyperParameterTuningJobWarmStartConfig) -> Self {
        self.warm_start_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the configuration for starting the hyperparameter tuning job using one or more previous tuning jobs as a starting point. The results of previous tuning jobs are used to inform which combinations of hyperparameters to search over in the new tuning job.</p>
    /// <p>All training jobs launched by the new hyperparameter tuning job are evaluated by using the objective metric. If you specify <code>IDENTICAL_DATA_AND_ALGORITHM</code> as the <code>WarmStartType</code> value for the warm start configuration, the training job that performs the best in the new tuning job is compared to the best training jobs from the parent tuning jobs. From these, the training job that performs the best as measured by the objective metric is returned as the overall best training job.</p><note>
    /// <p>All training jobs launched by parent hyperparameter tuning jobs and the new hyperparameter tuning jobs count against the limit of training jobs for the tuning job.</p>
    /// </note>
    pub fn set_warm_start_config(mut self, input: ::std::option::Option<crate::types::HyperParameterTuningJobWarmStartConfig>) -> Self {
        self.warm_start_config = input;
        self
    }
    /// <p>Specifies the configuration for starting the hyperparameter tuning job using one or more previous tuning jobs as a starting point. The results of previous tuning jobs are used to inform which combinations of hyperparameters to search over in the new tuning job.</p>
    /// <p>All training jobs launched by the new hyperparameter tuning job are evaluated by using the objective metric. If you specify <code>IDENTICAL_DATA_AND_ALGORITHM</code> as the <code>WarmStartType</code> value for the warm start configuration, the training job that performs the best in the new tuning job is compared to the best training jobs from the parent tuning jobs. From these, the training job that performs the best as measured by the objective metric is returned as the overall best training job.</p><note>
    /// <p>All training jobs launched by parent hyperparameter tuning jobs and the new hyperparameter tuning jobs count against the limit of training jobs for the tuning job.</p>
    /// </note>
    pub fn get_warm_start_config(&self) -> &::std::option::Option<crate::types::HyperParameterTuningJobWarmStartConfig> {
        &self.warm_start_config
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An array of key-value pairs. You can use tags to categorize your Amazon Web Services resources in different ways, for example, by purpose, owner, or environment. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services Resources</a>.</p>
    /// <p>Tags that you specify for the tuning job are also added to all training jobs that the tuning job launches.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of key-value pairs. You can use tags to categorize your Amazon Web Services resources in different ways, for example, by purpose, owner, or environment. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services Resources</a>.</p>
    /// <p>Tags that you specify for the tuning job are also added to all training jobs that the tuning job launches.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An array of key-value pairs. You can use tags to categorize your Amazon Web Services resources in different ways, for example, by purpose, owner, or environment. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services Resources</a>.</p>
    /// <p>Tags that you specify for the tuning job are also added to all training jobs that the tuning job launches.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>Configures SageMaker Automatic model tuning (AMT) to automatically find optimal parameters for the following fields:</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html#sagemaker-Type-HyperParameterTuningJobConfig-ParameterRanges">ParameterRanges</a>: The names and ranges of parameters that a hyperparameter tuning job can optimize.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ResourceLimits.html">ResourceLimits</a>: The maximum resources that can be used for a training job. These resources include the maximum number of training jobs, the maximum runtime of a tuning job, and the maximum number of training jobs to run at the same time.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html#sagemaker-Type-HyperParameterTuningJobConfig-TrainingJobEarlyStoppingType">TrainingJobEarlyStoppingType</a>: A flag that specifies whether or not to use early stopping for training jobs launched by a hyperparameter tuning job.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html#sagemaker-Type-HyperParameterTrainingJobDefinition-RetryStrategy">RetryStrategy</a>: The number of times to retry a training job.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html">Strategy</a>: Specifies how hyperparameter tuning chooses the combinations of hyperparameter values to use for the training jobs that it launches.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ConvergenceDetected.html">ConvergenceDetected</a>: A flag to indicate that Automatic model tuning (AMT) has detected model convergence.</p></li>
    /// </ul>
    pub fn autotune(mut self, input: crate::types::Autotune) -> Self {
        self.autotune = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configures SageMaker Automatic model tuning (AMT) to automatically find optimal parameters for the following fields:</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html#sagemaker-Type-HyperParameterTuningJobConfig-ParameterRanges">ParameterRanges</a>: The names and ranges of parameters that a hyperparameter tuning job can optimize.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ResourceLimits.html">ResourceLimits</a>: The maximum resources that can be used for a training job. These resources include the maximum number of training jobs, the maximum runtime of a tuning job, and the maximum number of training jobs to run at the same time.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html#sagemaker-Type-HyperParameterTuningJobConfig-TrainingJobEarlyStoppingType">TrainingJobEarlyStoppingType</a>: A flag that specifies whether or not to use early stopping for training jobs launched by a hyperparameter tuning job.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html#sagemaker-Type-HyperParameterTrainingJobDefinition-RetryStrategy">RetryStrategy</a>: The number of times to retry a training job.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html">Strategy</a>: Specifies how hyperparameter tuning chooses the combinations of hyperparameter values to use for the training jobs that it launches.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ConvergenceDetected.html">ConvergenceDetected</a>: A flag to indicate that Automatic model tuning (AMT) has detected model convergence.</p></li>
    /// </ul>
    pub fn set_autotune(mut self, input: ::std::option::Option<crate::types::Autotune>) -> Self {
        self.autotune = input;
        self
    }
    /// <p>Configures SageMaker Automatic model tuning (AMT) to automatically find optimal parameters for the following fields:</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html#sagemaker-Type-HyperParameterTuningJobConfig-ParameterRanges">ParameterRanges</a>: The names and ranges of parameters that a hyperparameter tuning job can optimize.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ResourceLimits.html">ResourceLimits</a>: The maximum resources that can be used for a training job. These resources include the maximum number of training jobs, the maximum runtime of a tuning job, and the maximum number of training jobs to run at the same time.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html#sagemaker-Type-HyperParameterTuningJobConfig-TrainingJobEarlyStoppingType">TrainingJobEarlyStoppingType</a>: A flag that specifies whether or not to use early stopping for training jobs launched by a hyperparameter tuning job.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html#sagemaker-Type-HyperParameterTrainingJobDefinition-RetryStrategy">RetryStrategy</a>: The number of times to retry a training job.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobConfig.html">Strategy</a>: Specifies how hyperparameter tuning chooses the combinations of hyperparameter values to use for the training jobs that it launches.</p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ConvergenceDetected.html">ConvergenceDetected</a>: A flag to indicate that Automatic model tuning (AMT) has detected model convergence.</p></li>
    /// </ul>
    pub fn get_autotune(&self) -> &::std::option::Option<crate::types::Autotune> {
        &self.autotune
    }
    /// Consumes the builder and constructs a [`CreateHyperParameterTuningJobInput`](crate::operation::create_hyper_parameter_tuning_job::CreateHyperParameterTuningJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_hyper_parameter_tuning_job::CreateHyperParameterTuningJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_hyper_parameter_tuning_job::CreateHyperParameterTuningJobInput {
            hyper_parameter_tuning_job_name: self.hyper_parameter_tuning_job_name,
            hyper_parameter_tuning_job_config: self.hyper_parameter_tuning_job_config,
            training_job_definition: self.training_job_definition,
            training_job_definitions: self.training_job_definitions,
            warm_start_config: self.warm_start_config,
            tags: self.tags,
            autotune: self.autotune,
        })
    }
}
