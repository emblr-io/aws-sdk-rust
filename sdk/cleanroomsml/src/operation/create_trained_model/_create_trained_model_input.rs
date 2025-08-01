// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTrainedModelInput {
    /// <p>The membership ID of the member that is creating the trained model.</p>
    pub membership_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The name of the trained model.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The associated configured model algorithm used to train this model.</p>
    pub configured_model_algorithm_association_arn: ::std::option::Option<::std::string::String>,
    /// <p>Algorithm-specific parameters that influence the quality of the model. You set hyperparameters before you start the learning process.</p>
    pub hyperparameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The environment variables to set in the Docker container.</p>
    pub environment: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Information about the EC2 resources that are used to train this model.</p>
    pub resource_config: ::std::option::Option<crate::types::ResourceConfig>,
    /// <p>The criteria that is used to stop model training.</p>
    pub stopping_condition: ::std::option::Option<crate::types::StoppingCondition>,
    /// <p>Specifies the incremental training data channels for the trained model.</p>
    /// <p>Incremental training allows you to create a new trained model with updates without retraining from scratch. You can specify up to one incremental training data channel that references a previously trained model and its version.</p>
    /// <p>Limit: Maximum of 20 channels total (including both <code>incrementalTrainingDataChannels</code> and <code>dataChannels</code>).</p>
    pub incremental_training_data_channels: ::std::option::Option<::std::vec::Vec<crate::types::IncrementalTrainingDataChannel>>,
    /// <p>Defines the data channels that are used as input for the trained model request.</p>
    /// <p>Limit: Maximum of 20 channels total (including both <code>dataChannels</code> and <code>incrementalTrainingDataChannels</code>).</p>
    pub data_channels: ::std::option::Option<::std::vec::Vec<crate::types::ModelTrainingDataChannel>>,
    /// <p>The input mode for accessing the training data. This parameter determines how the training data is made available to the training algorithm. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>File</code> - The training data is downloaded to the training instance and made available as files.</p></li>
    /// <li>
    /// <p><code>FastFile</code> - The training data is streamed directly from Amazon S3 to the training algorithm, providing faster access for large datasets.</p></li>
    /// <li>
    /// <p><code>Pipe</code> - The training data is streamed to the training algorithm using named pipes, which can improve performance for certain algorithms.</p></li>
    /// </ul>
    pub training_input_mode: ::std::option::Option<crate::types::TrainingInputMode>,
    /// <p>The description of the trained model.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the KMS key. This key is used to encrypt and decrypt customer-owned data in the trained ML model and the associated data.</p>
    pub kms_key_arn: ::std::option::Option<::std::string::String>,
    /// <p>The optional metadata that you apply to the resource to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use aws:, AWS:, or any upper or lowercase combination of such as a prefix for keys as it is reserved for AWS use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has aws as its prefix but the key does not, then Clean Rooms ML considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of aws do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateTrainedModelInput {
    /// <p>The membership ID of the member that is creating the trained model.</p>
    pub fn membership_identifier(&self) -> ::std::option::Option<&str> {
        self.membership_identifier.as_deref()
    }
    /// <p>The name of the trained model.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The associated configured model algorithm used to train this model.</p>
    pub fn configured_model_algorithm_association_arn(&self) -> ::std::option::Option<&str> {
        self.configured_model_algorithm_association_arn.as_deref()
    }
    /// <p>Algorithm-specific parameters that influence the quality of the model. You set hyperparameters before you start the learning process.</p>
    pub fn hyperparameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.hyperparameters.as_ref()
    }
    /// <p>The environment variables to set in the Docker container.</p>
    pub fn environment(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.environment.as_ref()
    }
    /// <p>Information about the EC2 resources that are used to train this model.</p>
    pub fn resource_config(&self) -> ::std::option::Option<&crate::types::ResourceConfig> {
        self.resource_config.as_ref()
    }
    /// <p>The criteria that is used to stop model training.</p>
    pub fn stopping_condition(&self) -> ::std::option::Option<&crate::types::StoppingCondition> {
        self.stopping_condition.as_ref()
    }
    /// <p>Specifies the incremental training data channels for the trained model.</p>
    /// <p>Incremental training allows you to create a new trained model with updates without retraining from scratch. You can specify up to one incremental training data channel that references a previously trained model and its version.</p>
    /// <p>Limit: Maximum of 20 channels total (including both <code>incrementalTrainingDataChannels</code> and <code>dataChannels</code>).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.incremental_training_data_channels.is_none()`.
    pub fn incremental_training_data_channels(&self) -> &[crate::types::IncrementalTrainingDataChannel] {
        self.incremental_training_data_channels.as_deref().unwrap_or_default()
    }
    /// <p>Defines the data channels that are used as input for the trained model request.</p>
    /// <p>Limit: Maximum of 20 channels total (including both <code>dataChannels</code> and <code>incrementalTrainingDataChannels</code>).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_channels.is_none()`.
    pub fn data_channels(&self) -> &[crate::types::ModelTrainingDataChannel] {
        self.data_channels.as_deref().unwrap_or_default()
    }
    /// <p>The input mode for accessing the training data. This parameter determines how the training data is made available to the training algorithm. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>File</code> - The training data is downloaded to the training instance and made available as files.</p></li>
    /// <li>
    /// <p><code>FastFile</code> - The training data is streamed directly from Amazon S3 to the training algorithm, providing faster access for large datasets.</p></li>
    /// <li>
    /// <p><code>Pipe</code> - The training data is streamed to the training algorithm using named pipes, which can improve performance for certain algorithms.</p></li>
    /// </ul>
    pub fn training_input_mode(&self) -> ::std::option::Option<&crate::types::TrainingInputMode> {
        self.training_input_mode.as_ref()
    }
    /// <p>The description of the trained model.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key. This key is used to encrypt and decrypt customer-owned data in the trained ML model and the associated data.</p>
    pub fn kms_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_key_arn.as_deref()
    }
    /// <p>The optional metadata that you apply to the resource to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use aws:, AWS:, or any upper or lowercase combination of such as a prefix for keys as it is reserved for AWS use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has aws as its prefix but the key does not, then Clean Rooms ML considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of aws do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateTrainedModelInput {
    /// Creates a new builder-style object to manufacture [`CreateTrainedModelInput`](crate::operation::create_trained_model::CreateTrainedModelInput).
    pub fn builder() -> crate::operation::create_trained_model::builders::CreateTrainedModelInputBuilder {
        crate::operation::create_trained_model::builders::CreateTrainedModelInputBuilder::default()
    }
}

/// A builder for [`CreateTrainedModelInput`](crate::operation::create_trained_model::CreateTrainedModelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTrainedModelInputBuilder {
    pub(crate) membership_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) configured_model_algorithm_association_arn: ::std::option::Option<::std::string::String>,
    pub(crate) hyperparameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) environment: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) resource_config: ::std::option::Option<crate::types::ResourceConfig>,
    pub(crate) stopping_condition: ::std::option::Option<crate::types::StoppingCondition>,
    pub(crate) incremental_training_data_channels: ::std::option::Option<::std::vec::Vec<crate::types::IncrementalTrainingDataChannel>>,
    pub(crate) data_channels: ::std::option::Option<::std::vec::Vec<crate::types::ModelTrainingDataChannel>>,
    pub(crate) training_input_mode: ::std::option::Option<crate::types::TrainingInputMode>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateTrainedModelInputBuilder {
    /// <p>The membership ID of the member that is creating the trained model.</p>
    /// This field is required.
    pub fn membership_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The membership ID of the member that is creating the trained model.</p>
    pub fn set_membership_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_identifier = input;
        self
    }
    /// <p>The membership ID of the member that is creating the trained model.</p>
    pub fn get_membership_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_identifier
    }
    /// <p>The name of the trained model.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the trained model.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the trained model.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The associated configured model algorithm used to train this model.</p>
    /// This field is required.
    pub fn configured_model_algorithm_association_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configured_model_algorithm_association_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The associated configured model algorithm used to train this model.</p>
    pub fn set_configured_model_algorithm_association_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configured_model_algorithm_association_arn = input;
        self
    }
    /// <p>The associated configured model algorithm used to train this model.</p>
    pub fn get_configured_model_algorithm_association_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.configured_model_algorithm_association_arn
    }
    /// Adds a key-value pair to `hyperparameters`.
    ///
    /// To override the contents of this collection use [`set_hyperparameters`](Self::set_hyperparameters).
    ///
    /// <p>Algorithm-specific parameters that influence the quality of the model. You set hyperparameters before you start the learning process.</p>
    pub fn hyperparameters(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.hyperparameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.hyperparameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Algorithm-specific parameters that influence the quality of the model. You set hyperparameters before you start the learning process.</p>
    pub fn set_hyperparameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.hyperparameters = input;
        self
    }
    /// <p>Algorithm-specific parameters that influence the quality of the model. You set hyperparameters before you start the learning process.</p>
    pub fn get_hyperparameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.hyperparameters
    }
    /// Adds a key-value pair to `environment`.
    ///
    /// To override the contents of this collection use [`set_environment`](Self::set_environment).
    ///
    /// <p>The environment variables to set in the Docker container.</p>
    pub fn environment(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.environment.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.environment = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The environment variables to set in the Docker container.</p>
    pub fn set_environment(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.environment = input;
        self
    }
    /// <p>The environment variables to set in the Docker container.</p>
    pub fn get_environment(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.environment
    }
    /// <p>Information about the EC2 resources that are used to train this model.</p>
    /// This field is required.
    pub fn resource_config(mut self, input: crate::types::ResourceConfig) -> Self {
        self.resource_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the EC2 resources that are used to train this model.</p>
    pub fn set_resource_config(mut self, input: ::std::option::Option<crate::types::ResourceConfig>) -> Self {
        self.resource_config = input;
        self
    }
    /// <p>Information about the EC2 resources that are used to train this model.</p>
    pub fn get_resource_config(&self) -> &::std::option::Option<crate::types::ResourceConfig> {
        &self.resource_config
    }
    /// <p>The criteria that is used to stop model training.</p>
    pub fn stopping_condition(mut self, input: crate::types::StoppingCondition) -> Self {
        self.stopping_condition = ::std::option::Option::Some(input);
        self
    }
    /// <p>The criteria that is used to stop model training.</p>
    pub fn set_stopping_condition(mut self, input: ::std::option::Option<crate::types::StoppingCondition>) -> Self {
        self.stopping_condition = input;
        self
    }
    /// <p>The criteria that is used to stop model training.</p>
    pub fn get_stopping_condition(&self) -> &::std::option::Option<crate::types::StoppingCondition> {
        &self.stopping_condition
    }
    /// Appends an item to `incremental_training_data_channels`.
    ///
    /// To override the contents of this collection use [`set_incremental_training_data_channels`](Self::set_incremental_training_data_channels).
    ///
    /// <p>Specifies the incremental training data channels for the trained model.</p>
    /// <p>Incremental training allows you to create a new trained model with updates without retraining from scratch. You can specify up to one incremental training data channel that references a previously trained model and its version.</p>
    /// <p>Limit: Maximum of 20 channels total (including both <code>incrementalTrainingDataChannels</code> and <code>dataChannels</code>).</p>
    pub fn incremental_training_data_channels(mut self, input: crate::types::IncrementalTrainingDataChannel) -> Self {
        let mut v = self.incremental_training_data_channels.unwrap_or_default();
        v.push(input);
        self.incremental_training_data_channels = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the incremental training data channels for the trained model.</p>
    /// <p>Incremental training allows you to create a new trained model with updates without retraining from scratch. You can specify up to one incremental training data channel that references a previously trained model and its version.</p>
    /// <p>Limit: Maximum of 20 channels total (including both <code>incrementalTrainingDataChannels</code> and <code>dataChannels</code>).</p>
    pub fn set_incremental_training_data_channels(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::IncrementalTrainingDataChannel>>,
    ) -> Self {
        self.incremental_training_data_channels = input;
        self
    }
    /// <p>Specifies the incremental training data channels for the trained model.</p>
    /// <p>Incremental training allows you to create a new trained model with updates without retraining from scratch. You can specify up to one incremental training data channel that references a previously trained model and its version.</p>
    /// <p>Limit: Maximum of 20 channels total (including both <code>incrementalTrainingDataChannels</code> and <code>dataChannels</code>).</p>
    pub fn get_incremental_training_data_channels(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IncrementalTrainingDataChannel>> {
        &self.incremental_training_data_channels
    }
    /// Appends an item to `data_channels`.
    ///
    /// To override the contents of this collection use [`set_data_channels`](Self::set_data_channels).
    ///
    /// <p>Defines the data channels that are used as input for the trained model request.</p>
    /// <p>Limit: Maximum of 20 channels total (including both <code>dataChannels</code> and <code>incrementalTrainingDataChannels</code>).</p>
    pub fn data_channels(mut self, input: crate::types::ModelTrainingDataChannel) -> Self {
        let mut v = self.data_channels.unwrap_or_default();
        v.push(input);
        self.data_channels = ::std::option::Option::Some(v);
        self
    }
    /// <p>Defines the data channels that are used as input for the trained model request.</p>
    /// <p>Limit: Maximum of 20 channels total (including both <code>dataChannels</code> and <code>incrementalTrainingDataChannels</code>).</p>
    pub fn set_data_channels(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ModelTrainingDataChannel>>) -> Self {
        self.data_channels = input;
        self
    }
    /// <p>Defines the data channels that are used as input for the trained model request.</p>
    /// <p>Limit: Maximum of 20 channels total (including both <code>dataChannels</code> and <code>incrementalTrainingDataChannels</code>).</p>
    pub fn get_data_channels(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ModelTrainingDataChannel>> {
        &self.data_channels
    }
    /// <p>The input mode for accessing the training data. This parameter determines how the training data is made available to the training algorithm. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>File</code> - The training data is downloaded to the training instance and made available as files.</p></li>
    /// <li>
    /// <p><code>FastFile</code> - The training data is streamed directly from Amazon S3 to the training algorithm, providing faster access for large datasets.</p></li>
    /// <li>
    /// <p><code>Pipe</code> - The training data is streamed to the training algorithm using named pipes, which can improve performance for certain algorithms.</p></li>
    /// </ul>
    pub fn training_input_mode(mut self, input: crate::types::TrainingInputMode) -> Self {
        self.training_input_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The input mode for accessing the training data. This parameter determines how the training data is made available to the training algorithm. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>File</code> - The training data is downloaded to the training instance and made available as files.</p></li>
    /// <li>
    /// <p><code>FastFile</code> - The training data is streamed directly from Amazon S3 to the training algorithm, providing faster access for large datasets.</p></li>
    /// <li>
    /// <p><code>Pipe</code> - The training data is streamed to the training algorithm using named pipes, which can improve performance for certain algorithms.</p></li>
    /// </ul>
    pub fn set_training_input_mode(mut self, input: ::std::option::Option<crate::types::TrainingInputMode>) -> Self {
        self.training_input_mode = input;
        self
    }
    /// <p>The input mode for accessing the training data. This parameter determines how the training data is made available to the training algorithm. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>File</code> - The training data is downloaded to the training instance and made available as files.</p></li>
    /// <li>
    /// <p><code>FastFile</code> - The training data is streamed directly from Amazon S3 to the training algorithm, providing faster access for large datasets.</p></li>
    /// <li>
    /// <p><code>Pipe</code> - The training data is streamed to the training algorithm using named pipes, which can improve performance for certain algorithms.</p></li>
    /// </ul>
    pub fn get_training_input_mode(&self) -> &::std::option::Option<crate::types::TrainingInputMode> {
        &self.training_input_mode
    }
    /// <p>The description of the trained model.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the trained model.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the trained model.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key. This key is used to encrypt and decrypt customer-owned data in the trained ML model and the associated data.</p>
    pub fn kms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key. This key is used to encrypt and decrypt customer-owned data in the trained ML model and the associated data.</p>
    pub fn set_kms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key. This key is used to encrypt and decrypt customer-owned data in the trained ML model and the associated data.</p>
    pub fn get_kms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_arn
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The optional metadata that you apply to the resource to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use aws:, AWS:, or any upper or lowercase combination of such as a prefix for keys as it is reserved for AWS use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has aws as its prefix but the key does not, then Clean Rooms ML considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of aws do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The optional metadata that you apply to the resource to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use aws:, AWS:, or any upper or lowercase combination of such as a prefix for keys as it is reserved for AWS use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has aws as its prefix but the key does not, then Clean Rooms ML considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of aws do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The optional metadata that you apply to the resource to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use aws:, AWS:, or any upper or lowercase combination of such as a prefix for keys as it is reserved for AWS use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has aws as its prefix but the key does not, then Clean Rooms ML considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of aws do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateTrainedModelInput`](crate::operation::create_trained_model::CreateTrainedModelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_trained_model::CreateTrainedModelInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_trained_model::CreateTrainedModelInput {
            membership_identifier: self.membership_identifier,
            name: self.name,
            configured_model_algorithm_association_arn: self.configured_model_algorithm_association_arn,
            hyperparameters: self.hyperparameters,
            environment: self.environment,
            resource_config: self.resource_config,
            stopping_condition: self.stopping_condition,
            incremental_training_data_channels: self.incremental_training_data_channels,
            data_channels: self.data_channels,
            training_input_mode: self.training_input_mode,
            description: self.description,
            kms_key_arn: self.kms_key_arn,
            tags: self.tags,
        })
    }
}
