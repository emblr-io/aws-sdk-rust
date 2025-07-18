// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration of resources, including compute instances and storage volumes for use in training jobs launched by hyperparameter tuning jobs. <code>HyperParameterTuningResourceConfig</code> is similar to <code>ResourceConfig</code>, but has the additional <code>InstanceConfigs</code> and <code>AllocationStrategy</code> fields to allow for flexible instance management. Specify one or more instance types, count, and the allocation strategy for instance selection.</p><note>
/// <p><code>HyperParameterTuningResourceConfig</code> supports the capabilities of <code>ResourceConfig</code> with the exception of <code>KeepAlivePeriodInSeconds</code>. Hyperparameter tuning jobs use warm pools by default, which reuse clusters between training jobs.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HyperParameterTuningResourceConfig {
    /// <p>The instance type used to run hyperparameter optimization tuning jobs. See <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/notebooks-available-instance-types.html"> descriptions of instance types</a> for more information.</p>
    pub instance_type: ::std::option::Option<crate::types::TrainingInstanceType>,
    /// <p>The number of compute instances of type <code>InstanceType</code> to use. For <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/data-parallel-use-api.html">distributed training</a>, select a value greater than 1.</p>
    pub instance_count: ::std::option::Option<i32>,
    /// <p>The volume size in GB for the storage volume to be used in processing hyperparameter optimization jobs (optional). These volumes store model artifacts, incremental states and optionally, scratch space for training algorithms. Do not provide a value for this parameter if a value for <code>InstanceConfigs</code> is also specified.</p>
    /// <p>Some instance types have a fixed total local storage size. If you select one of these instances for training, <code>VolumeSizeInGB</code> cannot be greater than this total size. For a list of instance types with local instance storage and their sizes, see <a href="http://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/">instance store volumes</a>.</p><note>
    /// <p>SageMaker supports only the <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html">General Purpose SSD (gp2)</a> storage volume type.</p>
    /// </note>
    pub volume_size_in_gb: ::std::option::Option<i32>,
    /// <p>A key used by Amazon Web Services Key Management Service to encrypt data on the storage volume attached to the compute instances used to run the training job. You can use either of the following formats to specify a key.</p>
    /// <p>KMS Key ID:</p>
    /// <p><code>"1234abcd-12ab-34cd-56ef-1234567890ab"</code></p>
    /// <p>Amazon Resource Name (ARN) of a KMS key:</p>
    /// <p><code>"arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"</code></p>
    /// <p>Some instances use local storage, which use a <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ssd-instance-store.html">hardware module to encrypt</a> storage volumes. If you choose one of these instance types, you cannot request a <code>VolumeKmsKeyId</code>. For a list of instance types that use local storage, see <a href="http://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/">instance store volumes</a>. For more information about Amazon Web Services Key Management Service, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sms-security-kms-permissions.html">KMS encryption</a> for more information.</p>
    pub volume_kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The strategy that determines the order of preference for resources specified in <code>InstanceConfigs</code> used in hyperparameter optimization.</p>
    pub allocation_strategy: ::std::option::Option<crate::types::HyperParameterTuningAllocationStrategy>,
    /// <p>A list containing the configuration(s) for one or more resources for processing hyperparameter jobs. These resources include compute instances and storage volumes to use in model training jobs launched by hyperparameter tuning jobs. The <code>AllocationStrategy</code> controls the order in which multiple configurations provided in <code>InstanceConfigs</code> are used.</p><note>
    /// <p>If you only want to use a single instance configuration inside the <code>HyperParameterTuningResourceConfig</code> API, do not provide a value for <code>InstanceConfigs</code>. Instead, use <code>InstanceType</code>, <code>VolumeSizeInGB</code> and <code>InstanceCount</code>. If you use <code>InstanceConfigs</code>, do not provide values for <code>InstanceType</code>, <code>VolumeSizeInGB</code> or <code>InstanceCount</code>.</p>
    /// </note>
    pub instance_configs: ::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTuningInstanceConfig>>,
}
impl HyperParameterTuningResourceConfig {
    /// <p>The instance type used to run hyperparameter optimization tuning jobs. See <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/notebooks-available-instance-types.html"> descriptions of instance types</a> for more information.</p>
    pub fn instance_type(&self) -> ::std::option::Option<&crate::types::TrainingInstanceType> {
        self.instance_type.as_ref()
    }
    /// <p>The number of compute instances of type <code>InstanceType</code> to use. For <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/data-parallel-use-api.html">distributed training</a>, select a value greater than 1.</p>
    pub fn instance_count(&self) -> ::std::option::Option<i32> {
        self.instance_count
    }
    /// <p>The volume size in GB for the storage volume to be used in processing hyperparameter optimization jobs (optional). These volumes store model artifacts, incremental states and optionally, scratch space for training algorithms. Do not provide a value for this parameter if a value for <code>InstanceConfigs</code> is also specified.</p>
    /// <p>Some instance types have a fixed total local storage size. If you select one of these instances for training, <code>VolumeSizeInGB</code> cannot be greater than this total size. For a list of instance types with local instance storage and their sizes, see <a href="http://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/">instance store volumes</a>.</p><note>
    /// <p>SageMaker supports only the <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html">General Purpose SSD (gp2)</a> storage volume type.</p>
    /// </note>
    pub fn volume_size_in_gb(&self) -> ::std::option::Option<i32> {
        self.volume_size_in_gb
    }
    /// <p>A key used by Amazon Web Services Key Management Service to encrypt data on the storage volume attached to the compute instances used to run the training job. You can use either of the following formats to specify a key.</p>
    /// <p>KMS Key ID:</p>
    /// <p><code>"1234abcd-12ab-34cd-56ef-1234567890ab"</code></p>
    /// <p>Amazon Resource Name (ARN) of a KMS key:</p>
    /// <p><code>"arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"</code></p>
    /// <p>Some instances use local storage, which use a <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ssd-instance-store.html">hardware module to encrypt</a> storage volumes. If you choose one of these instance types, you cannot request a <code>VolumeKmsKeyId</code>. For a list of instance types that use local storage, see <a href="http://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/">instance store volumes</a>. For more information about Amazon Web Services Key Management Service, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sms-security-kms-permissions.html">KMS encryption</a> for more information.</p>
    pub fn volume_kms_key_id(&self) -> ::std::option::Option<&str> {
        self.volume_kms_key_id.as_deref()
    }
    /// <p>The strategy that determines the order of preference for resources specified in <code>InstanceConfigs</code> used in hyperparameter optimization.</p>
    pub fn allocation_strategy(&self) -> ::std::option::Option<&crate::types::HyperParameterTuningAllocationStrategy> {
        self.allocation_strategy.as_ref()
    }
    /// <p>A list containing the configuration(s) for one or more resources for processing hyperparameter jobs. These resources include compute instances and storage volumes to use in model training jobs launched by hyperparameter tuning jobs. The <code>AllocationStrategy</code> controls the order in which multiple configurations provided in <code>InstanceConfigs</code> are used.</p><note>
    /// <p>If you only want to use a single instance configuration inside the <code>HyperParameterTuningResourceConfig</code> API, do not provide a value for <code>InstanceConfigs</code>. Instead, use <code>InstanceType</code>, <code>VolumeSizeInGB</code> and <code>InstanceCount</code>. If you use <code>InstanceConfigs</code>, do not provide values for <code>InstanceType</code>, <code>VolumeSizeInGB</code> or <code>InstanceCount</code>.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_configs.is_none()`.
    pub fn instance_configs(&self) -> &[crate::types::HyperParameterTuningInstanceConfig] {
        self.instance_configs.as_deref().unwrap_or_default()
    }
}
impl HyperParameterTuningResourceConfig {
    /// Creates a new builder-style object to manufacture [`HyperParameterTuningResourceConfig`](crate::types::HyperParameterTuningResourceConfig).
    pub fn builder() -> crate::types::builders::HyperParameterTuningResourceConfigBuilder {
        crate::types::builders::HyperParameterTuningResourceConfigBuilder::default()
    }
}

/// A builder for [`HyperParameterTuningResourceConfig`](crate::types::HyperParameterTuningResourceConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HyperParameterTuningResourceConfigBuilder {
    pub(crate) instance_type: ::std::option::Option<crate::types::TrainingInstanceType>,
    pub(crate) instance_count: ::std::option::Option<i32>,
    pub(crate) volume_size_in_gb: ::std::option::Option<i32>,
    pub(crate) volume_kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) allocation_strategy: ::std::option::Option<crate::types::HyperParameterTuningAllocationStrategy>,
    pub(crate) instance_configs: ::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTuningInstanceConfig>>,
}
impl HyperParameterTuningResourceConfigBuilder {
    /// <p>The instance type used to run hyperparameter optimization tuning jobs. See <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/notebooks-available-instance-types.html"> descriptions of instance types</a> for more information.</p>
    pub fn instance_type(mut self, input: crate::types::TrainingInstanceType) -> Self {
        self.instance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The instance type used to run hyperparameter optimization tuning jobs. See <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/notebooks-available-instance-types.html"> descriptions of instance types</a> for more information.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<crate::types::TrainingInstanceType>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The instance type used to run hyperparameter optimization tuning jobs. See <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/notebooks-available-instance-types.html"> descriptions of instance types</a> for more information.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<crate::types::TrainingInstanceType> {
        &self.instance_type
    }
    /// <p>The number of compute instances of type <code>InstanceType</code> to use. For <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/data-parallel-use-api.html">distributed training</a>, select a value greater than 1.</p>
    pub fn instance_count(mut self, input: i32) -> Self {
        self.instance_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of compute instances of type <code>InstanceType</code> to use. For <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/data-parallel-use-api.html">distributed training</a>, select a value greater than 1.</p>
    pub fn set_instance_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.instance_count = input;
        self
    }
    /// <p>The number of compute instances of type <code>InstanceType</code> to use. For <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/data-parallel-use-api.html">distributed training</a>, select a value greater than 1.</p>
    pub fn get_instance_count(&self) -> &::std::option::Option<i32> {
        &self.instance_count
    }
    /// <p>The volume size in GB for the storage volume to be used in processing hyperparameter optimization jobs (optional). These volumes store model artifacts, incremental states and optionally, scratch space for training algorithms. Do not provide a value for this parameter if a value for <code>InstanceConfigs</code> is also specified.</p>
    /// <p>Some instance types have a fixed total local storage size. If you select one of these instances for training, <code>VolumeSizeInGB</code> cannot be greater than this total size. For a list of instance types with local instance storage and their sizes, see <a href="http://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/">instance store volumes</a>.</p><note>
    /// <p>SageMaker supports only the <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html">General Purpose SSD (gp2)</a> storage volume type.</p>
    /// </note>
    pub fn volume_size_in_gb(mut self, input: i32) -> Self {
        self.volume_size_in_gb = ::std::option::Option::Some(input);
        self
    }
    /// <p>The volume size in GB for the storage volume to be used in processing hyperparameter optimization jobs (optional). These volumes store model artifacts, incremental states and optionally, scratch space for training algorithms. Do not provide a value for this parameter if a value for <code>InstanceConfigs</code> is also specified.</p>
    /// <p>Some instance types have a fixed total local storage size. If you select one of these instances for training, <code>VolumeSizeInGB</code> cannot be greater than this total size. For a list of instance types with local instance storage and their sizes, see <a href="http://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/">instance store volumes</a>.</p><note>
    /// <p>SageMaker supports only the <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html">General Purpose SSD (gp2)</a> storage volume type.</p>
    /// </note>
    pub fn set_volume_size_in_gb(mut self, input: ::std::option::Option<i32>) -> Self {
        self.volume_size_in_gb = input;
        self
    }
    /// <p>The volume size in GB for the storage volume to be used in processing hyperparameter optimization jobs (optional). These volumes store model artifacts, incremental states and optionally, scratch space for training algorithms. Do not provide a value for this parameter if a value for <code>InstanceConfigs</code> is also specified.</p>
    /// <p>Some instance types have a fixed total local storage size. If you select one of these instances for training, <code>VolumeSizeInGB</code> cannot be greater than this total size. For a list of instance types with local instance storage and their sizes, see <a href="http://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/">instance store volumes</a>.</p><note>
    /// <p>SageMaker supports only the <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html">General Purpose SSD (gp2)</a> storage volume type.</p>
    /// </note>
    pub fn get_volume_size_in_gb(&self) -> &::std::option::Option<i32> {
        &self.volume_size_in_gb
    }
    /// <p>A key used by Amazon Web Services Key Management Service to encrypt data on the storage volume attached to the compute instances used to run the training job. You can use either of the following formats to specify a key.</p>
    /// <p>KMS Key ID:</p>
    /// <p><code>"1234abcd-12ab-34cd-56ef-1234567890ab"</code></p>
    /// <p>Amazon Resource Name (ARN) of a KMS key:</p>
    /// <p><code>"arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"</code></p>
    /// <p>Some instances use local storage, which use a <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ssd-instance-store.html">hardware module to encrypt</a> storage volumes. If you choose one of these instance types, you cannot request a <code>VolumeKmsKeyId</code>. For a list of instance types that use local storage, see <a href="http://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/">instance store volumes</a>. For more information about Amazon Web Services Key Management Service, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sms-security-kms-permissions.html">KMS encryption</a> for more information.</p>
    pub fn volume_kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A key used by Amazon Web Services Key Management Service to encrypt data on the storage volume attached to the compute instances used to run the training job. You can use either of the following formats to specify a key.</p>
    /// <p>KMS Key ID:</p>
    /// <p><code>"1234abcd-12ab-34cd-56ef-1234567890ab"</code></p>
    /// <p>Amazon Resource Name (ARN) of a KMS key:</p>
    /// <p><code>"arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"</code></p>
    /// <p>Some instances use local storage, which use a <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ssd-instance-store.html">hardware module to encrypt</a> storage volumes. If you choose one of these instance types, you cannot request a <code>VolumeKmsKeyId</code>. For a list of instance types that use local storage, see <a href="http://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/">instance store volumes</a>. For more information about Amazon Web Services Key Management Service, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sms-security-kms-permissions.html">KMS encryption</a> for more information.</p>
    pub fn set_volume_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_kms_key_id = input;
        self
    }
    /// <p>A key used by Amazon Web Services Key Management Service to encrypt data on the storage volume attached to the compute instances used to run the training job. You can use either of the following formats to specify a key.</p>
    /// <p>KMS Key ID:</p>
    /// <p><code>"1234abcd-12ab-34cd-56ef-1234567890ab"</code></p>
    /// <p>Amazon Resource Name (ARN) of a KMS key:</p>
    /// <p><code>"arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"</code></p>
    /// <p>Some instances use local storage, which use a <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ssd-instance-store.html">hardware module to encrypt</a> storage volumes. If you choose one of these instance types, you cannot request a <code>VolumeKmsKeyId</code>. For a list of instance types that use local storage, see <a href="http://aws.amazon.com/releasenotes/host-instance-storage-volumes-table/">instance store volumes</a>. For more information about Amazon Web Services Key Management Service, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sms-security-kms-permissions.html">KMS encryption</a> for more information.</p>
    pub fn get_volume_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_kms_key_id
    }
    /// <p>The strategy that determines the order of preference for resources specified in <code>InstanceConfigs</code> used in hyperparameter optimization.</p>
    pub fn allocation_strategy(mut self, input: crate::types::HyperParameterTuningAllocationStrategy) -> Self {
        self.allocation_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The strategy that determines the order of preference for resources specified in <code>InstanceConfigs</code> used in hyperparameter optimization.</p>
    pub fn set_allocation_strategy(mut self, input: ::std::option::Option<crate::types::HyperParameterTuningAllocationStrategy>) -> Self {
        self.allocation_strategy = input;
        self
    }
    /// <p>The strategy that determines the order of preference for resources specified in <code>InstanceConfigs</code> used in hyperparameter optimization.</p>
    pub fn get_allocation_strategy(&self) -> &::std::option::Option<crate::types::HyperParameterTuningAllocationStrategy> {
        &self.allocation_strategy
    }
    /// Appends an item to `instance_configs`.
    ///
    /// To override the contents of this collection use [`set_instance_configs`](Self::set_instance_configs).
    ///
    /// <p>A list containing the configuration(s) for one or more resources for processing hyperparameter jobs. These resources include compute instances and storage volumes to use in model training jobs launched by hyperparameter tuning jobs. The <code>AllocationStrategy</code> controls the order in which multiple configurations provided in <code>InstanceConfigs</code> are used.</p><note>
    /// <p>If you only want to use a single instance configuration inside the <code>HyperParameterTuningResourceConfig</code> API, do not provide a value for <code>InstanceConfigs</code>. Instead, use <code>InstanceType</code>, <code>VolumeSizeInGB</code> and <code>InstanceCount</code>. If you use <code>InstanceConfigs</code>, do not provide values for <code>InstanceType</code>, <code>VolumeSizeInGB</code> or <code>InstanceCount</code>.</p>
    /// </note>
    pub fn instance_configs(mut self, input: crate::types::HyperParameterTuningInstanceConfig) -> Self {
        let mut v = self.instance_configs.unwrap_or_default();
        v.push(input);
        self.instance_configs = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list containing the configuration(s) for one or more resources for processing hyperparameter jobs. These resources include compute instances and storage volumes to use in model training jobs launched by hyperparameter tuning jobs. The <code>AllocationStrategy</code> controls the order in which multiple configurations provided in <code>InstanceConfigs</code> are used.</p><note>
    /// <p>If you only want to use a single instance configuration inside the <code>HyperParameterTuningResourceConfig</code> API, do not provide a value for <code>InstanceConfigs</code>. Instead, use <code>InstanceType</code>, <code>VolumeSizeInGB</code> and <code>InstanceCount</code>. If you use <code>InstanceConfigs</code>, do not provide values for <code>InstanceType</code>, <code>VolumeSizeInGB</code> or <code>InstanceCount</code>.</p>
    /// </note>
    pub fn set_instance_configs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTuningInstanceConfig>>) -> Self {
        self.instance_configs = input;
        self
    }
    /// <p>A list containing the configuration(s) for one or more resources for processing hyperparameter jobs. These resources include compute instances and storage volumes to use in model training jobs launched by hyperparameter tuning jobs. The <code>AllocationStrategy</code> controls the order in which multiple configurations provided in <code>InstanceConfigs</code> are used.</p><note>
    /// <p>If you only want to use a single instance configuration inside the <code>HyperParameterTuningResourceConfig</code> API, do not provide a value for <code>InstanceConfigs</code>. Instead, use <code>InstanceType</code>, <code>VolumeSizeInGB</code> and <code>InstanceCount</code>. If you use <code>InstanceConfigs</code>, do not provide values for <code>InstanceType</code>, <code>VolumeSizeInGB</code> or <code>InstanceCount</code>.</p>
    /// </note>
    pub fn get_instance_configs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTuningInstanceConfig>> {
        &self.instance_configs
    }
    /// Consumes the builder and constructs a [`HyperParameterTuningResourceConfig`](crate::types::HyperParameterTuningResourceConfig).
    pub fn build(self) -> crate::types::HyperParameterTuningResourceConfig {
        crate::types::HyperParameterTuningResourceConfig {
            instance_type: self.instance_type,
            instance_count: self.instance_count,
            volume_size_in_gb: self.volume_size_in_gb,
            volume_kms_key_id: self.volume_kms_key_id,
            allocation_strategy: self.allocation_strategy,
            instance_configs: self.instance_configs,
        }
    }
}
