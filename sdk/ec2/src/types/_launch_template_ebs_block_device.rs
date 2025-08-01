// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a block device for an EBS volume.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchTemplateEbsBlockDevice {
    /// <p>Indicates whether the EBS volume is encrypted.</p>
    pub encrypted: ::std::option::Option<bool>,
    /// <p>Indicates whether the EBS volume is deleted on instance termination.</p>
    pub delete_on_termination: ::std::option::Option<bool>,
    /// <p>The number of I/O operations per second (IOPS) that the volume supports.</p>
    pub iops: ::std::option::Option<i32>,
    /// <p>Identifier (key ID, key alias, key ARN, or alias ARN) of the customer managed KMS key to use for EBS encryption.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the snapshot.</p>
    pub snapshot_id: ::std::option::Option<::std::string::String>,
    /// <p>The size of the volume, in GiB.</p>
    pub volume_size: ::std::option::Option<i32>,
    /// <p>The volume type.</p>
    pub volume_type: ::std::option::Option<crate::types::VolumeType>,
    /// <p>The throughput that the volume supports, in MiB/s.</p>
    pub throughput: ::std::option::Option<i32>,
    /// <p>The Amazon EBS Provisioned Rate for Volume Initialization (volume initialization rate) specified for the volume, in MiB/s. If no volume initialization rate was specified, the value is <code>null</code>.</p>
    pub volume_initialization_rate: ::std::option::Option<i32>,
}
impl LaunchTemplateEbsBlockDevice {
    /// <p>Indicates whether the EBS volume is encrypted.</p>
    pub fn encrypted(&self) -> ::std::option::Option<bool> {
        self.encrypted
    }
    /// <p>Indicates whether the EBS volume is deleted on instance termination.</p>
    pub fn delete_on_termination(&self) -> ::std::option::Option<bool> {
        self.delete_on_termination
    }
    /// <p>The number of I/O operations per second (IOPS) that the volume supports.</p>
    pub fn iops(&self) -> ::std::option::Option<i32> {
        self.iops
    }
    /// <p>Identifier (key ID, key alias, key ARN, or alias ARN) of the customer managed KMS key to use for EBS encryption.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>The ID of the snapshot.</p>
    pub fn snapshot_id(&self) -> ::std::option::Option<&str> {
        self.snapshot_id.as_deref()
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn volume_size(&self) -> ::std::option::Option<i32> {
        self.volume_size
    }
    /// <p>The volume type.</p>
    pub fn volume_type(&self) -> ::std::option::Option<&crate::types::VolumeType> {
        self.volume_type.as_ref()
    }
    /// <p>The throughput that the volume supports, in MiB/s.</p>
    pub fn throughput(&self) -> ::std::option::Option<i32> {
        self.throughput
    }
    /// <p>The Amazon EBS Provisioned Rate for Volume Initialization (volume initialization rate) specified for the volume, in MiB/s. If no volume initialization rate was specified, the value is <code>null</code>.</p>
    pub fn volume_initialization_rate(&self) -> ::std::option::Option<i32> {
        self.volume_initialization_rate
    }
}
impl LaunchTemplateEbsBlockDevice {
    /// Creates a new builder-style object to manufacture [`LaunchTemplateEbsBlockDevice`](crate::types::LaunchTemplateEbsBlockDevice).
    pub fn builder() -> crate::types::builders::LaunchTemplateEbsBlockDeviceBuilder {
        crate::types::builders::LaunchTemplateEbsBlockDeviceBuilder::default()
    }
}

/// A builder for [`LaunchTemplateEbsBlockDevice`](crate::types::LaunchTemplateEbsBlockDevice).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchTemplateEbsBlockDeviceBuilder {
    pub(crate) encrypted: ::std::option::Option<bool>,
    pub(crate) delete_on_termination: ::std::option::Option<bool>,
    pub(crate) iops: ::std::option::Option<i32>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) snapshot_id: ::std::option::Option<::std::string::String>,
    pub(crate) volume_size: ::std::option::Option<i32>,
    pub(crate) volume_type: ::std::option::Option<crate::types::VolumeType>,
    pub(crate) throughput: ::std::option::Option<i32>,
    pub(crate) volume_initialization_rate: ::std::option::Option<i32>,
}
impl LaunchTemplateEbsBlockDeviceBuilder {
    /// <p>Indicates whether the EBS volume is encrypted.</p>
    pub fn encrypted(mut self, input: bool) -> Self {
        self.encrypted = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the EBS volume is encrypted.</p>
    pub fn set_encrypted(mut self, input: ::std::option::Option<bool>) -> Self {
        self.encrypted = input;
        self
    }
    /// <p>Indicates whether the EBS volume is encrypted.</p>
    pub fn get_encrypted(&self) -> &::std::option::Option<bool> {
        &self.encrypted
    }
    /// <p>Indicates whether the EBS volume is deleted on instance termination.</p>
    pub fn delete_on_termination(mut self, input: bool) -> Self {
        self.delete_on_termination = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the EBS volume is deleted on instance termination.</p>
    pub fn set_delete_on_termination(mut self, input: ::std::option::Option<bool>) -> Self {
        self.delete_on_termination = input;
        self
    }
    /// <p>Indicates whether the EBS volume is deleted on instance termination.</p>
    pub fn get_delete_on_termination(&self) -> &::std::option::Option<bool> {
        &self.delete_on_termination
    }
    /// <p>The number of I/O operations per second (IOPS) that the volume supports.</p>
    pub fn iops(mut self, input: i32) -> Self {
        self.iops = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of I/O operations per second (IOPS) that the volume supports.</p>
    pub fn set_iops(mut self, input: ::std::option::Option<i32>) -> Self {
        self.iops = input;
        self
    }
    /// <p>The number of I/O operations per second (IOPS) that the volume supports.</p>
    pub fn get_iops(&self) -> &::std::option::Option<i32> {
        &self.iops
    }
    /// <p>Identifier (key ID, key alias, key ARN, or alias ARN) of the customer managed KMS key to use for EBS encryption.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier (key ID, key alias, key ARN, or alias ARN) of the customer managed KMS key to use for EBS encryption.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>Identifier (key ID, key alias, key ARN, or alias ARN) of the customer managed KMS key to use for EBS encryption.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>The ID of the snapshot.</p>
    pub fn snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the snapshot.</p>
    pub fn set_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_id = input;
        self
    }
    /// <p>The ID of the snapshot.</p>
    pub fn get_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_id
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn volume_size(mut self, input: i32) -> Self {
        self.volume_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn set_volume_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.volume_size = input;
        self
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn get_volume_size(&self) -> &::std::option::Option<i32> {
        &self.volume_size
    }
    /// <p>The volume type.</p>
    pub fn volume_type(mut self, input: crate::types::VolumeType) -> Self {
        self.volume_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The volume type.</p>
    pub fn set_volume_type(mut self, input: ::std::option::Option<crate::types::VolumeType>) -> Self {
        self.volume_type = input;
        self
    }
    /// <p>The volume type.</p>
    pub fn get_volume_type(&self) -> &::std::option::Option<crate::types::VolumeType> {
        &self.volume_type
    }
    /// <p>The throughput that the volume supports, in MiB/s.</p>
    pub fn throughput(mut self, input: i32) -> Self {
        self.throughput = ::std::option::Option::Some(input);
        self
    }
    /// <p>The throughput that the volume supports, in MiB/s.</p>
    pub fn set_throughput(mut self, input: ::std::option::Option<i32>) -> Self {
        self.throughput = input;
        self
    }
    /// <p>The throughput that the volume supports, in MiB/s.</p>
    pub fn get_throughput(&self) -> &::std::option::Option<i32> {
        &self.throughput
    }
    /// <p>The Amazon EBS Provisioned Rate for Volume Initialization (volume initialization rate) specified for the volume, in MiB/s. If no volume initialization rate was specified, the value is <code>null</code>.</p>
    pub fn volume_initialization_rate(mut self, input: i32) -> Self {
        self.volume_initialization_rate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon EBS Provisioned Rate for Volume Initialization (volume initialization rate) specified for the volume, in MiB/s. If no volume initialization rate was specified, the value is <code>null</code>.</p>
    pub fn set_volume_initialization_rate(mut self, input: ::std::option::Option<i32>) -> Self {
        self.volume_initialization_rate = input;
        self
    }
    /// <p>The Amazon EBS Provisioned Rate for Volume Initialization (volume initialization rate) specified for the volume, in MiB/s. If no volume initialization rate was specified, the value is <code>null</code>.</p>
    pub fn get_volume_initialization_rate(&self) -> &::std::option::Option<i32> {
        &self.volume_initialization_rate
    }
    /// Consumes the builder and constructs a [`LaunchTemplateEbsBlockDevice`](crate::types::LaunchTemplateEbsBlockDevice).
    pub fn build(self) -> crate::types::LaunchTemplateEbsBlockDevice {
        crate::types::LaunchTemplateEbsBlockDevice {
            encrypted: self.encrypted,
            delete_on_termination: self.delete_on_termination,
            iops: self.iops,
            kms_key_id: self.kms_key_id,
            snapshot_id: self.snapshot_id,
            volume_size: self.volume_size,
            volume_type: self.volume_type,
            throughput: self.throughput,
            volume_initialization_rate: self.volume_initialization_rate,
        }
    }
}
