// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Parameters that are used to automatically set up EBS volumes when an instance is launched.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails {
    /// <p>Whether to delete the volume when the instance is terminated.</p>
    pub delete_on_termination: ::std::option::Option<bool>,
    /// <p>Whether to encrypt the volume.</p>
    pub encrypted: ::std::option::Option<bool>,
    /// <p>The number of input/output (I/O) operations per second (IOPS) to provision for the volume.</p>
    /// <p>Only supported for <code>gp3</code> or <code>io1</code> volumes. Required for <code>io1</code> volumes. Not used with <code>standard</code>, <code>gp2</code>, <code>st1</code>, or <code>sc1</code> volumes.</p>
    pub iops: ::std::option::Option<i32>,
    /// <p>The snapshot ID of the volume to use.</p>
    /// <p>You must specify either <code>VolumeSize</code> or <code>SnapshotId</code>.</p>
    pub snapshot_id: ::std::option::Option<::std::string::String>,
    /// <p>The volume size, in GiBs. The following are the supported volumes sizes for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p>gp2 and gp3: 1-16,384</p></li>
    /// <li>
    /// <p>io1: 4-16,384</p></li>
    /// <li>
    /// <p>st1 and sc1: 125-16,384</p></li>
    /// <li>
    /// <p>standard: 1-1,024</p></li>
    /// </ul>
    /// <p>You must specify either <code>SnapshotId</code> or <code>VolumeSize</code>. If you specify both <code>SnapshotId</code> and <code>VolumeSize</code>, the volume size must be equal or greater than the size of the snapshot.</p>
    pub volume_size: ::std::option::Option<i32>,
    /// <p>The volume type. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp2</code></p></li>
    /// <li>
    /// <p><code>gp3</code></p></li>
    /// <li>
    /// <p><code>io1</code></p></li>
    /// <li>
    /// <p><code>sc1</code></p></li>
    /// <li>
    /// <p><code>st1</code></p></li>
    /// <li>
    /// <p><code>standard</code></p></li>
    /// </ul>
    pub volume_type: ::std::option::Option<::std::string::String>,
}
impl AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails {
    /// <p>Whether to delete the volume when the instance is terminated.</p>
    pub fn delete_on_termination(&self) -> ::std::option::Option<bool> {
        self.delete_on_termination
    }
    /// <p>Whether to encrypt the volume.</p>
    pub fn encrypted(&self) -> ::std::option::Option<bool> {
        self.encrypted
    }
    /// <p>The number of input/output (I/O) operations per second (IOPS) to provision for the volume.</p>
    /// <p>Only supported for <code>gp3</code> or <code>io1</code> volumes. Required for <code>io1</code> volumes. Not used with <code>standard</code>, <code>gp2</code>, <code>st1</code>, or <code>sc1</code> volumes.</p>
    pub fn iops(&self) -> ::std::option::Option<i32> {
        self.iops
    }
    /// <p>The snapshot ID of the volume to use.</p>
    /// <p>You must specify either <code>VolumeSize</code> or <code>SnapshotId</code>.</p>
    pub fn snapshot_id(&self) -> ::std::option::Option<&str> {
        self.snapshot_id.as_deref()
    }
    /// <p>The volume size, in GiBs. The following are the supported volumes sizes for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p>gp2 and gp3: 1-16,384</p></li>
    /// <li>
    /// <p>io1: 4-16,384</p></li>
    /// <li>
    /// <p>st1 and sc1: 125-16,384</p></li>
    /// <li>
    /// <p>standard: 1-1,024</p></li>
    /// </ul>
    /// <p>You must specify either <code>SnapshotId</code> or <code>VolumeSize</code>. If you specify both <code>SnapshotId</code> and <code>VolumeSize</code>, the volume size must be equal or greater than the size of the snapshot.</p>
    pub fn volume_size(&self) -> ::std::option::Option<i32> {
        self.volume_size
    }
    /// <p>The volume type. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp2</code></p></li>
    /// <li>
    /// <p><code>gp3</code></p></li>
    /// <li>
    /// <p><code>io1</code></p></li>
    /// <li>
    /// <p><code>sc1</code></p></li>
    /// <li>
    /// <p><code>st1</code></p></li>
    /// <li>
    /// <p><code>standard</code></p></li>
    /// </ul>
    pub fn volume_type(&self) -> ::std::option::Option<&str> {
        self.volume_type.as_deref()
    }
}
impl AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails {
    /// Creates a new builder-style object to manufacture [`AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails`](crate::types::AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails).
    pub fn builder() -> crate::types::builders::AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetailsBuilder {
        crate::types::builders::AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetailsBuilder::default()
    }
}

/// A builder for [`AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails`](crate::types::AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetailsBuilder {
    pub(crate) delete_on_termination: ::std::option::Option<bool>,
    pub(crate) encrypted: ::std::option::Option<bool>,
    pub(crate) iops: ::std::option::Option<i32>,
    pub(crate) snapshot_id: ::std::option::Option<::std::string::String>,
    pub(crate) volume_size: ::std::option::Option<i32>,
    pub(crate) volume_type: ::std::option::Option<::std::string::String>,
}
impl AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetailsBuilder {
    /// <p>Whether to delete the volume when the instance is terminated.</p>
    pub fn delete_on_termination(mut self, input: bool) -> Self {
        self.delete_on_termination = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to delete the volume when the instance is terminated.</p>
    pub fn set_delete_on_termination(mut self, input: ::std::option::Option<bool>) -> Self {
        self.delete_on_termination = input;
        self
    }
    /// <p>Whether to delete the volume when the instance is terminated.</p>
    pub fn get_delete_on_termination(&self) -> &::std::option::Option<bool> {
        &self.delete_on_termination
    }
    /// <p>Whether to encrypt the volume.</p>
    pub fn encrypted(mut self, input: bool) -> Self {
        self.encrypted = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to encrypt the volume.</p>
    pub fn set_encrypted(mut self, input: ::std::option::Option<bool>) -> Self {
        self.encrypted = input;
        self
    }
    /// <p>Whether to encrypt the volume.</p>
    pub fn get_encrypted(&self) -> &::std::option::Option<bool> {
        &self.encrypted
    }
    /// <p>The number of input/output (I/O) operations per second (IOPS) to provision for the volume.</p>
    /// <p>Only supported for <code>gp3</code> or <code>io1</code> volumes. Required for <code>io1</code> volumes. Not used with <code>standard</code>, <code>gp2</code>, <code>st1</code>, or <code>sc1</code> volumes.</p>
    pub fn iops(mut self, input: i32) -> Self {
        self.iops = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of input/output (I/O) operations per second (IOPS) to provision for the volume.</p>
    /// <p>Only supported for <code>gp3</code> or <code>io1</code> volumes. Required for <code>io1</code> volumes. Not used with <code>standard</code>, <code>gp2</code>, <code>st1</code>, or <code>sc1</code> volumes.</p>
    pub fn set_iops(mut self, input: ::std::option::Option<i32>) -> Self {
        self.iops = input;
        self
    }
    /// <p>The number of input/output (I/O) operations per second (IOPS) to provision for the volume.</p>
    /// <p>Only supported for <code>gp3</code> or <code>io1</code> volumes. Required for <code>io1</code> volumes. Not used with <code>standard</code>, <code>gp2</code>, <code>st1</code>, or <code>sc1</code> volumes.</p>
    pub fn get_iops(&self) -> &::std::option::Option<i32> {
        &self.iops
    }
    /// <p>The snapshot ID of the volume to use.</p>
    /// <p>You must specify either <code>VolumeSize</code> or <code>SnapshotId</code>.</p>
    pub fn snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The snapshot ID of the volume to use.</p>
    /// <p>You must specify either <code>VolumeSize</code> or <code>SnapshotId</code>.</p>
    pub fn set_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_id = input;
        self
    }
    /// <p>The snapshot ID of the volume to use.</p>
    /// <p>You must specify either <code>VolumeSize</code> or <code>SnapshotId</code>.</p>
    pub fn get_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_id
    }
    /// <p>The volume size, in GiBs. The following are the supported volumes sizes for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p>gp2 and gp3: 1-16,384</p></li>
    /// <li>
    /// <p>io1: 4-16,384</p></li>
    /// <li>
    /// <p>st1 and sc1: 125-16,384</p></li>
    /// <li>
    /// <p>standard: 1-1,024</p></li>
    /// </ul>
    /// <p>You must specify either <code>SnapshotId</code> or <code>VolumeSize</code>. If you specify both <code>SnapshotId</code> and <code>VolumeSize</code>, the volume size must be equal or greater than the size of the snapshot.</p>
    pub fn volume_size(mut self, input: i32) -> Self {
        self.volume_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The volume size, in GiBs. The following are the supported volumes sizes for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p>gp2 and gp3: 1-16,384</p></li>
    /// <li>
    /// <p>io1: 4-16,384</p></li>
    /// <li>
    /// <p>st1 and sc1: 125-16,384</p></li>
    /// <li>
    /// <p>standard: 1-1,024</p></li>
    /// </ul>
    /// <p>You must specify either <code>SnapshotId</code> or <code>VolumeSize</code>. If you specify both <code>SnapshotId</code> and <code>VolumeSize</code>, the volume size must be equal or greater than the size of the snapshot.</p>
    pub fn set_volume_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.volume_size = input;
        self
    }
    /// <p>The volume size, in GiBs. The following are the supported volumes sizes for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p>gp2 and gp3: 1-16,384</p></li>
    /// <li>
    /// <p>io1: 4-16,384</p></li>
    /// <li>
    /// <p>st1 and sc1: 125-16,384</p></li>
    /// <li>
    /// <p>standard: 1-1,024</p></li>
    /// </ul>
    /// <p>You must specify either <code>SnapshotId</code> or <code>VolumeSize</code>. If you specify both <code>SnapshotId</code> and <code>VolumeSize</code>, the volume size must be equal or greater than the size of the snapshot.</p>
    pub fn get_volume_size(&self) -> &::std::option::Option<i32> {
        &self.volume_size
    }
    /// <p>The volume type. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp2</code></p></li>
    /// <li>
    /// <p><code>gp3</code></p></li>
    /// <li>
    /// <p><code>io1</code></p></li>
    /// <li>
    /// <p><code>sc1</code></p></li>
    /// <li>
    /// <p><code>st1</code></p></li>
    /// <li>
    /// <p><code>standard</code></p></li>
    /// </ul>
    pub fn volume_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The volume type. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp2</code></p></li>
    /// <li>
    /// <p><code>gp3</code></p></li>
    /// <li>
    /// <p><code>io1</code></p></li>
    /// <li>
    /// <p><code>sc1</code></p></li>
    /// <li>
    /// <p><code>st1</code></p></li>
    /// <li>
    /// <p><code>standard</code></p></li>
    /// </ul>
    pub fn set_volume_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_type = input;
        self
    }
    /// <p>The volume type. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp2</code></p></li>
    /// <li>
    /// <p><code>gp3</code></p></li>
    /// <li>
    /// <p><code>io1</code></p></li>
    /// <li>
    /// <p><code>sc1</code></p></li>
    /// <li>
    /// <p><code>st1</code></p></li>
    /// <li>
    /// <p><code>standard</code></p></li>
    /// </ul>
    pub fn get_volume_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_type
    }
    /// Consumes the builder and constructs a [`AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails`](crate::types::AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails).
    pub fn build(self) -> crate::types::AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails {
        crate::types::AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails {
            delete_on_termination: self.delete_on_termination,
            encrypted: self.encrypted,
            iops: self.iops,
            snapshot_id: self.snapshot_id,
            volume_size: self.volume_size,
            volume_type: self.volume_type,
        }
    }
}
