// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes information used to set up an Amazon EBS volume specified in a block device mapping.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Ebs {
    /// <p>The snapshot ID of the volume to use.</p>
    /// <p>You must specify either a <code>VolumeSize</code> or a <code>SnapshotId</code>.</p>
    pub snapshot_id: ::std::option::Option<::std::string::String>,
    /// <p>The volume size, in GiBs. The following are the supported volumes sizes for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp2</code> and <code>gp3</code>: 1-16,384</p></li>
    /// <li>
    /// <p><code>io1</code>: 4-16,384</p></li>
    /// <li>
    /// <p><code>st1</code> and <code>sc1</code>: 125-16,384</p></li>
    /// <li>
    /// <p><code>standard</code>: 1-1,024</p></li>
    /// </ul>
    /// <p>You must specify either a <code>SnapshotId</code> or a <code>VolumeSize</code>. If you specify both <code>SnapshotId</code> and <code>VolumeSize</code>, the volume size must be equal or greater than the size of the snapshot.</p>
    pub volume_size: ::std::option::Option<i32>,
    /// <p>The volume type. For more information, see <a href="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html">Amazon EBS volume types</a> in the <i>Amazon EBS User Guide</i>.</p>
    /// <p>Valid values: <code>standard</code> | <code>io1</code> | <code>gp2</code> | <code>st1</code> | <code>sc1</code> | <code>gp3</code></p>
    pub volume_type: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the volume is deleted on instance termination. For Amazon EC2 Auto Scaling, the default value is <code>true</code>.</p>
    pub delete_on_termination: ::std::option::Option<bool>,
    /// <p>The number of input/output (I/O) operations per second (IOPS) to provision for the volume. For <code>gp3</code> and <code>io1</code> volumes, this represents the number of IOPS that are provisioned for the volume. For <code>gp2</code> volumes, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting.</p>
    /// <p>The following are the supported values for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp3</code>: 3,000-16,000 IOPS</p></li>
    /// <li>
    /// <p><code>io1</code>: 100-64,000 IOPS</p></li>
    /// </ul>
    /// <p>For <code>io1</code> volumes, we guarantee 64,000 IOPS only for <a href="https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-nitro-instances.html">Instances built on the Amazon Web Services Nitro System</a>. Other instance families guarantee performance up to 32,000 IOPS.</p>
    /// <p><code>Iops</code> is supported when the volume type is <code>gp3</code> or <code>io1</code> and required only when the volume type is <code>io1</code>. (Not used with <code>standard</code>, <code>gp2</code>, <code>st1</code>, or <code>sc1</code> volumes.)</p>
    pub iops: ::std::option::Option<i32>,
    /// <p>Specifies whether the volume should be encrypted. Encrypted EBS volumes can only be attached to instances that support Amazon EBS encryption. For more information, see <a href="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption-requirements.html">Requirements for Amazon EBS encryption</a> in the <i>Amazon EBS User Guide</i>. If your AMI uses encrypted volumes, you can also only launch it on supported instance types.</p><note>
    /// <p>If you are creating a volume from a snapshot, you cannot create an unencrypted volume from an encrypted snapshot. Also, you cannot specify a KMS key ID when using a launch configuration.</p>
    /// <p>If you enable encryption by default, the EBS volumes that you create are always encrypted, either using the Amazon Web Services managed KMS key or a customer-managed KMS key, regardless of whether the snapshot was encrypted.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-data-protection.html#encryption">Use Amazon Web Services KMS keys to encrypt Amazon EBS volumes</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    /// </note>
    pub encrypted: ::std::option::Option<bool>,
    /// <p>The throughput (MiBps) to provision for a <code>gp3</code> volume.</p>
    pub throughput: ::std::option::Option<i32>,
}
impl Ebs {
    /// <p>The snapshot ID of the volume to use.</p>
    /// <p>You must specify either a <code>VolumeSize</code> or a <code>SnapshotId</code>.</p>
    pub fn snapshot_id(&self) -> ::std::option::Option<&str> {
        self.snapshot_id.as_deref()
    }
    /// <p>The volume size, in GiBs. The following are the supported volumes sizes for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp2</code> and <code>gp3</code>: 1-16,384</p></li>
    /// <li>
    /// <p><code>io1</code>: 4-16,384</p></li>
    /// <li>
    /// <p><code>st1</code> and <code>sc1</code>: 125-16,384</p></li>
    /// <li>
    /// <p><code>standard</code>: 1-1,024</p></li>
    /// </ul>
    /// <p>You must specify either a <code>SnapshotId</code> or a <code>VolumeSize</code>. If you specify both <code>SnapshotId</code> and <code>VolumeSize</code>, the volume size must be equal or greater than the size of the snapshot.</p>
    pub fn volume_size(&self) -> ::std::option::Option<i32> {
        self.volume_size
    }
    /// <p>The volume type. For more information, see <a href="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html">Amazon EBS volume types</a> in the <i>Amazon EBS User Guide</i>.</p>
    /// <p>Valid values: <code>standard</code> | <code>io1</code> | <code>gp2</code> | <code>st1</code> | <code>sc1</code> | <code>gp3</code></p>
    pub fn volume_type(&self) -> ::std::option::Option<&str> {
        self.volume_type.as_deref()
    }
    /// <p>Indicates whether the volume is deleted on instance termination. For Amazon EC2 Auto Scaling, the default value is <code>true</code>.</p>
    pub fn delete_on_termination(&self) -> ::std::option::Option<bool> {
        self.delete_on_termination
    }
    /// <p>The number of input/output (I/O) operations per second (IOPS) to provision for the volume. For <code>gp3</code> and <code>io1</code> volumes, this represents the number of IOPS that are provisioned for the volume. For <code>gp2</code> volumes, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting.</p>
    /// <p>The following are the supported values for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp3</code>: 3,000-16,000 IOPS</p></li>
    /// <li>
    /// <p><code>io1</code>: 100-64,000 IOPS</p></li>
    /// </ul>
    /// <p>For <code>io1</code> volumes, we guarantee 64,000 IOPS only for <a href="https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-nitro-instances.html">Instances built on the Amazon Web Services Nitro System</a>. Other instance families guarantee performance up to 32,000 IOPS.</p>
    /// <p><code>Iops</code> is supported when the volume type is <code>gp3</code> or <code>io1</code> and required only when the volume type is <code>io1</code>. (Not used with <code>standard</code>, <code>gp2</code>, <code>st1</code>, or <code>sc1</code> volumes.)</p>
    pub fn iops(&self) -> ::std::option::Option<i32> {
        self.iops
    }
    /// <p>Specifies whether the volume should be encrypted. Encrypted EBS volumes can only be attached to instances that support Amazon EBS encryption. For more information, see <a href="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption-requirements.html">Requirements for Amazon EBS encryption</a> in the <i>Amazon EBS User Guide</i>. If your AMI uses encrypted volumes, you can also only launch it on supported instance types.</p><note>
    /// <p>If you are creating a volume from a snapshot, you cannot create an unencrypted volume from an encrypted snapshot. Also, you cannot specify a KMS key ID when using a launch configuration.</p>
    /// <p>If you enable encryption by default, the EBS volumes that you create are always encrypted, either using the Amazon Web Services managed KMS key or a customer-managed KMS key, regardless of whether the snapshot was encrypted.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-data-protection.html#encryption">Use Amazon Web Services KMS keys to encrypt Amazon EBS volumes</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    /// </note>
    pub fn encrypted(&self) -> ::std::option::Option<bool> {
        self.encrypted
    }
    /// <p>The throughput (MiBps) to provision for a <code>gp3</code> volume.</p>
    pub fn throughput(&self) -> ::std::option::Option<i32> {
        self.throughput
    }
}
impl Ebs {
    /// Creates a new builder-style object to manufacture [`Ebs`](crate::types::Ebs).
    pub fn builder() -> crate::types::builders::EbsBuilder {
        crate::types::builders::EbsBuilder::default()
    }
}

/// A builder for [`Ebs`](crate::types::Ebs).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EbsBuilder {
    pub(crate) snapshot_id: ::std::option::Option<::std::string::String>,
    pub(crate) volume_size: ::std::option::Option<i32>,
    pub(crate) volume_type: ::std::option::Option<::std::string::String>,
    pub(crate) delete_on_termination: ::std::option::Option<bool>,
    pub(crate) iops: ::std::option::Option<i32>,
    pub(crate) encrypted: ::std::option::Option<bool>,
    pub(crate) throughput: ::std::option::Option<i32>,
}
impl EbsBuilder {
    /// <p>The snapshot ID of the volume to use.</p>
    /// <p>You must specify either a <code>VolumeSize</code> or a <code>SnapshotId</code>.</p>
    pub fn snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The snapshot ID of the volume to use.</p>
    /// <p>You must specify either a <code>VolumeSize</code> or a <code>SnapshotId</code>.</p>
    pub fn set_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_id = input;
        self
    }
    /// <p>The snapshot ID of the volume to use.</p>
    /// <p>You must specify either a <code>VolumeSize</code> or a <code>SnapshotId</code>.</p>
    pub fn get_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_id
    }
    /// <p>The volume size, in GiBs. The following are the supported volumes sizes for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp2</code> and <code>gp3</code>: 1-16,384</p></li>
    /// <li>
    /// <p><code>io1</code>: 4-16,384</p></li>
    /// <li>
    /// <p><code>st1</code> and <code>sc1</code>: 125-16,384</p></li>
    /// <li>
    /// <p><code>standard</code>: 1-1,024</p></li>
    /// </ul>
    /// <p>You must specify either a <code>SnapshotId</code> or a <code>VolumeSize</code>. If you specify both <code>SnapshotId</code> and <code>VolumeSize</code>, the volume size must be equal or greater than the size of the snapshot.</p>
    pub fn volume_size(mut self, input: i32) -> Self {
        self.volume_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The volume size, in GiBs. The following are the supported volumes sizes for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp2</code> and <code>gp3</code>: 1-16,384</p></li>
    /// <li>
    /// <p><code>io1</code>: 4-16,384</p></li>
    /// <li>
    /// <p><code>st1</code> and <code>sc1</code>: 125-16,384</p></li>
    /// <li>
    /// <p><code>standard</code>: 1-1,024</p></li>
    /// </ul>
    /// <p>You must specify either a <code>SnapshotId</code> or a <code>VolumeSize</code>. If you specify both <code>SnapshotId</code> and <code>VolumeSize</code>, the volume size must be equal or greater than the size of the snapshot.</p>
    pub fn set_volume_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.volume_size = input;
        self
    }
    /// <p>The volume size, in GiBs. The following are the supported volumes sizes for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp2</code> and <code>gp3</code>: 1-16,384</p></li>
    /// <li>
    /// <p><code>io1</code>: 4-16,384</p></li>
    /// <li>
    /// <p><code>st1</code> and <code>sc1</code>: 125-16,384</p></li>
    /// <li>
    /// <p><code>standard</code>: 1-1,024</p></li>
    /// </ul>
    /// <p>You must specify either a <code>SnapshotId</code> or a <code>VolumeSize</code>. If you specify both <code>SnapshotId</code> and <code>VolumeSize</code>, the volume size must be equal or greater than the size of the snapshot.</p>
    pub fn get_volume_size(&self) -> &::std::option::Option<i32> {
        &self.volume_size
    }
    /// <p>The volume type. For more information, see <a href="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html">Amazon EBS volume types</a> in the <i>Amazon EBS User Guide</i>.</p>
    /// <p>Valid values: <code>standard</code> | <code>io1</code> | <code>gp2</code> | <code>st1</code> | <code>sc1</code> | <code>gp3</code></p>
    pub fn volume_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The volume type. For more information, see <a href="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html">Amazon EBS volume types</a> in the <i>Amazon EBS User Guide</i>.</p>
    /// <p>Valid values: <code>standard</code> | <code>io1</code> | <code>gp2</code> | <code>st1</code> | <code>sc1</code> | <code>gp3</code></p>
    pub fn set_volume_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_type = input;
        self
    }
    /// <p>The volume type. For more information, see <a href="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html">Amazon EBS volume types</a> in the <i>Amazon EBS User Guide</i>.</p>
    /// <p>Valid values: <code>standard</code> | <code>io1</code> | <code>gp2</code> | <code>st1</code> | <code>sc1</code> | <code>gp3</code></p>
    pub fn get_volume_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_type
    }
    /// <p>Indicates whether the volume is deleted on instance termination. For Amazon EC2 Auto Scaling, the default value is <code>true</code>.</p>
    pub fn delete_on_termination(mut self, input: bool) -> Self {
        self.delete_on_termination = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the volume is deleted on instance termination. For Amazon EC2 Auto Scaling, the default value is <code>true</code>.</p>
    pub fn set_delete_on_termination(mut self, input: ::std::option::Option<bool>) -> Self {
        self.delete_on_termination = input;
        self
    }
    /// <p>Indicates whether the volume is deleted on instance termination. For Amazon EC2 Auto Scaling, the default value is <code>true</code>.</p>
    pub fn get_delete_on_termination(&self) -> &::std::option::Option<bool> {
        &self.delete_on_termination
    }
    /// <p>The number of input/output (I/O) operations per second (IOPS) to provision for the volume. For <code>gp3</code> and <code>io1</code> volumes, this represents the number of IOPS that are provisioned for the volume. For <code>gp2</code> volumes, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting.</p>
    /// <p>The following are the supported values for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp3</code>: 3,000-16,000 IOPS</p></li>
    /// <li>
    /// <p><code>io1</code>: 100-64,000 IOPS</p></li>
    /// </ul>
    /// <p>For <code>io1</code> volumes, we guarantee 64,000 IOPS only for <a href="https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-nitro-instances.html">Instances built on the Amazon Web Services Nitro System</a>. Other instance families guarantee performance up to 32,000 IOPS.</p>
    /// <p><code>Iops</code> is supported when the volume type is <code>gp3</code> or <code>io1</code> and required only when the volume type is <code>io1</code>. (Not used with <code>standard</code>, <code>gp2</code>, <code>st1</code>, or <code>sc1</code> volumes.)</p>
    pub fn iops(mut self, input: i32) -> Self {
        self.iops = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of input/output (I/O) operations per second (IOPS) to provision for the volume. For <code>gp3</code> and <code>io1</code> volumes, this represents the number of IOPS that are provisioned for the volume. For <code>gp2</code> volumes, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting.</p>
    /// <p>The following are the supported values for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp3</code>: 3,000-16,000 IOPS</p></li>
    /// <li>
    /// <p><code>io1</code>: 100-64,000 IOPS</p></li>
    /// </ul>
    /// <p>For <code>io1</code> volumes, we guarantee 64,000 IOPS only for <a href="https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-nitro-instances.html">Instances built on the Amazon Web Services Nitro System</a>. Other instance families guarantee performance up to 32,000 IOPS.</p>
    /// <p><code>Iops</code> is supported when the volume type is <code>gp3</code> or <code>io1</code> and required only when the volume type is <code>io1</code>. (Not used with <code>standard</code>, <code>gp2</code>, <code>st1</code>, or <code>sc1</code> volumes.)</p>
    pub fn set_iops(mut self, input: ::std::option::Option<i32>) -> Self {
        self.iops = input;
        self
    }
    /// <p>The number of input/output (I/O) operations per second (IOPS) to provision for the volume. For <code>gp3</code> and <code>io1</code> volumes, this represents the number of IOPS that are provisioned for the volume. For <code>gp2</code> volumes, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting.</p>
    /// <p>The following are the supported values for each volume type:</p>
    /// <ul>
    /// <li>
    /// <p><code>gp3</code>: 3,000-16,000 IOPS</p></li>
    /// <li>
    /// <p><code>io1</code>: 100-64,000 IOPS</p></li>
    /// </ul>
    /// <p>For <code>io1</code> volumes, we guarantee 64,000 IOPS only for <a href="https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-nitro-instances.html">Instances built on the Amazon Web Services Nitro System</a>. Other instance families guarantee performance up to 32,000 IOPS.</p>
    /// <p><code>Iops</code> is supported when the volume type is <code>gp3</code> or <code>io1</code> and required only when the volume type is <code>io1</code>. (Not used with <code>standard</code>, <code>gp2</code>, <code>st1</code>, or <code>sc1</code> volumes.)</p>
    pub fn get_iops(&self) -> &::std::option::Option<i32> {
        &self.iops
    }
    /// <p>Specifies whether the volume should be encrypted. Encrypted EBS volumes can only be attached to instances that support Amazon EBS encryption. For more information, see <a href="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption-requirements.html">Requirements for Amazon EBS encryption</a> in the <i>Amazon EBS User Guide</i>. If your AMI uses encrypted volumes, you can also only launch it on supported instance types.</p><note>
    /// <p>If you are creating a volume from a snapshot, you cannot create an unencrypted volume from an encrypted snapshot. Also, you cannot specify a KMS key ID when using a launch configuration.</p>
    /// <p>If you enable encryption by default, the EBS volumes that you create are always encrypted, either using the Amazon Web Services managed KMS key or a customer-managed KMS key, regardless of whether the snapshot was encrypted.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-data-protection.html#encryption">Use Amazon Web Services KMS keys to encrypt Amazon EBS volumes</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    /// </note>
    pub fn encrypted(mut self, input: bool) -> Self {
        self.encrypted = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the volume should be encrypted. Encrypted EBS volumes can only be attached to instances that support Amazon EBS encryption. For more information, see <a href="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption-requirements.html">Requirements for Amazon EBS encryption</a> in the <i>Amazon EBS User Guide</i>. If your AMI uses encrypted volumes, you can also only launch it on supported instance types.</p><note>
    /// <p>If you are creating a volume from a snapshot, you cannot create an unencrypted volume from an encrypted snapshot. Also, you cannot specify a KMS key ID when using a launch configuration.</p>
    /// <p>If you enable encryption by default, the EBS volumes that you create are always encrypted, either using the Amazon Web Services managed KMS key or a customer-managed KMS key, regardless of whether the snapshot was encrypted.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-data-protection.html#encryption">Use Amazon Web Services KMS keys to encrypt Amazon EBS volumes</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    /// </note>
    pub fn set_encrypted(mut self, input: ::std::option::Option<bool>) -> Self {
        self.encrypted = input;
        self
    }
    /// <p>Specifies whether the volume should be encrypted. Encrypted EBS volumes can only be attached to instances that support Amazon EBS encryption. For more information, see <a href="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption-requirements.html">Requirements for Amazon EBS encryption</a> in the <i>Amazon EBS User Guide</i>. If your AMI uses encrypted volumes, you can also only launch it on supported instance types.</p><note>
    /// <p>If you are creating a volume from a snapshot, you cannot create an unencrypted volume from an encrypted snapshot. Also, you cannot specify a KMS key ID when using a launch configuration.</p>
    /// <p>If you enable encryption by default, the EBS volumes that you create are always encrypted, either using the Amazon Web Services managed KMS key or a customer-managed KMS key, regardless of whether the snapshot was encrypted.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-data-protection.html#encryption">Use Amazon Web Services KMS keys to encrypt Amazon EBS volumes</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    /// </note>
    pub fn get_encrypted(&self) -> &::std::option::Option<bool> {
        &self.encrypted
    }
    /// <p>The throughput (MiBps) to provision for a <code>gp3</code> volume.</p>
    pub fn throughput(mut self, input: i32) -> Self {
        self.throughput = ::std::option::Option::Some(input);
        self
    }
    /// <p>The throughput (MiBps) to provision for a <code>gp3</code> volume.</p>
    pub fn set_throughput(mut self, input: ::std::option::Option<i32>) -> Self {
        self.throughput = input;
        self
    }
    /// <p>The throughput (MiBps) to provision for a <code>gp3</code> volume.</p>
    pub fn get_throughput(&self) -> &::std::option::Option<i32> {
        &self.throughput
    }
    /// Consumes the builder and constructs a [`Ebs`](crate::types::Ebs).
    pub fn build(self) -> crate::types::Ebs {
        crate::types::Ebs {
            snapshot_id: self.snapshot_id,
            volume_size: self.volume_size,
            volume_type: self.volume_type,
            delete_on_termination: self.delete_on_termination,
            iops: self.iops,
            encrypted: self.encrypted,
            throughput: self.throughput,
        }
    }
}
