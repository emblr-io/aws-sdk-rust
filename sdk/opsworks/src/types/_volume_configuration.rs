// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an Amazon EBS volume configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VolumeConfiguration {
    /// <p>The volume mount point. For example "/dev/sdh".</p>
    pub mount_point: ::std::string::String,
    /// <p>The volume <a href="http://en.wikipedia.org/wiki/Standard_RAID_levels">RAID level</a>.</p>
    pub raid_level: ::std::option::Option<i32>,
    /// <p>The number of disks in the volume.</p>
    pub number_of_disks: i32,
    /// <p>The volume size.</p>
    pub size: i32,
    /// <p>The volume type. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html"> Amazon EBS Volume Types</a>.</p>
    /// <ul>
    /// <li>
    /// <p><code>standard</code> - Magnetic. Magnetic volumes must have a minimum size of 1 GiB and a maximum size of 1024 GiB.</p></li>
    /// <li>
    /// <p><code>io1</code> - Provisioned IOPS (SSD). PIOPS volumes must have a minimum size of 4 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>gp2</code> - General Purpose (SSD). General purpose volumes must have a minimum size of 1 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>st1</code> - Throughput Optimized hard disk drive (HDD). Throughput optimized HDD volumes must have a minimum size of 125 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>sc1</code> - Cold HDD. Cold HDD volumes must have a minimum size of 125 GiB and a maximum size of 16384 GiB.</p></li>
    /// </ul>
    pub volume_type: ::std::option::Option<::std::string::String>,
    /// <p>For PIOPS volumes, the IOPS per disk.</p>
    pub iops: ::std::option::Option<i32>,
    /// <p>Specifies whether an Amazon EBS volume is encrypted. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html">Amazon EBS Encryption</a>.</p>
    pub encrypted: ::std::option::Option<bool>,
}
impl VolumeConfiguration {
    /// <p>The volume mount point. For example "/dev/sdh".</p>
    pub fn mount_point(&self) -> &str {
        use std::ops::Deref;
        self.mount_point.deref()
    }
    /// <p>The volume <a href="http://en.wikipedia.org/wiki/Standard_RAID_levels">RAID level</a>.</p>
    pub fn raid_level(&self) -> ::std::option::Option<i32> {
        self.raid_level
    }
    /// <p>The number of disks in the volume.</p>
    pub fn number_of_disks(&self) -> i32 {
        self.number_of_disks
    }
    /// <p>The volume size.</p>
    pub fn size(&self) -> i32 {
        self.size
    }
    /// <p>The volume type. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html"> Amazon EBS Volume Types</a>.</p>
    /// <ul>
    /// <li>
    /// <p><code>standard</code> - Magnetic. Magnetic volumes must have a minimum size of 1 GiB and a maximum size of 1024 GiB.</p></li>
    /// <li>
    /// <p><code>io1</code> - Provisioned IOPS (SSD). PIOPS volumes must have a minimum size of 4 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>gp2</code> - General Purpose (SSD). General purpose volumes must have a minimum size of 1 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>st1</code> - Throughput Optimized hard disk drive (HDD). Throughput optimized HDD volumes must have a minimum size of 125 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>sc1</code> - Cold HDD. Cold HDD volumes must have a minimum size of 125 GiB and a maximum size of 16384 GiB.</p></li>
    /// </ul>
    pub fn volume_type(&self) -> ::std::option::Option<&str> {
        self.volume_type.as_deref()
    }
    /// <p>For PIOPS volumes, the IOPS per disk.</p>
    pub fn iops(&self) -> ::std::option::Option<i32> {
        self.iops
    }
    /// <p>Specifies whether an Amazon EBS volume is encrypted. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html">Amazon EBS Encryption</a>.</p>
    pub fn encrypted(&self) -> ::std::option::Option<bool> {
        self.encrypted
    }
}
impl VolumeConfiguration {
    /// Creates a new builder-style object to manufacture [`VolumeConfiguration`](crate::types::VolumeConfiguration).
    pub fn builder() -> crate::types::builders::VolumeConfigurationBuilder {
        crate::types::builders::VolumeConfigurationBuilder::default()
    }
}

/// A builder for [`VolumeConfiguration`](crate::types::VolumeConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VolumeConfigurationBuilder {
    pub(crate) mount_point: ::std::option::Option<::std::string::String>,
    pub(crate) raid_level: ::std::option::Option<i32>,
    pub(crate) number_of_disks: ::std::option::Option<i32>,
    pub(crate) size: ::std::option::Option<i32>,
    pub(crate) volume_type: ::std::option::Option<::std::string::String>,
    pub(crate) iops: ::std::option::Option<i32>,
    pub(crate) encrypted: ::std::option::Option<bool>,
}
impl VolumeConfigurationBuilder {
    /// <p>The volume mount point. For example "/dev/sdh".</p>
    /// This field is required.
    pub fn mount_point(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mount_point = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The volume mount point. For example "/dev/sdh".</p>
    pub fn set_mount_point(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mount_point = input;
        self
    }
    /// <p>The volume mount point. For example "/dev/sdh".</p>
    pub fn get_mount_point(&self) -> &::std::option::Option<::std::string::String> {
        &self.mount_point
    }
    /// <p>The volume <a href="http://en.wikipedia.org/wiki/Standard_RAID_levels">RAID level</a>.</p>
    pub fn raid_level(mut self, input: i32) -> Self {
        self.raid_level = ::std::option::Option::Some(input);
        self
    }
    /// <p>The volume <a href="http://en.wikipedia.org/wiki/Standard_RAID_levels">RAID level</a>.</p>
    pub fn set_raid_level(mut self, input: ::std::option::Option<i32>) -> Self {
        self.raid_level = input;
        self
    }
    /// <p>The volume <a href="http://en.wikipedia.org/wiki/Standard_RAID_levels">RAID level</a>.</p>
    pub fn get_raid_level(&self) -> &::std::option::Option<i32> {
        &self.raid_level
    }
    /// <p>The number of disks in the volume.</p>
    /// This field is required.
    pub fn number_of_disks(mut self, input: i32) -> Self {
        self.number_of_disks = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of disks in the volume.</p>
    pub fn set_number_of_disks(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_disks = input;
        self
    }
    /// <p>The number of disks in the volume.</p>
    pub fn get_number_of_disks(&self) -> &::std::option::Option<i32> {
        &self.number_of_disks
    }
    /// <p>The volume size.</p>
    /// This field is required.
    pub fn size(mut self, input: i32) -> Self {
        self.size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The volume size.</p>
    pub fn set_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.size = input;
        self
    }
    /// <p>The volume size.</p>
    pub fn get_size(&self) -> &::std::option::Option<i32> {
        &self.size
    }
    /// <p>The volume type. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html"> Amazon EBS Volume Types</a>.</p>
    /// <ul>
    /// <li>
    /// <p><code>standard</code> - Magnetic. Magnetic volumes must have a minimum size of 1 GiB and a maximum size of 1024 GiB.</p></li>
    /// <li>
    /// <p><code>io1</code> - Provisioned IOPS (SSD). PIOPS volumes must have a minimum size of 4 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>gp2</code> - General Purpose (SSD). General purpose volumes must have a minimum size of 1 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>st1</code> - Throughput Optimized hard disk drive (HDD). Throughput optimized HDD volumes must have a minimum size of 125 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>sc1</code> - Cold HDD. Cold HDD volumes must have a minimum size of 125 GiB and a maximum size of 16384 GiB.</p></li>
    /// </ul>
    pub fn volume_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The volume type. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html"> Amazon EBS Volume Types</a>.</p>
    /// <ul>
    /// <li>
    /// <p><code>standard</code> - Magnetic. Magnetic volumes must have a minimum size of 1 GiB and a maximum size of 1024 GiB.</p></li>
    /// <li>
    /// <p><code>io1</code> - Provisioned IOPS (SSD). PIOPS volumes must have a minimum size of 4 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>gp2</code> - General Purpose (SSD). General purpose volumes must have a minimum size of 1 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>st1</code> - Throughput Optimized hard disk drive (HDD). Throughput optimized HDD volumes must have a minimum size of 125 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>sc1</code> - Cold HDD. Cold HDD volumes must have a minimum size of 125 GiB and a maximum size of 16384 GiB.</p></li>
    /// </ul>
    pub fn set_volume_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_type = input;
        self
    }
    /// <p>The volume type. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html"> Amazon EBS Volume Types</a>.</p>
    /// <ul>
    /// <li>
    /// <p><code>standard</code> - Magnetic. Magnetic volumes must have a minimum size of 1 GiB and a maximum size of 1024 GiB.</p></li>
    /// <li>
    /// <p><code>io1</code> - Provisioned IOPS (SSD). PIOPS volumes must have a minimum size of 4 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>gp2</code> - General Purpose (SSD). General purpose volumes must have a minimum size of 1 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>st1</code> - Throughput Optimized hard disk drive (HDD). Throughput optimized HDD volumes must have a minimum size of 125 GiB and a maximum size of 16384 GiB.</p></li>
    /// <li>
    /// <p><code>sc1</code> - Cold HDD. Cold HDD volumes must have a minimum size of 125 GiB and a maximum size of 16384 GiB.</p></li>
    /// </ul>
    pub fn get_volume_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_type
    }
    /// <p>For PIOPS volumes, the IOPS per disk.</p>
    pub fn iops(mut self, input: i32) -> Self {
        self.iops = ::std::option::Option::Some(input);
        self
    }
    /// <p>For PIOPS volumes, the IOPS per disk.</p>
    pub fn set_iops(mut self, input: ::std::option::Option<i32>) -> Self {
        self.iops = input;
        self
    }
    /// <p>For PIOPS volumes, the IOPS per disk.</p>
    pub fn get_iops(&self) -> &::std::option::Option<i32> {
        &self.iops
    }
    /// <p>Specifies whether an Amazon EBS volume is encrypted. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html">Amazon EBS Encryption</a>.</p>
    pub fn encrypted(mut self, input: bool) -> Self {
        self.encrypted = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether an Amazon EBS volume is encrypted. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html">Amazon EBS Encryption</a>.</p>
    pub fn set_encrypted(mut self, input: ::std::option::Option<bool>) -> Self {
        self.encrypted = input;
        self
    }
    /// <p>Specifies whether an Amazon EBS volume is encrypted. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html">Amazon EBS Encryption</a>.</p>
    pub fn get_encrypted(&self) -> &::std::option::Option<bool> {
        &self.encrypted
    }
    /// Consumes the builder and constructs a [`VolumeConfiguration`](crate::types::VolumeConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`mount_point`](crate::types::builders::VolumeConfigurationBuilder::mount_point)
    /// - [`number_of_disks`](crate::types::builders::VolumeConfigurationBuilder::number_of_disks)
    /// - [`size`](crate::types::builders::VolumeConfigurationBuilder::size)
    pub fn build(self) -> ::std::result::Result<crate::types::VolumeConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VolumeConfiguration {
            mount_point: self.mount_point.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "mount_point",
                    "mount_point was not specified but it is required when building VolumeConfiguration",
                )
            })?,
            raid_level: self.raid_level,
            number_of_disks: self.number_of_disks.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "number_of_disks",
                    "number_of_disks was not specified but it is required when building VolumeConfiguration",
                )
            })?,
            size: self.size.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "size",
                    "size was not specified but it is required when building VolumeConfiguration",
                )
            })?,
            volume_type: self.volume_type,
            iops: self.iops,
            encrypted: self.encrypted,
        })
    }
}
