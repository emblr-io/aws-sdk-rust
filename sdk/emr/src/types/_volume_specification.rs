// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>EBS volume specifications such as volume type, IOPS, size (GiB) and throughput (MiB/s) that are requested for the EBS volume attached to an Amazon EC2 instance in the cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VolumeSpecification {
    /// <p>The volume type. Volume types supported are gp3, gp2, io1, st1, sc1, and standard.</p>
    pub volume_type: ::std::option::Option<::std::string::String>,
    /// <p>The number of I/O operations per second (IOPS) that the volume supports.</p>
    pub iops: ::std::option::Option<i32>,
    /// <p>The volume size, in gibibytes (GiB). This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.</p>
    pub size_in_gb: ::std::option::Option<i32>,
    /// <p>The throughput, in mebibyte per second (MiB/s). This optional parameter can be a number from 125 - 1000 and is valid only for gp3 volumes.</p>
    pub throughput: ::std::option::Option<i32>,
}
impl VolumeSpecification {
    /// <p>The volume type. Volume types supported are gp3, gp2, io1, st1, sc1, and standard.</p>
    pub fn volume_type(&self) -> ::std::option::Option<&str> {
        self.volume_type.as_deref()
    }
    /// <p>The number of I/O operations per second (IOPS) that the volume supports.</p>
    pub fn iops(&self) -> ::std::option::Option<i32> {
        self.iops
    }
    /// <p>The volume size, in gibibytes (GiB). This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.</p>
    pub fn size_in_gb(&self) -> ::std::option::Option<i32> {
        self.size_in_gb
    }
    /// <p>The throughput, in mebibyte per second (MiB/s). This optional parameter can be a number from 125 - 1000 and is valid only for gp3 volumes.</p>
    pub fn throughput(&self) -> ::std::option::Option<i32> {
        self.throughput
    }
}
impl VolumeSpecification {
    /// Creates a new builder-style object to manufacture [`VolumeSpecification`](crate::types::VolumeSpecification).
    pub fn builder() -> crate::types::builders::VolumeSpecificationBuilder {
        crate::types::builders::VolumeSpecificationBuilder::default()
    }
}

/// A builder for [`VolumeSpecification`](crate::types::VolumeSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VolumeSpecificationBuilder {
    pub(crate) volume_type: ::std::option::Option<::std::string::String>,
    pub(crate) iops: ::std::option::Option<i32>,
    pub(crate) size_in_gb: ::std::option::Option<i32>,
    pub(crate) throughput: ::std::option::Option<i32>,
}
impl VolumeSpecificationBuilder {
    /// <p>The volume type. Volume types supported are gp3, gp2, io1, st1, sc1, and standard.</p>
    /// This field is required.
    pub fn volume_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The volume type. Volume types supported are gp3, gp2, io1, st1, sc1, and standard.</p>
    pub fn set_volume_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_type = input;
        self
    }
    /// <p>The volume type. Volume types supported are gp3, gp2, io1, st1, sc1, and standard.</p>
    pub fn get_volume_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_type
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
    /// <p>The volume size, in gibibytes (GiB). This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.</p>
    /// This field is required.
    pub fn size_in_gb(mut self, input: i32) -> Self {
        self.size_in_gb = ::std::option::Option::Some(input);
        self
    }
    /// <p>The volume size, in gibibytes (GiB). This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.</p>
    pub fn set_size_in_gb(mut self, input: ::std::option::Option<i32>) -> Self {
        self.size_in_gb = input;
        self
    }
    /// <p>The volume size, in gibibytes (GiB). This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.</p>
    pub fn get_size_in_gb(&self) -> &::std::option::Option<i32> {
        &self.size_in_gb
    }
    /// <p>The throughput, in mebibyte per second (MiB/s). This optional parameter can be a number from 125 - 1000 and is valid only for gp3 volumes.</p>
    pub fn throughput(mut self, input: i32) -> Self {
        self.throughput = ::std::option::Option::Some(input);
        self
    }
    /// <p>The throughput, in mebibyte per second (MiB/s). This optional parameter can be a number from 125 - 1000 and is valid only for gp3 volumes.</p>
    pub fn set_throughput(mut self, input: ::std::option::Option<i32>) -> Self {
        self.throughput = input;
        self
    }
    /// <p>The throughput, in mebibyte per second (MiB/s). This optional parameter can be a number from 125 - 1000 and is valid only for gp3 volumes.</p>
    pub fn get_throughput(&self) -> &::std::option::Option<i32> {
        &self.throughput
    }
    /// Consumes the builder and constructs a [`VolumeSpecification`](crate::types::VolumeSpecification).
    pub fn build(self) -> crate::types::VolumeSpecification {
        crate::types::VolumeSpecification {
            volume_type: self.volume_type,
            iops: self.iops,
            size_in_gb: self.size_in_gb,
            throughput: self.throughput,
        }
    }
}
