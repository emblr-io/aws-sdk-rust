// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Launch template disk configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchTemplateDiskConf {
    /// <p>Launch template disk volume type configuration.</p>
    pub volume_type: ::std::option::Option<crate::types::VolumeType>,
    /// <p>Launch template disk iops configuration.</p>
    pub iops: ::std::option::Option<i64>,
    /// <p>Launch template disk throughput configuration.</p>
    pub throughput: ::std::option::Option<i64>,
}
impl LaunchTemplateDiskConf {
    /// <p>Launch template disk volume type configuration.</p>
    pub fn volume_type(&self) -> ::std::option::Option<&crate::types::VolumeType> {
        self.volume_type.as_ref()
    }
    /// <p>Launch template disk iops configuration.</p>
    pub fn iops(&self) -> ::std::option::Option<i64> {
        self.iops
    }
    /// <p>Launch template disk throughput configuration.</p>
    pub fn throughput(&self) -> ::std::option::Option<i64> {
        self.throughput
    }
}
impl LaunchTemplateDiskConf {
    /// Creates a new builder-style object to manufacture [`LaunchTemplateDiskConf`](crate::types::LaunchTemplateDiskConf).
    pub fn builder() -> crate::types::builders::LaunchTemplateDiskConfBuilder {
        crate::types::builders::LaunchTemplateDiskConfBuilder::default()
    }
}

/// A builder for [`LaunchTemplateDiskConf`](crate::types::LaunchTemplateDiskConf).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchTemplateDiskConfBuilder {
    pub(crate) volume_type: ::std::option::Option<crate::types::VolumeType>,
    pub(crate) iops: ::std::option::Option<i64>,
    pub(crate) throughput: ::std::option::Option<i64>,
}
impl LaunchTemplateDiskConfBuilder {
    /// <p>Launch template disk volume type configuration.</p>
    pub fn volume_type(mut self, input: crate::types::VolumeType) -> Self {
        self.volume_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Launch template disk volume type configuration.</p>
    pub fn set_volume_type(mut self, input: ::std::option::Option<crate::types::VolumeType>) -> Self {
        self.volume_type = input;
        self
    }
    /// <p>Launch template disk volume type configuration.</p>
    pub fn get_volume_type(&self) -> &::std::option::Option<crate::types::VolumeType> {
        &self.volume_type
    }
    /// <p>Launch template disk iops configuration.</p>
    pub fn iops(mut self, input: i64) -> Self {
        self.iops = ::std::option::Option::Some(input);
        self
    }
    /// <p>Launch template disk iops configuration.</p>
    pub fn set_iops(mut self, input: ::std::option::Option<i64>) -> Self {
        self.iops = input;
        self
    }
    /// <p>Launch template disk iops configuration.</p>
    pub fn get_iops(&self) -> &::std::option::Option<i64> {
        &self.iops
    }
    /// <p>Launch template disk throughput configuration.</p>
    pub fn throughput(mut self, input: i64) -> Self {
        self.throughput = ::std::option::Option::Some(input);
        self
    }
    /// <p>Launch template disk throughput configuration.</p>
    pub fn set_throughput(mut self, input: ::std::option::Option<i64>) -> Self {
        self.throughput = input;
        self
    }
    /// <p>Launch template disk throughput configuration.</p>
    pub fn get_throughput(&self) -> &::std::option::Option<i64> {
        &self.throughput
    }
    /// Consumes the builder and constructs a [`LaunchTemplateDiskConf`](crate::types::LaunchTemplateDiskConf).
    pub fn build(self) -> crate::types::LaunchTemplateDiskConf {
        crate::types::LaunchTemplateDiskConf {
            volume_type: self.volume_type,
            iops: self.iops,
            throughput: self.throughput,
        }
    }
}
