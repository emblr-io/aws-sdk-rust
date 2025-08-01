// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing a block storage device on the Recovery Instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecoveryInstanceDisk {
    /// <p>The internal device name of this disk. This is the name that is visible on the machine itself and not from the EC2 console.</p>
    pub internal_device_name: ::std::option::Option<::std::string::String>,
    /// <p>The amount of storage on the disk in bytes.</p>
    pub bytes: i64,
    /// <p>The EBS Volume ID of this disk.</p>
    pub ebs_volume_id: ::std::option::Option<::std::string::String>,
}
impl RecoveryInstanceDisk {
    /// <p>The internal device name of this disk. This is the name that is visible on the machine itself and not from the EC2 console.</p>
    pub fn internal_device_name(&self) -> ::std::option::Option<&str> {
        self.internal_device_name.as_deref()
    }
    /// <p>The amount of storage on the disk in bytes.</p>
    pub fn bytes(&self) -> i64 {
        self.bytes
    }
    /// <p>The EBS Volume ID of this disk.</p>
    pub fn ebs_volume_id(&self) -> ::std::option::Option<&str> {
        self.ebs_volume_id.as_deref()
    }
}
impl RecoveryInstanceDisk {
    /// Creates a new builder-style object to manufacture [`RecoveryInstanceDisk`](crate::types::RecoveryInstanceDisk).
    pub fn builder() -> crate::types::builders::RecoveryInstanceDiskBuilder {
        crate::types::builders::RecoveryInstanceDiskBuilder::default()
    }
}

/// A builder for [`RecoveryInstanceDisk`](crate::types::RecoveryInstanceDisk).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecoveryInstanceDiskBuilder {
    pub(crate) internal_device_name: ::std::option::Option<::std::string::String>,
    pub(crate) bytes: ::std::option::Option<i64>,
    pub(crate) ebs_volume_id: ::std::option::Option<::std::string::String>,
}
impl RecoveryInstanceDiskBuilder {
    /// <p>The internal device name of this disk. This is the name that is visible on the machine itself and not from the EC2 console.</p>
    pub fn internal_device_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.internal_device_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The internal device name of this disk. This is the name that is visible on the machine itself and not from the EC2 console.</p>
    pub fn set_internal_device_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.internal_device_name = input;
        self
    }
    /// <p>The internal device name of this disk. This is the name that is visible on the machine itself and not from the EC2 console.</p>
    pub fn get_internal_device_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.internal_device_name
    }
    /// <p>The amount of storage on the disk in bytes.</p>
    pub fn bytes(mut self, input: i64) -> Self {
        self.bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of storage on the disk in bytes.</p>
    pub fn set_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.bytes = input;
        self
    }
    /// <p>The amount of storage on the disk in bytes.</p>
    pub fn get_bytes(&self) -> &::std::option::Option<i64> {
        &self.bytes
    }
    /// <p>The EBS Volume ID of this disk.</p>
    pub fn ebs_volume_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ebs_volume_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The EBS Volume ID of this disk.</p>
    pub fn set_ebs_volume_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ebs_volume_id = input;
        self
    }
    /// <p>The EBS Volume ID of this disk.</p>
    pub fn get_ebs_volume_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ebs_volume_id
    }
    /// Consumes the builder and constructs a [`RecoveryInstanceDisk`](crate::types::RecoveryInstanceDisk).
    pub fn build(self) -> crate::types::RecoveryInstanceDisk {
        crate::types::RecoveryInstanceDisk {
            internal_device_name: self.internal_device_name,
            bytes: self.bytes.unwrap_or_default(),
            ebs_volume_id: self.ebs_volume_id,
        }
    }
}
