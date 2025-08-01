// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the instance store features that are supported by the instance type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstanceStorageInfo {
    /// <p>The total size of the disks, in GB.</p>
    pub total_size_in_gb: ::std::option::Option<i64>,
    /// <p>Describes the disks that are available for the instance type.</p>
    pub disks: ::std::option::Option<::std::vec::Vec<crate::types::DiskInfo>>,
    /// <p>Indicates whether non-volatile memory express (NVMe) is supported.</p>
    pub nvme_support: ::std::option::Option<crate::types::EphemeralNvmeSupport>,
    /// <p>Indicates whether data is encrypted at rest.</p>
    pub encryption_support: ::std::option::Option<crate::types::InstanceStorageEncryptionSupport>,
}
impl InstanceStorageInfo {
    /// <p>The total size of the disks, in GB.</p>
    pub fn total_size_in_gb(&self) -> ::std::option::Option<i64> {
        self.total_size_in_gb
    }
    /// <p>Describes the disks that are available for the instance type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.disks.is_none()`.
    pub fn disks(&self) -> &[crate::types::DiskInfo] {
        self.disks.as_deref().unwrap_or_default()
    }
    /// <p>Indicates whether non-volatile memory express (NVMe) is supported.</p>
    pub fn nvme_support(&self) -> ::std::option::Option<&crate::types::EphemeralNvmeSupport> {
        self.nvme_support.as_ref()
    }
    /// <p>Indicates whether data is encrypted at rest.</p>
    pub fn encryption_support(&self) -> ::std::option::Option<&crate::types::InstanceStorageEncryptionSupport> {
        self.encryption_support.as_ref()
    }
}
impl InstanceStorageInfo {
    /// Creates a new builder-style object to manufacture [`InstanceStorageInfo`](crate::types::InstanceStorageInfo).
    pub fn builder() -> crate::types::builders::InstanceStorageInfoBuilder {
        crate::types::builders::InstanceStorageInfoBuilder::default()
    }
}

/// A builder for [`InstanceStorageInfo`](crate::types::InstanceStorageInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstanceStorageInfoBuilder {
    pub(crate) total_size_in_gb: ::std::option::Option<i64>,
    pub(crate) disks: ::std::option::Option<::std::vec::Vec<crate::types::DiskInfo>>,
    pub(crate) nvme_support: ::std::option::Option<crate::types::EphemeralNvmeSupport>,
    pub(crate) encryption_support: ::std::option::Option<crate::types::InstanceStorageEncryptionSupport>,
}
impl InstanceStorageInfoBuilder {
    /// <p>The total size of the disks, in GB.</p>
    pub fn total_size_in_gb(mut self, input: i64) -> Self {
        self.total_size_in_gb = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total size of the disks, in GB.</p>
    pub fn set_total_size_in_gb(mut self, input: ::std::option::Option<i64>) -> Self {
        self.total_size_in_gb = input;
        self
    }
    /// <p>The total size of the disks, in GB.</p>
    pub fn get_total_size_in_gb(&self) -> &::std::option::Option<i64> {
        &self.total_size_in_gb
    }
    /// Appends an item to `disks`.
    ///
    /// To override the contents of this collection use [`set_disks`](Self::set_disks).
    ///
    /// <p>Describes the disks that are available for the instance type.</p>
    pub fn disks(mut self, input: crate::types::DiskInfo) -> Self {
        let mut v = self.disks.unwrap_or_default();
        v.push(input);
        self.disks = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the disks that are available for the instance type.</p>
    pub fn set_disks(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DiskInfo>>) -> Self {
        self.disks = input;
        self
    }
    /// <p>Describes the disks that are available for the instance type.</p>
    pub fn get_disks(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DiskInfo>> {
        &self.disks
    }
    /// <p>Indicates whether non-volatile memory express (NVMe) is supported.</p>
    pub fn nvme_support(mut self, input: crate::types::EphemeralNvmeSupport) -> Self {
        self.nvme_support = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether non-volatile memory express (NVMe) is supported.</p>
    pub fn set_nvme_support(mut self, input: ::std::option::Option<crate::types::EphemeralNvmeSupport>) -> Self {
        self.nvme_support = input;
        self
    }
    /// <p>Indicates whether non-volatile memory express (NVMe) is supported.</p>
    pub fn get_nvme_support(&self) -> &::std::option::Option<crate::types::EphemeralNvmeSupport> {
        &self.nvme_support
    }
    /// <p>Indicates whether data is encrypted at rest.</p>
    pub fn encryption_support(mut self, input: crate::types::InstanceStorageEncryptionSupport) -> Self {
        self.encryption_support = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether data is encrypted at rest.</p>
    pub fn set_encryption_support(mut self, input: ::std::option::Option<crate::types::InstanceStorageEncryptionSupport>) -> Self {
        self.encryption_support = input;
        self
    }
    /// <p>Indicates whether data is encrypted at rest.</p>
    pub fn get_encryption_support(&self) -> &::std::option::Option<crate::types::InstanceStorageEncryptionSupport> {
        &self.encryption_support
    }
    /// Consumes the builder and constructs a [`InstanceStorageInfo`](crate::types::InstanceStorageInfo).
    pub fn build(self) -> crate::types::InstanceStorageInfo {
        crate::types::InstanceStorageInfo {
            total_size_in_gb: self.total_size_in_gb,
            disks: self.disks,
            nvme_support: self.nvme_support,
            encryption_support: self.encryption_support,
        }
    }
}
