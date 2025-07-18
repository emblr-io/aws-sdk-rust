// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration for managed Amazon S3 backup access from the ODB network.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ManagedS3BackupAccess {
    /// <p>The status of the managed Amazon S3 backup access.</p>
    /// <p>Valid Values: <code>enabled | disabled</code></p>
    pub status: ::std::option::Option<crate::types::ManagedResourceStatus>,
    /// <p>The IPv4 addresses for the managed Amazon S3 backup access.</p>
    pub ipv4_addresses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ManagedS3BackupAccess {
    /// <p>The status of the managed Amazon S3 backup access.</p>
    /// <p>Valid Values: <code>enabled | disabled</code></p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ManagedResourceStatus> {
        self.status.as_ref()
    }
    /// <p>The IPv4 addresses for the managed Amazon S3 backup access.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ipv4_addresses.is_none()`.
    pub fn ipv4_addresses(&self) -> &[::std::string::String] {
        self.ipv4_addresses.as_deref().unwrap_or_default()
    }
}
impl ManagedS3BackupAccess {
    /// Creates a new builder-style object to manufacture [`ManagedS3BackupAccess`](crate::types::ManagedS3BackupAccess).
    pub fn builder() -> crate::types::builders::ManagedS3BackupAccessBuilder {
        crate::types::builders::ManagedS3BackupAccessBuilder::default()
    }
}

/// A builder for [`ManagedS3BackupAccess`](crate::types::ManagedS3BackupAccess).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ManagedS3BackupAccessBuilder {
    pub(crate) status: ::std::option::Option<crate::types::ManagedResourceStatus>,
    pub(crate) ipv4_addresses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ManagedS3BackupAccessBuilder {
    /// <p>The status of the managed Amazon S3 backup access.</p>
    /// <p>Valid Values: <code>enabled | disabled</code></p>
    pub fn status(mut self, input: crate::types::ManagedResourceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the managed Amazon S3 backup access.</p>
    /// <p>Valid Values: <code>enabled | disabled</code></p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ManagedResourceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the managed Amazon S3 backup access.</p>
    /// <p>Valid Values: <code>enabled | disabled</code></p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ManagedResourceStatus> {
        &self.status
    }
    /// Appends an item to `ipv4_addresses`.
    ///
    /// To override the contents of this collection use [`set_ipv4_addresses`](Self::set_ipv4_addresses).
    ///
    /// <p>The IPv4 addresses for the managed Amazon S3 backup access.</p>
    pub fn ipv4_addresses(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ipv4_addresses.unwrap_or_default();
        v.push(input.into());
        self.ipv4_addresses = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IPv4 addresses for the managed Amazon S3 backup access.</p>
    pub fn set_ipv4_addresses(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ipv4_addresses = input;
        self
    }
    /// <p>The IPv4 addresses for the managed Amazon S3 backup access.</p>
    pub fn get_ipv4_addresses(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ipv4_addresses
    }
    /// Consumes the builder and constructs a [`ManagedS3BackupAccess`](crate::types::ManagedS3BackupAccess).
    pub fn build(self) -> crate::types::ManagedS3BackupAccess {
        crate::types::ManagedS3BackupAccess {
            status: self.status,
            ipv4_addresses: self.ipv4_addresses,
        }
    }
}
