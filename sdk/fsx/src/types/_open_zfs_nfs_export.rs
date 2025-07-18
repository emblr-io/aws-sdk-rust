// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Network File System (NFS) configurations for mounting an Amazon FSx for OpenZFS file system.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OpenZfsNfsExport {
    /// <p>A list of configuration objects that contain the client and options for mounting the OpenZFS file system.</p>
    pub client_configurations: ::std::option::Option<::std::vec::Vec<crate::types::OpenZfsClientConfiguration>>,
}
impl OpenZfsNfsExport {
    /// <p>A list of configuration objects that contain the client and options for mounting the OpenZFS file system.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.client_configurations.is_none()`.
    pub fn client_configurations(&self) -> &[crate::types::OpenZfsClientConfiguration] {
        self.client_configurations.as_deref().unwrap_or_default()
    }
}
impl OpenZfsNfsExport {
    /// Creates a new builder-style object to manufacture [`OpenZfsNfsExport`](crate::types::OpenZfsNfsExport).
    pub fn builder() -> crate::types::builders::OpenZfsNfsExportBuilder {
        crate::types::builders::OpenZfsNfsExportBuilder::default()
    }
}

/// A builder for [`OpenZfsNfsExport`](crate::types::OpenZfsNfsExport).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OpenZfsNfsExportBuilder {
    pub(crate) client_configurations: ::std::option::Option<::std::vec::Vec<crate::types::OpenZfsClientConfiguration>>,
}
impl OpenZfsNfsExportBuilder {
    /// Appends an item to `client_configurations`.
    ///
    /// To override the contents of this collection use [`set_client_configurations`](Self::set_client_configurations).
    ///
    /// <p>A list of configuration objects that contain the client and options for mounting the OpenZFS file system.</p>
    pub fn client_configurations(mut self, input: crate::types::OpenZfsClientConfiguration) -> Self {
        let mut v = self.client_configurations.unwrap_or_default();
        v.push(input);
        self.client_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of configuration objects that contain the client and options for mounting the OpenZFS file system.</p>
    pub fn set_client_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OpenZfsClientConfiguration>>) -> Self {
        self.client_configurations = input;
        self
    }
    /// <p>A list of configuration objects that contain the client and options for mounting the OpenZFS file system.</p>
    pub fn get_client_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OpenZfsClientConfiguration>> {
        &self.client_configurations
    }
    /// Consumes the builder and constructs a [`OpenZfsNfsExport`](crate::types::OpenZfsNfsExport).
    pub fn build(self) -> crate::types::OpenZfsNfsExport {
        crate::types::OpenZfsNfsExport {
            client_configurations: self.client_configurations,
        }
    }
}
