// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDiskSnapshotInput {
    /// <p>The name of the disk snapshot (<code>my-disk-snapshot</code>).</p>
    pub disk_snapshot_name: ::std::option::Option<::std::string::String>,
}
impl GetDiskSnapshotInput {
    /// <p>The name of the disk snapshot (<code>my-disk-snapshot</code>).</p>
    pub fn disk_snapshot_name(&self) -> ::std::option::Option<&str> {
        self.disk_snapshot_name.as_deref()
    }
}
impl GetDiskSnapshotInput {
    /// Creates a new builder-style object to manufacture [`GetDiskSnapshotInput`](crate::operation::get_disk_snapshot::GetDiskSnapshotInput).
    pub fn builder() -> crate::operation::get_disk_snapshot::builders::GetDiskSnapshotInputBuilder {
        crate::operation::get_disk_snapshot::builders::GetDiskSnapshotInputBuilder::default()
    }
}

/// A builder for [`GetDiskSnapshotInput`](crate::operation::get_disk_snapshot::GetDiskSnapshotInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDiskSnapshotInputBuilder {
    pub(crate) disk_snapshot_name: ::std::option::Option<::std::string::String>,
}
impl GetDiskSnapshotInputBuilder {
    /// <p>The name of the disk snapshot (<code>my-disk-snapshot</code>).</p>
    /// This field is required.
    pub fn disk_snapshot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.disk_snapshot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the disk snapshot (<code>my-disk-snapshot</code>).</p>
    pub fn set_disk_snapshot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.disk_snapshot_name = input;
        self
    }
    /// <p>The name of the disk snapshot (<code>my-disk-snapshot</code>).</p>
    pub fn get_disk_snapshot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.disk_snapshot_name
    }
    /// Consumes the builder and constructs a [`GetDiskSnapshotInput`](crate::operation::get_disk_snapshot::GetDiskSnapshotInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_disk_snapshot::GetDiskSnapshotInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_disk_snapshot::GetDiskSnapshotInput {
            disk_snapshot_name: self.disk_snapshot_name,
        })
    }
}
