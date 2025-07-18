// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisableSnapshotCopyInput {
    /// <p>The unique identifier of the source cluster that you want to disable copying of snapshots to a destination region.</p>
    /// <p>Constraints: Must be the valid name of an existing cluster that has cross-region snapshot copy enabled.</p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
}
impl DisableSnapshotCopyInput {
    /// <p>The unique identifier of the source cluster that you want to disable copying of snapshots to a destination region.</p>
    /// <p>Constraints: Must be the valid name of an existing cluster that has cross-region snapshot copy enabled.</p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
}
impl DisableSnapshotCopyInput {
    /// Creates a new builder-style object to manufacture [`DisableSnapshotCopyInput`](crate::operation::disable_snapshot_copy::DisableSnapshotCopyInput).
    pub fn builder() -> crate::operation::disable_snapshot_copy::builders::DisableSnapshotCopyInputBuilder {
        crate::operation::disable_snapshot_copy::builders::DisableSnapshotCopyInputBuilder::default()
    }
}

/// A builder for [`DisableSnapshotCopyInput`](crate::operation::disable_snapshot_copy::DisableSnapshotCopyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisableSnapshotCopyInputBuilder {
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
}
impl DisableSnapshotCopyInputBuilder {
    /// <p>The unique identifier of the source cluster that you want to disable copying of snapshots to a destination region.</p>
    /// <p>Constraints: Must be the valid name of an existing cluster that has cross-region snapshot copy enabled.</p>
    /// This field is required.
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the source cluster that you want to disable copying of snapshots to a destination region.</p>
    /// <p>Constraints: Must be the valid name of an existing cluster that has cross-region snapshot copy enabled.</p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The unique identifier of the source cluster that you want to disable copying of snapshots to a destination region.</p>
    /// <p>Constraints: Must be the valid name of an existing cluster that has cross-region snapshot copy enabled.</p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// Consumes the builder and constructs a [`DisableSnapshotCopyInput`](crate::operation::disable_snapshot_copy::DisableSnapshotCopyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::disable_snapshot_copy::DisableSnapshotCopyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::disable_snapshot_copy::DisableSnapshotCopyInput {
            cluster_identifier: self.cluster_identifier,
        })
    }
}
