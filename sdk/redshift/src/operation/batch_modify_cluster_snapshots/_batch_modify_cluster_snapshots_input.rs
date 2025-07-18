// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchModifyClusterSnapshotsInput {
    /// <p>A list of snapshot identifiers you want to modify.</p>
    pub snapshot_identifier_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The number of days that a manual snapshot is retained. If you specify the value -1, the manual snapshot is retained indefinitely.</p>
    /// <p>The number must be either -1 or an integer between 1 and 3,653.</p>
    /// <p>If you decrease the manual snapshot retention period from its current value, existing manual snapshots that fall outside of the new retention period will return an error. If you want to suppress the errors and delete the snapshots, use the force option.</p>
    pub manual_snapshot_retention_period: ::std::option::Option<i32>,
    /// <p>A boolean value indicating whether to override an exception if the retention period has passed.</p>
    pub force: ::std::option::Option<bool>,
}
impl BatchModifyClusterSnapshotsInput {
    /// <p>A list of snapshot identifiers you want to modify.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.snapshot_identifier_list.is_none()`.
    pub fn snapshot_identifier_list(&self) -> &[::std::string::String] {
        self.snapshot_identifier_list.as_deref().unwrap_or_default()
    }
    /// <p>The number of days that a manual snapshot is retained. If you specify the value -1, the manual snapshot is retained indefinitely.</p>
    /// <p>The number must be either -1 or an integer between 1 and 3,653.</p>
    /// <p>If you decrease the manual snapshot retention period from its current value, existing manual snapshots that fall outside of the new retention period will return an error. If you want to suppress the errors and delete the snapshots, use the force option.</p>
    pub fn manual_snapshot_retention_period(&self) -> ::std::option::Option<i32> {
        self.manual_snapshot_retention_period
    }
    /// <p>A boolean value indicating whether to override an exception if the retention period has passed.</p>
    pub fn force(&self) -> ::std::option::Option<bool> {
        self.force
    }
}
impl BatchModifyClusterSnapshotsInput {
    /// Creates a new builder-style object to manufacture [`BatchModifyClusterSnapshotsInput`](crate::operation::batch_modify_cluster_snapshots::BatchModifyClusterSnapshotsInput).
    pub fn builder() -> crate::operation::batch_modify_cluster_snapshots::builders::BatchModifyClusterSnapshotsInputBuilder {
        crate::operation::batch_modify_cluster_snapshots::builders::BatchModifyClusterSnapshotsInputBuilder::default()
    }
}

/// A builder for [`BatchModifyClusterSnapshotsInput`](crate::operation::batch_modify_cluster_snapshots::BatchModifyClusterSnapshotsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchModifyClusterSnapshotsInputBuilder {
    pub(crate) snapshot_identifier_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) manual_snapshot_retention_period: ::std::option::Option<i32>,
    pub(crate) force: ::std::option::Option<bool>,
}
impl BatchModifyClusterSnapshotsInputBuilder {
    /// Appends an item to `snapshot_identifier_list`.
    ///
    /// To override the contents of this collection use [`set_snapshot_identifier_list`](Self::set_snapshot_identifier_list).
    ///
    /// <p>A list of snapshot identifiers you want to modify.</p>
    pub fn snapshot_identifier_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.snapshot_identifier_list.unwrap_or_default();
        v.push(input.into());
        self.snapshot_identifier_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of snapshot identifiers you want to modify.</p>
    pub fn set_snapshot_identifier_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.snapshot_identifier_list = input;
        self
    }
    /// <p>A list of snapshot identifiers you want to modify.</p>
    pub fn get_snapshot_identifier_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.snapshot_identifier_list
    }
    /// <p>The number of days that a manual snapshot is retained. If you specify the value -1, the manual snapshot is retained indefinitely.</p>
    /// <p>The number must be either -1 or an integer between 1 and 3,653.</p>
    /// <p>If you decrease the manual snapshot retention period from its current value, existing manual snapshots that fall outside of the new retention period will return an error. If you want to suppress the errors and delete the snapshots, use the force option.</p>
    pub fn manual_snapshot_retention_period(mut self, input: i32) -> Self {
        self.manual_snapshot_retention_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of days that a manual snapshot is retained. If you specify the value -1, the manual snapshot is retained indefinitely.</p>
    /// <p>The number must be either -1 or an integer between 1 and 3,653.</p>
    /// <p>If you decrease the manual snapshot retention period from its current value, existing manual snapshots that fall outside of the new retention period will return an error. If you want to suppress the errors and delete the snapshots, use the force option.</p>
    pub fn set_manual_snapshot_retention_period(mut self, input: ::std::option::Option<i32>) -> Self {
        self.manual_snapshot_retention_period = input;
        self
    }
    /// <p>The number of days that a manual snapshot is retained. If you specify the value -1, the manual snapshot is retained indefinitely.</p>
    /// <p>The number must be either -1 or an integer between 1 and 3,653.</p>
    /// <p>If you decrease the manual snapshot retention period from its current value, existing manual snapshots that fall outside of the new retention period will return an error. If you want to suppress the errors and delete the snapshots, use the force option.</p>
    pub fn get_manual_snapshot_retention_period(&self) -> &::std::option::Option<i32> {
        &self.manual_snapshot_retention_period
    }
    /// <p>A boolean value indicating whether to override an exception if the retention period has passed.</p>
    pub fn force(mut self, input: bool) -> Self {
        self.force = ::std::option::Option::Some(input);
        self
    }
    /// <p>A boolean value indicating whether to override an exception if the retention period has passed.</p>
    pub fn set_force(mut self, input: ::std::option::Option<bool>) -> Self {
        self.force = input;
        self
    }
    /// <p>A boolean value indicating whether to override an exception if the retention period has passed.</p>
    pub fn get_force(&self) -> &::std::option::Option<bool> {
        &self.force
    }
    /// Consumes the builder and constructs a [`BatchModifyClusterSnapshotsInput`](crate::operation::batch_modify_cluster_snapshots::BatchModifyClusterSnapshotsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_modify_cluster_snapshots::BatchModifyClusterSnapshotsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::batch_modify_cluster_snapshots::BatchModifyClusterSnapshotsInput {
            snapshot_identifier_list: self.snapshot_identifier_list,
            manual_snapshot_retention_period: self.manual_snapshot_retention_period,
            force: self.force,
        })
    }
}
