// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains the file groups that are requested for the artifact generation in a <code>StartDashboardSnapshotJob</code> API call.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnonymousUserSnapshotJobResult {
    /// <p>A list of <code>SnapshotJobResultFileGroup</code> objects that contain information on the files that are requested during a <code>StartDashboardSnapshotJob</code> API call. If the job succeeds, these objects contain the location where the snapshot artifacts are stored. If the job fails, the objects contain information about the error that caused the job to fail.</p>
    pub file_groups: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotJobResultFileGroup>>,
}
impl AnonymousUserSnapshotJobResult {
    /// <p>A list of <code>SnapshotJobResultFileGroup</code> objects that contain information on the files that are requested during a <code>StartDashboardSnapshotJob</code> API call. If the job succeeds, these objects contain the location where the snapshot artifacts are stored. If the job fails, the objects contain information about the error that caused the job to fail.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.file_groups.is_none()`.
    pub fn file_groups(&self) -> &[crate::types::SnapshotJobResultFileGroup] {
        self.file_groups.as_deref().unwrap_or_default()
    }
}
impl AnonymousUserSnapshotJobResult {
    /// Creates a new builder-style object to manufacture [`AnonymousUserSnapshotJobResult`](crate::types::AnonymousUserSnapshotJobResult).
    pub fn builder() -> crate::types::builders::AnonymousUserSnapshotJobResultBuilder {
        crate::types::builders::AnonymousUserSnapshotJobResultBuilder::default()
    }
}

/// A builder for [`AnonymousUserSnapshotJobResult`](crate::types::AnonymousUserSnapshotJobResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnonymousUserSnapshotJobResultBuilder {
    pub(crate) file_groups: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotJobResultFileGroup>>,
}
impl AnonymousUserSnapshotJobResultBuilder {
    /// Appends an item to `file_groups`.
    ///
    /// To override the contents of this collection use [`set_file_groups`](Self::set_file_groups).
    ///
    /// <p>A list of <code>SnapshotJobResultFileGroup</code> objects that contain information on the files that are requested during a <code>StartDashboardSnapshotJob</code> API call. If the job succeeds, these objects contain the location where the snapshot artifacts are stored. If the job fails, the objects contain information about the error that caused the job to fail.</p>
    pub fn file_groups(mut self, input: crate::types::SnapshotJobResultFileGroup) -> Self {
        let mut v = self.file_groups.unwrap_or_default();
        v.push(input);
        self.file_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>SnapshotJobResultFileGroup</code> objects that contain information on the files that are requested during a <code>StartDashboardSnapshotJob</code> API call. If the job succeeds, these objects contain the location where the snapshot artifacts are stored. If the job fails, the objects contain information about the error that caused the job to fail.</p>
    pub fn set_file_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotJobResultFileGroup>>) -> Self {
        self.file_groups = input;
        self
    }
    /// <p>A list of <code>SnapshotJobResultFileGroup</code> objects that contain information on the files that are requested during a <code>StartDashboardSnapshotJob</code> API call. If the job succeeds, these objects contain the location where the snapshot artifacts are stored. If the job fails, the objects contain information about the error that caused the job to fail.</p>
    pub fn get_file_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SnapshotJobResultFileGroup>> {
        &self.file_groups
    }
    /// Consumes the builder and constructs a [`AnonymousUserSnapshotJobResult`](crate::types::AnonymousUserSnapshotJobResult).
    pub fn build(self) -> crate::types::AnonymousUserSnapshotJobResult {
        crate::types::AnonymousUserSnapshotJobResult {
            file_groups: self.file_groups,
        }
    }
}
