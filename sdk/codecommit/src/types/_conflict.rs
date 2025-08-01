// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about conflicts in a merge operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Conflict {
    /// <p>Metadata about a conflict in a merge operation.</p>
    pub conflict_metadata: ::std::option::Option<crate::types::ConflictMetadata>,
    /// <p>A list of hunks that contain the differences between files or lines causing the conflict.</p>
    pub merge_hunks: ::std::option::Option<::std::vec::Vec<crate::types::MergeHunk>>,
}
impl Conflict {
    /// <p>Metadata about a conflict in a merge operation.</p>
    pub fn conflict_metadata(&self) -> ::std::option::Option<&crate::types::ConflictMetadata> {
        self.conflict_metadata.as_ref()
    }
    /// <p>A list of hunks that contain the differences between files or lines causing the conflict.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.merge_hunks.is_none()`.
    pub fn merge_hunks(&self) -> &[crate::types::MergeHunk] {
        self.merge_hunks.as_deref().unwrap_or_default()
    }
}
impl Conflict {
    /// Creates a new builder-style object to manufacture [`Conflict`](crate::types::Conflict).
    pub fn builder() -> crate::types::builders::ConflictBuilder {
        crate::types::builders::ConflictBuilder::default()
    }
}

/// A builder for [`Conflict`](crate::types::Conflict).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConflictBuilder {
    pub(crate) conflict_metadata: ::std::option::Option<crate::types::ConflictMetadata>,
    pub(crate) merge_hunks: ::std::option::Option<::std::vec::Vec<crate::types::MergeHunk>>,
}
impl ConflictBuilder {
    /// <p>Metadata about a conflict in a merge operation.</p>
    pub fn conflict_metadata(mut self, input: crate::types::ConflictMetadata) -> Self {
        self.conflict_metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>Metadata about a conflict in a merge operation.</p>
    pub fn set_conflict_metadata(mut self, input: ::std::option::Option<crate::types::ConflictMetadata>) -> Self {
        self.conflict_metadata = input;
        self
    }
    /// <p>Metadata about a conflict in a merge operation.</p>
    pub fn get_conflict_metadata(&self) -> &::std::option::Option<crate::types::ConflictMetadata> {
        &self.conflict_metadata
    }
    /// Appends an item to `merge_hunks`.
    ///
    /// To override the contents of this collection use [`set_merge_hunks`](Self::set_merge_hunks).
    ///
    /// <p>A list of hunks that contain the differences between files or lines causing the conflict.</p>
    pub fn merge_hunks(mut self, input: crate::types::MergeHunk) -> Self {
        let mut v = self.merge_hunks.unwrap_or_default();
        v.push(input);
        self.merge_hunks = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of hunks that contain the differences between files or lines causing the conflict.</p>
    pub fn set_merge_hunks(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MergeHunk>>) -> Self {
        self.merge_hunks = input;
        self
    }
    /// <p>A list of hunks that contain the differences between files or lines causing the conflict.</p>
    pub fn get_merge_hunks(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MergeHunk>> {
        &self.merge_hunks
    }
    /// Consumes the builder and constructs a [`Conflict`](crate::types::Conflict).
    pub fn build(self) -> crate::types::Conflict {
        crate::types::Conflict {
            conflict_metadata: self.conflict_metadata,
            merge_hunks: self.merge_hunks,
        }
    }
}
