// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CopySnapshotOutput {
    /// <p>Any tags applied to the new snapshot.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The ID of the new snapshot.</p>
    pub snapshot_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CopySnapshotOutput {
    /// <p>Any tags applied to the new snapshot.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the new snapshot.</p>
    pub fn snapshot_id(&self) -> ::std::option::Option<&str> {
        self.snapshot_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CopySnapshotOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CopySnapshotOutput {
    /// Creates a new builder-style object to manufacture [`CopySnapshotOutput`](crate::operation::copy_snapshot::CopySnapshotOutput).
    pub fn builder() -> crate::operation::copy_snapshot::builders::CopySnapshotOutputBuilder {
        crate::operation::copy_snapshot::builders::CopySnapshotOutputBuilder::default()
    }
}

/// A builder for [`CopySnapshotOutput`](crate::operation::copy_snapshot::CopySnapshotOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CopySnapshotOutputBuilder {
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) snapshot_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CopySnapshotOutputBuilder {
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Any tags applied to the new snapshot.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Any tags applied to the new snapshot.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Any tags applied to the new snapshot.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The ID of the new snapshot.</p>
    pub fn snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the new snapshot.</p>
    pub fn set_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_id = input;
        self
    }
    /// <p>The ID of the new snapshot.</p>
    pub fn get_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CopySnapshotOutput`](crate::operation::copy_snapshot::CopySnapshotOutput).
    pub fn build(self) -> crate::operation::copy_snapshot::CopySnapshotOutput {
        crate::operation::copy_snapshot::CopySnapshotOutput {
            tags: self.tags,
            snapshot_id: self.snapshot_id,
            _request_id: self._request_id,
        }
    }
}
