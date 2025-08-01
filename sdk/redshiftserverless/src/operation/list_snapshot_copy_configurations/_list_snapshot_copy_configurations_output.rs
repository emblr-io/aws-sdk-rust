// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSnapshotCopyConfigurationsOutput {
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>All of the returned snapshot copy configurations.</p>
    pub snapshot_copy_configurations: ::std::vec::Vec<crate::types::SnapshotCopyConfiguration>,
    _request_id: Option<String>,
}
impl ListSnapshotCopyConfigurationsOutput {
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>All of the returned snapshot copy configurations.</p>
    pub fn snapshot_copy_configurations(&self) -> &[crate::types::SnapshotCopyConfiguration] {
        use std::ops::Deref;
        self.snapshot_copy_configurations.deref()
    }
}
impl ::aws_types::request_id::RequestId for ListSnapshotCopyConfigurationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSnapshotCopyConfigurationsOutput {
    /// Creates a new builder-style object to manufacture [`ListSnapshotCopyConfigurationsOutput`](crate::operation::list_snapshot_copy_configurations::ListSnapshotCopyConfigurationsOutput).
    pub fn builder() -> crate::operation::list_snapshot_copy_configurations::builders::ListSnapshotCopyConfigurationsOutputBuilder {
        crate::operation::list_snapshot_copy_configurations::builders::ListSnapshotCopyConfigurationsOutputBuilder::default()
    }
}

/// A builder for [`ListSnapshotCopyConfigurationsOutput`](crate::operation::list_snapshot_copy_configurations::ListSnapshotCopyConfigurationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSnapshotCopyConfigurationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) snapshot_copy_configurations: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotCopyConfiguration>>,
    _request_id: Option<String>,
}
impl ListSnapshotCopyConfigurationsOutputBuilder {
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `snapshot_copy_configurations`.
    ///
    /// To override the contents of this collection use [`set_snapshot_copy_configurations`](Self::set_snapshot_copy_configurations).
    ///
    /// <p>All of the returned snapshot copy configurations.</p>
    pub fn snapshot_copy_configurations(mut self, input: crate::types::SnapshotCopyConfiguration) -> Self {
        let mut v = self.snapshot_copy_configurations.unwrap_or_default();
        v.push(input);
        self.snapshot_copy_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>All of the returned snapshot copy configurations.</p>
    pub fn set_snapshot_copy_configurations(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotCopyConfiguration>>,
    ) -> Self {
        self.snapshot_copy_configurations = input;
        self
    }
    /// <p>All of the returned snapshot copy configurations.</p>
    pub fn get_snapshot_copy_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SnapshotCopyConfiguration>> {
        &self.snapshot_copy_configurations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListSnapshotCopyConfigurationsOutput`](crate::operation::list_snapshot_copy_configurations::ListSnapshotCopyConfigurationsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`snapshot_copy_configurations`](crate::operation::list_snapshot_copy_configurations::builders::ListSnapshotCopyConfigurationsOutputBuilder::snapshot_copy_configurations)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_snapshot_copy_configurations::ListSnapshotCopyConfigurationsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_snapshot_copy_configurations::ListSnapshotCopyConfigurationsOutput {
                next_token: self.next_token,
                snapshot_copy_configurations: self.snapshot_copy_configurations.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "snapshot_copy_configurations",
                        "snapshot_copy_configurations was not specified but it is required when building ListSnapshotCopyConfigurationsOutput",
                    )
                })?,
                _request_id: self._request_id,
            },
        )
    }
}
