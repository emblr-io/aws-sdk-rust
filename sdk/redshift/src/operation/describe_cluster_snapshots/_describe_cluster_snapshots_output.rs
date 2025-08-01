// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the output from the <code>DescribeClusterSnapshots</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeClusterSnapshotsOutput {
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned marker value in the <code>Marker</code> parameter and retrying the command. If the <code>Marker</code> field is empty, all response records have been retrieved for the request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>Snapshot</code> instances.</p>
    pub snapshots: ::std::option::Option<::std::vec::Vec<crate::types::Snapshot>>,
    _request_id: Option<String>,
}
impl DescribeClusterSnapshotsOutput {
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned marker value in the <code>Marker</code> parameter and retrying the command. If the <code>Marker</code> field is empty, all response records have been retrieved for the request.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>A list of <code>Snapshot</code> instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.snapshots.is_none()`.
    pub fn snapshots(&self) -> &[crate::types::Snapshot] {
        self.snapshots.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeClusterSnapshotsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeClusterSnapshotsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeClusterSnapshotsOutput`](crate::operation::describe_cluster_snapshots::DescribeClusterSnapshotsOutput).
    pub fn builder() -> crate::operation::describe_cluster_snapshots::builders::DescribeClusterSnapshotsOutputBuilder {
        crate::operation::describe_cluster_snapshots::builders::DescribeClusterSnapshotsOutputBuilder::default()
    }
}

/// A builder for [`DescribeClusterSnapshotsOutput`](crate::operation::describe_cluster_snapshots::DescribeClusterSnapshotsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeClusterSnapshotsOutputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) snapshots: ::std::option::Option<::std::vec::Vec<crate::types::Snapshot>>,
    _request_id: Option<String>,
}
impl DescribeClusterSnapshotsOutputBuilder {
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned marker value in the <code>Marker</code> parameter and retrying the command. If the <code>Marker</code> field is empty, all response records have been retrieved for the request.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned marker value in the <code>Marker</code> parameter and retrying the command. If the <code>Marker</code> field is empty, all response records have been retrieved for the request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned marker value in the <code>Marker</code> parameter and retrying the command. If the <code>Marker</code> field is empty, all response records have been retrieved for the request.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Appends an item to `snapshots`.
    ///
    /// To override the contents of this collection use [`set_snapshots`](Self::set_snapshots).
    ///
    /// <p>A list of <code>Snapshot</code> instances.</p>
    pub fn snapshots(mut self, input: crate::types::Snapshot) -> Self {
        let mut v = self.snapshots.unwrap_or_default();
        v.push(input);
        self.snapshots = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>Snapshot</code> instances.</p>
    pub fn set_snapshots(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Snapshot>>) -> Self {
        self.snapshots = input;
        self
    }
    /// <p>A list of <code>Snapshot</code> instances.</p>
    pub fn get_snapshots(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Snapshot>> {
        &self.snapshots
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeClusterSnapshotsOutput`](crate::operation::describe_cluster_snapshots::DescribeClusterSnapshotsOutput).
    pub fn build(self) -> crate::operation::describe_cluster_snapshots::DescribeClusterSnapshotsOutput {
        crate::operation::describe_cluster_snapshots::DescribeClusterSnapshotsOutput {
            marker: self.marker,
            snapshots: self.snapshots,
            _request_id: self._request_id,
        }
    }
}
