// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the result of a successful invocation of the <code>DescribeDBSnapshots</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDbSnapshotsOutput {
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>DBSnapshot</code> instances.</p>
    pub db_snapshots: ::std::option::Option<::std::vec::Vec<crate::types::DbSnapshot>>,
    _request_id: Option<String>,
}
impl DescribeDbSnapshotsOutput {
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>A list of <code>DBSnapshot</code> instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.db_snapshots.is_none()`.
    pub fn db_snapshots(&self) -> &[crate::types::DbSnapshot] {
        self.db_snapshots.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDbSnapshotsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDbSnapshotsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDbSnapshotsOutput`](crate::operation::describe_db_snapshots::DescribeDbSnapshotsOutput).
    pub fn builder() -> crate::operation::describe_db_snapshots::builders::DescribeDbSnapshotsOutputBuilder {
        crate::operation::describe_db_snapshots::builders::DescribeDbSnapshotsOutputBuilder::default()
    }
}

/// A builder for [`DescribeDbSnapshotsOutput`](crate::operation::describe_db_snapshots::DescribeDbSnapshotsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDbSnapshotsOutputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) db_snapshots: ::std::option::Option<::std::vec::Vec<crate::types::DbSnapshot>>,
    _request_id: Option<String>,
}
impl DescribeDbSnapshotsOutputBuilder {
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Appends an item to `db_snapshots`.
    ///
    /// To override the contents of this collection use [`set_db_snapshots`](Self::set_db_snapshots).
    ///
    /// <p>A list of <code>DBSnapshot</code> instances.</p>
    pub fn db_snapshots(mut self, input: crate::types::DbSnapshot) -> Self {
        let mut v = self.db_snapshots.unwrap_or_default();
        v.push(input);
        self.db_snapshots = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>DBSnapshot</code> instances.</p>
    pub fn set_db_snapshots(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DbSnapshot>>) -> Self {
        self.db_snapshots = input;
        self
    }
    /// <p>A list of <code>DBSnapshot</code> instances.</p>
    pub fn get_db_snapshots(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DbSnapshot>> {
        &self.db_snapshots
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeDbSnapshotsOutput`](crate::operation::describe_db_snapshots::DescribeDbSnapshotsOutput).
    pub fn build(self) -> crate::operation::describe_db_snapshots::DescribeDbSnapshotsOutput {
        crate::operation::describe_db_snapshots::DescribeDbSnapshotsOutput {
            marker: self.marker,
            db_snapshots: self.db_snapshots,
            _request_id: self._request_id,
        }
    }
}
