// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeGlobalReplicationGroupsOutput {
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by MaxRecords. &gt;</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the slot configuration and global identifier for each slice group.</p>
    pub global_replication_groups: ::std::option::Option<::std::vec::Vec<crate::types::GlobalReplicationGroup>>,
    _request_id: Option<String>,
}
impl DescribeGlobalReplicationGroupsOutput {
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by MaxRecords. &gt;</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>Indicates the slot configuration and global identifier for each slice group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.global_replication_groups.is_none()`.
    pub fn global_replication_groups(&self) -> &[crate::types::GlobalReplicationGroup] {
        self.global_replication_groups.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeGlobalReplicationGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeGlobalReplicationGroupsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeGlobalReplicationGroupsOutput`](crate::operation::describe_global_replication_groups::DescribeGlobalReplicationGroupsOutput).
    pub fn builder() -> crate::operation::describe_global_replication_groups::builders::DescribeGlobalReplicationGroupsOutputBuilder {
        crate::operation::describe_global_replication_groups::builders::DescribeGlobalReplicationGroupsOutputBuilder::default()
    }
}

/// A builder for [`DescribeGlobalReplicationGroupsOutput`](crate::operation::describe_global_replication_groups::DescribeGlobalReplicationGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeGlobalReplicationGroupsOutputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) global_replication_groups: ::std::option::Option<::std::vec::Vec<crate::types::GlobalReplicationGroup>>,
    _request_id: Option<String>,
}
impl DescribeGlobalReplicationGroupsOutputBuilder {
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by MaxRecords. &gt;</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by MaxRecords. &gt;</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by MaxRecords. &gt;</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Appends an item to `global_replication_groups`.
    ///
    /// To override the contents of this collection use [`set_global_replication_groups`](Self::set_global_replication_groups).
    ///
    /// <p>Indicates the slot configuration and global identifier for each slice group.</p>
    pub fn global_replication_groups(mut self, input: crate::types::GlobalReplicationGroup) -> Self {
        let mut v = self.global_replication_groups.unwrap_or_default();
        v.push(input);
        self.global_replication_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates the slot configuration and global identifier for each slice group.</p>
    pub fn set_global_replication_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GlobalReplicationGroup>>) -> Self {
        self.global_replication_groups = input;
        self
    }
    /// <p>Indicates the slot configuration and global identifier for each slice group.</p>
    pub fn get_global_replication_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GlobalReplicationGroup>> {
        &self.global_replication_groups
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeGlobalReplicationGroupsOutput`](crate::operation::describe_global_replication_groups::DescribeGlobalReplicationGroupsOutput).
    pub fn build(self) -> crate::operation::describe_global_replication_groups::DescribeGlobalReplicationGroupsOutput {
        crate::operation::describe_global_replication_groups::DescribeGlobalReplicationGroupsOutput {
            marker: self.marker,
            global_replication_groups: self.global_replication_groups,
            _request_id: self._request_id,
        }
    }
}
