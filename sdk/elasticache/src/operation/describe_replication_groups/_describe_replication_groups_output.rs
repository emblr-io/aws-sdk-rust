// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>DescribeReplicationGroups</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeReplicationGroupsOutput {
    /// <p>Provides an identifier to allow retrieval of paginated results.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>A list of replication groups. Each item in the list contains detailed information about one replication group.</p>
    pub replication_groups: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationGroup>>,
    _request_id: Option<String>,
}
impl DescribeReplicationGroupsOutput {
    /// <p>Provides an identifier to allow retrieval of paginated results.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>A list of replication groups. Each item in the list contains detailed information about one replication group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.replication_groups.is_none()`.
    pub fn replication_groups(&self) -> &[crate::types::ReplicationGroup] {
        self.replication_groups.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeReplicationGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeReplicationGroupsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeReplicationGroupsOutput`](crate::operation::describe_replication_groups::DescribeReplicationGroupsOutput).
    pub fn builder() -> crate::operation::describe_replication_groups::builders::DescribeReplicationGroupsOutputBuilder {
        crate::operation::describe_replication_groups::builders::DescribeReplicationGroupsOutputBuilder::default()
    }
}

/// A builder for [`DescribeReplicationGroupsOutput`](crate::operation::describe_replication_groups::DescribeReplicationGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeReplicationGroupsOutputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) replication_groups: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationGroup>>,
    _request_id: Option<String>,
}
impl DescribeReplicationGroupsOutputBuilder {
    /// <p>Provides an identifier to allow retrieval of paginated results.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides an identifier to allow retrieval of paginated results.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>Provides an identifier to allow retrieval of paginated results.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Appends an item to `replication_groups`.
    ///
    /// To override the contents of this collection use [`set_replication_groups`](Self::set_replication_groups).
    ///
    /// <p>A list of replication groups. Each item in the list contains detailed information about one replication group.</p>
    pub fn replication_groups(mut self, input: crate::types::ReplicationGroup) -> Self {
        let mut v = self.replication_groups.unwrap_or_default();
        v.push(input);
        self.replication_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of replication groups. Each item in the list contains detailed information about one replication group.</p>
    pub fn set_replication_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationGroup>>) -> Self {
        self.replication_groups = input;
        self
    }
    /// <p>A list of replication groups. Each item in the list contains detailed information about one replication group.</p>
    pub fn get_replication_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReplicationGroup>> {
        &self.replication_groups
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeReplicationGroupsOutput`](crate::operation::describe_replication_groups::DescribeReplicationGroupsOutput).
    pub fn build(self) -> crate::operation::describe_replication_groups::DescribeReplicationGroupsOutput {
        crate::operation::describe_replication_groups::DescribeReplicationGroupsOutput {
            marker: self.marker,
            replication_groups: self.replication_groups,
            _request_id: self._request_id,
        }
    }
}
