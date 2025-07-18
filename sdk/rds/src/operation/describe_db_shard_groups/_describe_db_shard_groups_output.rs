// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDbShardGroupsOutput {
    /// <p>Contains a list of DB shard groups for the user.</p>
    pub db_shard_groups: ::std::option::Option<::std::vec::Vec<crate::types::DbShardGroup>>,
    /// <p>A pagination token that can be used in a later <code>DescribeDBClusters</code> request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeDbShardGroupsOutput {
    /// <p>Contains a list of DB shard groups for the user.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.db_shard_groups.is_none()`.
    pub fn db_shard_groups(&self) -> &[crate::types::DbShardGroup] {
        self.db_shard_groups.as_deref().unwrap_or_default()
    }
    /// <p>A pagination token that can be used in a later <code>DescribeDBClusters</code> request.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDbShardGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDbShardGroupsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDbShardGroupsOutput`](crate::operation::describe_db_shard_groups::DescribeDbShardGroupsOutput).
    pub fn builder() -> crate::operation::describe_db_shard_groups::builders::DescribeDbShardGroupsOutputBuilder {
        crate::operation::describe_db_shard_groups::builders::DescribeDbShardGroupsOutputBuilder::default()
    }
}

/// A builder for [`DescribeDbShardGroupsOutput`](crate::operation::describe_db_shard_groups::DescribeDbShardGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDbShardGroupsOutputBuilder {
    pub(crate) db_shard_groups: ::std::option::Option<::std::vec::Vec<crate::types::DbShardGroup>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeDbShardGroupsOutputBuilder {
    /// Appends an item to `db_shard_groups`.
    ///
    /// To override the contents of this collection use [`set_db_shard_groups`](Self::set_db_shard_groups).
    ///
    /// <p>Contains a list of DB shard groups for the user.</p>
    pub fn db_shard_groups(mut self, input: crate::types::DbShardGroup) -> Self {
        let mut v = self.db_shard_groups.unwrap_or_default();
        v.push(input);
        self.db_shard_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains a list of DB shard groups for the user.</p>
    pub fn set_db_shard_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DbShardGroup>>) -> Self {
        self.db_shard_groups = input;
        self
    }
    /// <p>Contains a list of DB shard groups for the user.</p>
    pub fn get_db_shard_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DbShardGroup>> {
        &self.db_shard_groups
    }
    /// <p>A pagination token that can be used in a later <code>DescribeDBClusters</code> request.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token that can be used in a later <code>DescribeDBClusters</code> request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>A pagination token that can be used in a later <code>DescribeDBClusters</code> request.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeDbShardGroupsOutput`](crate::operation::describe_db_shard_groups::DescribeDbShardGroupsOutput).
    pub fn build(self) -> crate::operation::describe_db_shard_groups::DescribeDbShardGroupsOutput {
        crate::operation::describe_db_shard_groups::DescribeDbShardGroupsOutput {
            db_shard_groups: self.db_shard_groups,
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
