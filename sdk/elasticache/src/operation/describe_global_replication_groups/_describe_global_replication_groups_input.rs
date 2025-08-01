// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeGlobalReplicationGroupsInput {
    /// <p>The name of the Global datastore</p>
    pub global_replication_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of records to include in the response. If more records exist than the specified MaxRecords value, a marker is included in the response so that the remaining results can be retrieved.</p>
    pub max_records: ::std::option::Option<i32>,
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>Returns the list of members that comprise the Global datastore.</p>
    pub show_member_info: ::std::option::Option<bool>,
}
impl DescribeGlobalReplicationGroupsInput {
    /// <p>The name of the Global datastore</p>
    pub fn global_replication_group_id(&self) -> ::std::option::Option<&str> {
        self.global_replication_group_id.as_deref()
    }
    /// <p>The maximum number of records to include in the response. If more records exist than the specified MaxRecords value, a marker is included in the response so that the remaining results can be retrieved.</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>Returns the list of members that comprise the Global datastore.</p>
    pub fn show_member_info(&self) -> ::std::option::Option<bool> {
        self.show_member_info
    }
}
impl DescribeGlobalReplicationGroupsInput {
    /// Creates a new builder-style object to manufacture [`DescribeGlobalReplicationGroupsInput`](crate::operation::describe_global_replication_groups::DescribeGlobalReplicationGroupsInput).
    pub fn builder() -> crate::operation::describe_global_replication_groups::builders::DescribeGlobalReplicationGroupsInputBuilder {
        crate::operation::describe_global_replication_groups::builders::DescribeGlobalReplicationGroupsInputBuilder::default()
    }
}

/// A builder for [`DescribeGlobalReplicationGroupsInput`](crate::operation::describe_global_replication_groups::DescribeGlobalReplicationGroupsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeGlobalReplicationGroupsInputBuilder {
    pub(crate) global_replication_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_records: ::std::option::Option<i32>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) show_member_info: ::std::option::Option<bool>,
}
impl DescribeGlobalReplicationGroupsInputBuilder {
    /// <p>The name of the Global datastore</p>
    pub fn global_replication_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.global_replication_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Global datastore</p>
    pub fn set_global_replication_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.global_replication_group_id = input;
        self
    }
    /// <p>The name of the Global datastore</p>
    pub fn get_global_replication_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.global_replication_group_id
    }
    /// <p>The maximum number of records to include in the response. If more records exist than the specified MaxRecords value, a marker is included in the response so that the remaining results can be retrieved.</p>
    pub fn max_records(mut self, input: i32) -> Self {
        self.max_records = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of records to include in the response. If more records exist than the specified MaxRecords value, a marker is included in the response so that the remaining results can be retrieved.</p>
    pub fn set_max_records(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_records = input;
        self
    }
    /// <p>The maximum number of records to include in the response. If more records exist than the specified MaxRecords value, a marker is included in the response so that the remaining results can be retrieved.</p>
    pub fn get_max_records(&self) -> &::std::option::Option<i32> {
        &self.max_records
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>Returns the list of members that comprise the Global datastore.</p>
    pub fn show_member_info(mut self, input: bool) -> Self {
        self.show_member_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns the list of members that comprise the Global datastore.</p>
    pub fn set_show_member_info(mut self, input: ::std::option::Option<bool>) -> Self {
        self.show_member_info = input;
        self
    }
    /// <p>Returns the list of members that comprise the Global datastore.</p>
    pub fn get_show_member_info(&self) -> &::std::option::Option<bool> {
        &self.show_member_info
    }
    /// Consumes the builder and constructs a [`DescribeGlobalReplicationGroupsInput`](crate::operation::describe_global_replication_groups::DescribeGlobalReplicationGroupsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_global_replication_groups::DescribeGlobalReplicationGroupsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_global_replication_groups::DescribeGlobalReplicationGroupsInput {
                global_replication_group_id: self.global_replication_group_id,
                max_records: self.max_records,
                marker: self.marker,
                show_member_info: self.show_member_info,
            },
        )
    }
}
