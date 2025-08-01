// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeUserGroupsInput {
    /// <p>The ID of the user group.</p>
    pub user_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of records to include in the response. If more records exist than the specified MaxRecords value, a marker is included in the response so that the remaining results can be retrieved.</p>
    pub max_records: ::std::option::Option<i32>,
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by MaxRecords. &gt;</p>
    pub marker: ::std::option::Option<::std::string::String>,
}
impl DescribeUserGroupsInput {
    /// <p>The ID of the user group.</p>
    pub fn user_group_id(&self) -> ::std::option::Option<&str> {
        self.user_group_id.as_deref()
    }
    /// <p>The maximum number of records to include in the response. If more records exist than the specified MaxRecords value, a marker is included in the response so that the remaining results can be retrieved.</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by MaxRecords. &gt;</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl DescribeUserGroupsInput {
    /// Creates a new builder-style object to manufacture [`DescribeUserGroupsInput`](crate::operation::describe_user_groups::DescribeUserGroupsInput).
    pub fn builder() -> crate::operation::describe_user_groups::builders::DescribeUserGroupsInputBuilder {
        crate::operation::describe_user_groups::builders::DescribeUserGroupsInputBuilder::default()
    }
}

/// A builder for [`DescribeUserGroupsInput`](crate::operation::describe_user_groups::DescribeUserGroupsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeUserGroupsInputBuilder {
    pub(crate) user_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_records: ::std::option::Option<i32>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
}
impl DescribeUserGroupsInputBuilder {
    /// <p>The ID of the user group.</p>
    pub fn user_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the user group.</p>
    pub fn set_user_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_group_id = input;
        self
    }
    /// <p>The ID of the user group.</p>
    pub fn get_user_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_group_id
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
    /// Consumes the builder and constructs a [`DescribeUserGroupsInput`](crate::operation::describe_user_groups::DescribeUserGroupsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_user_groups::DescribeUserGroupsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_user_groups::DescribeUserGroupsInput {
            user_group_id: self.user_group_id,
            max_records: self.max_records,
            marker: self.marker,
        })
    }
}
