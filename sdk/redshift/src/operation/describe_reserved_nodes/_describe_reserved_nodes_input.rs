// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeReservedNodesInput {
    /// <p>Identifier for the node reservation.</p>
    pub reserved_node_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned marker value.</p>
    /// <p>Default: <code>100</code></p>
    /// <p>Constraints: minimum 20, maximum 100.</p>
    pub max_records: ::std::option::Option<i32>,
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeReservedNodes</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
}
impl DescribeReservedNodesInput {
    /// <p>Identifier for the node reservation.</p>
    pub fn reserved_node_id(&self) -> ::std::option::Option<&str> {
        self.reserved_node_id.as_deref()
    }
    /// <p>The maximum number of response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned marker value.</p>
    /// <p>Default: <code>100</code></p>
    /// <p>Constraints: minimum 20, maximum 100.</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeReservedNodes</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl DescribeReservedNodesInput {
    /// Creates a new builder-style object to manufacture [`DescribeReservedNodesInput`](crate::operation::describe_reserved_nodes::DescribeReservedNodesInput).
    pub fn builder() -> crate::operation::describe_reserved_nodes::builders::DescribeReservedNodesInputBuilder {
        crate::operation::describe_reserved_nodes::builders::DescribeReservedNodesInputBuilder::default()
    }
}

/// A builder for [`DescribeReservedNodesInput`](crate::operation::describe_reserved_nodes::DescribeReservedNodesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeReservedNodesInputBuilder {
    pub(crate) reserved_node_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_records: ::std::option::Option<i32>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
}
impl DescribeReservedNodesInputBuilder {
    /// <p>Identifier for the node reservation.</p>
    pub fn reserved_node_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reserved_node_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier for the node reservation.</p>
    pub fn set_reserved_node_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reserved_node_id = input;
        self
    }
    /// <p>Identifier for the node reservation.</p>
    pub fn get_reserved_node_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.reserved_node_id
    }
    /// <p>The maximum number of response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned marker value.</p>
    /// <p>Default: <code>100</code></p>
    /// <p>Constraints: minimum 20, maximum 100.</p>
    pub fn max_records(mut self, input: i32) -> Self {
        self.max_records = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned marker value.</p>
    /// <p>Default: <code>100</code></p>
    /// <p>Constraints: minimum 20, maximum 100.</p>
    pub fn set_max_records(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_records = input;
        self
    }
    /// <p>The maximum number of response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned marker value.</p>
    /// <p>Default: <code>100</code></p>
    /// <p>Constraints: minimum 20, maximum 100.</p>
    pub fn get_max_records(&self) -> &::std::option::Option<i32> {
        &self.max_records
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeReservedNodes</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeReservedNodes</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeReservedNodes</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Consumes the builder and constructs a [`DescribeReservedNodesInput`](crate::operation::describe_reserved_nodes::DescribeReservedNodesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_reserved_nodes::DescribeReservedNodesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_reserved_nodes::DescribeReservedNodesInput {
            reserved_node_id: self.reserved_node_id,
            max_records: self.max_records,
            marker: self.marker,
        })
    }
}
