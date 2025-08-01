// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeOrderableClusterOptionsInput {
    /// <p>The version filter value. Specify this parameter to show only the available offerings matching the specified version.</p>
    /// <p>Default: All versions.</p>
    /// <p>Constraints: Must be one of the version returned from <code>DescribeClusterVersions</code>.</p>
    pub cluster_version: ::std::option::Option<::std::string::String>,
    /// <p>The node type filter value. Specify this parameter to show only the available offerings matching the specified node type.</p>
    pub node_type: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned marker value.</p>
    /// <p>Default: <code>100</code></p>
    /// <p>Constraints: minimum 20, maximum 100.</p>
    pub max_records: ::std::option::Option<i32>,
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeOrderableClusterOptions</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
}
impl DescribeOrderableClusterOptionsInput {
    /// <p>The version filter value. Specify this parameter to show only the available offerings matching the specified version.</p>
    /// <p>Default: All versions.</p>
    /// <p>Constraints: Must be one of the version returned from <code>DescribeClusterVersions</code>.</p>
    pub fn cluster_version(&self) -> ::std::option::Option<&str> {
        self.cluster_version.as_deref()
    }
    /// <p>The node type filter value. Specify this parameter to show only the available offerings matching the specified node type.</p>
    pub fn node_type(&self) -> ::std::option::Option<&str> {
        self.node_type.as_deref()
    }
    /// <p>The maximum number of response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned marker value.</p>
    /// <p>Default: <code>100</code></p>
    /// <p>Constraints: minimum 20, maximum 100.</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeOrderableClusterOptions</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl DescribeOrderableClusterOptionsInput {
    /// Creates a new builder-style object to manufacture [`DescribeOrderableClusterOptionsInput`](crate::operation::describe_orderable_cluster_options::DescribeOrderableClusterOptionsInput).
    pub fn builder() -> crate::operation::describe_orderable_cluster_options::builders::DescribeOrderableClusterOptionsInputBuilder {
        crate::operation::describe_orderable_cluster_options::builders::DescribeOrderableClusterOptionsInputBuilder::default()
    }
}

/// A builder for [`DescribeOrderableClusterOptionsInput`](crate::operation::describe_orderable_cluster_options::DescribeOrderableClusterOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeOrderableClusterOptionsInputBuilder {
    pub(crate) cluster_version: ::std::option::Option<::std::string::String>,
    pub(crate) node_type: ::std::option::Option<::std::string::String>,
    pub(crate) max_records: ::std::option::Option<i32>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
}
impl DescribeOrderableClusterOptionsInputBuilder {
    /// <p>The version filter value. Specify this parameter to show only the available offerings matching the specified version.</p>
    /// <p>Default: All versions.</p>
    /// <p>Constraints: Must be one of the version returned from <code>DescribeClusterVersions</code>.</p>
    pub fn cluster_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version filter value. Specify this parameter to show only the available offerings matching the specified version.</p>
    /// <p>Default: All versions.</p>
    /// <p>Constraints: Must be one of the version returned from <code>DescribeClusterVersions</code>.</p>
    pub fn set_cluster_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_version = input;
        self
    }
    /// <p>The version filter value. Specify this parameter to show only the available offerings matching the specified version.</p>
    /// <p>Default: All versions.</p>
    /// <p>Constraints: Must be one of the version returned from <code>DescribeClusterVersions</code>.</p>
    pub fn get_cluster_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_version
    }
    /// <p>The node type filter value. Specify this parameter to show only the available offerings matching the specified node type.</p>
    pub fn node_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node type filter value. Specify this parameter to show only the available offerings matching the specified node type.</p>
    pub fn set_node_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node_type = input;
        self
    }
    /// <p>The node type filter value. Specify this parameter to show only the available offerings matching the specified node type.</p>
    pub fn get_node_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.node_type
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
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeOrderableClusterOptions</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeOrderableClusterOptions</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeOrderableClusterOptions</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Consumes the builder and constructs a [`DescribeOrderableClusterOptionsInput`](crate::operation::describe_orderable_cluster_options::DescribeOrderableClusterOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_orderable_cluster_options::DescribeOrderableClusterOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_orderable_cluster_options::DescribeOrderableClusterOptionsInput {
                cluster_version: self.cluster_version,
                node_type: self.node_type,
                max_records: self.max_records,
                marker: self.marker,
            },
        )
    }
}
