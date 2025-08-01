// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDbProxiesInput {
    /// <p>The name of the DB proxy. If you omit this parameter, the output includes information about all DB proxies owned by your Amazon Web Services account ID.</p>
    pub db_proxy_name: ::std::option::Option<::std::string::String>,
    /// <p>This parameter is not currently supported.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of records to include in the response. If more records exist than the specified <code>MaxRecords</code> value, a pagination token called a marker is included in the response so that the remaining results can be retrieved.</p>
    /// <p>Default: 100</p>
    /// <p>Constraints: Minimum 20, maximum 100.</p>
    pub max_records: ::std::option::Option<i32>,
}
impl DescribeDbProxiesInput {
    /// <p>The name of the DB proxy. If you omit this parameter, the output includes information about all DB proxies owned by your Amazon Web Services account ID.</p>
    pub fn db_proxy_name(&self) -> ::std::option::Option<&str> {
        self.db_proxy_name.as_deref()
    }
    /// <p>This parameter is not currently supported.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>The maximum number of records to include in the response. If more records exist than the specified <code>MaxRecords</code> value, a pagination token called a marker is included in the response so that the remaining results can be retrieved.</p>
    /// <p>Default: 100</p>
    /// <p>Constraints: Minimum 20, maximum 100.</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
}
impl DescribeDbProxiesInput {
    /// Creates a new builder-style object to manufacture [`DescribeDbProxiesInput`](crate::operation::describe_db_proxies::DescribeDbProxiesInput).
    pub fn builder() -> crate::operation::describe_db_proxies::builders::DescribeDbProxiesInputBuilder {
        crate::operation::describe_db_proxies::builders::DescribeDbProxiesInputBuilder::default()
    }
}

/// A builder for [`DescribeDbProxiesInput`](crate::operation::describe_db_proxies::DescribeDbProxiesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDbProxiesInputBuilder {
    pub(crate) db_proxy_name: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) max_records: ::std::option::Option<i32>,
}
impl DescribeDbProxiesInputBuilder {
    /// <p>The name of the DB proxy. If you omit this parameter, the output includes information about all DB proxies owned by your Amazon Web Services account ID.</p>
    pub fn db_proxy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_proxy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the DB proxy. If you omit this parameter, the output includes information about all DB proxies owned by your Amazon Web Services account ID.</p>
    pub fn set_db_proxy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_proxy_name = input;
        self
    }
    /// <p>The name of the DB proxy. If you omit this parameter, the output includes information about all DB proxies owned by your Amazon Web Services account ID.</p>
    pub fn get_db_proxy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_proxy_name
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>This parameter is not currently supported.</p>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>This parameter is not currently supported.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>This parameter is not currently supported.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
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
    /// <p>The maximum number of records to include in the response. If more records exist than the specified <code>MaxRecords</code> value, a pagination token called a marker is included in the response so that the remaining results can be retrieved.</p>
    /// <p>Default: 100</p>
    /// <p>Constraints: Minimum 20, maximum 100.</p>
    pub fn max_records(mut self, input: i32) -> Self {
        self.max_records = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of records to include in the response. If more records exist than the specified <code>MaxRecords</code> value, a pagination token called a marker is included in the response so that the remaining results can be retrieved.</p>
    /// <p>Default: 100</p>
    /// <p>Constraints: Minimum 20, maximum 100.</p>
    pub fn set_max_records(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_records = input;
        self
    }
    /// <p>The maximum number of records to include in the response. If more records exist than the specified <code>MaxRecords</code> value, a pagination token called a marker is included in the response so that the remaining results can be retrieved.</p>
    /// <p>Default: 100</p>
    /// <p>Constraints: Minimum 20, maximum 100.</p>
    pub fn get_max_records(&self) -> &::std::option::Option<i32> {
        &self.max_records
    }
    /// Consumes the builder and constructs a [`DescribeDbProxiesInput`](crate::operation::describe_db_proxies::DescribeDbProxiesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_db_proxies::DescribeDbProxiesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_db_proxies::DescribeDbProxiesInput {
            db_proxy_name: self.db_proxy_name,
            filters: self.filters,
            marker: self.marker,
            max_records: self.max_records,
        })
    }
}
