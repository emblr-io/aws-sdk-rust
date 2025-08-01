// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the result of a successful invocation of the <code>DescribeDBEngineVersions</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDbEngineVersionsOutput {
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>DBEngineVersion</code> elements.</p>
    pub db_engine_versions: ::std::option::Option<::std::vec::Vec<crate::types::DbEngineVersion>>,
    _request_id: Option<String>,
}
impl DescribeDbEngineVersionsOutput {
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>A list of <code>DBEngineVersion</code> elements.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.db_engine_versions.is_none()`.
    pub fn db_engine_versions(&self) -> &[crate::types::DbEngineVersion] {
        self.db_engine_versions.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDbEngineVersionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDbEngineVersionsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDbEngineVersionsOutput`](crate::operation::describe_db_engine_versions::DescribeDbEngineVersionsOutput).
    pub fn builder() -> crate::operation::describe_db_engine_versions::builders::DescribeDbEngineVersionsOutputBuilder {
        crate::operation::describe_db_engine_versions::builders::DescribeDbEngineVersionsOutputBuilder::default()
    }
}

/// A builder for [`DescribeDbEngineVersionsOutput`](crate::operation::describe_db_engine_versions::DescribeDbEngineVersionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDbEngineVersionsOutputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) db_engine_versions: ::std::option::Option<::std::vec::Vec<crate::types::DbEngineVersion>>,
    _request_id: Option<String>,
}
impl DescribeDbEngineVersionsOutputBuilder {
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
    /// Appends an item to `db_engine_versions`.
    ///
    /// To override the contents of this collection use [`set_db_engine_versions`](Self::set_db_engine_versions).
    ///
    /// <p>A list of <code>DBEngineVersion</code> elements.</p>
    pub fn db_engine_versions(mut self, input: crate::types::DbEngineVersion) -> Self {
        let mut v = self.db_engine_versions.unwrap_or_default();
        v.push(input);
        self.db_engine_versions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>DBEngineVersion</code> elements.</p>
    pub fn set_db_engine_versions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DbEngineVersion>>) -> Self {
        self.db_engine_versions = input;
        self
    }
    /// <p>A list of <code>DBEngineVersion</code> elements.</p>
    pub fn get_db_engine_versions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DbEngineVersion>> {
        &self.db_engine_versions
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeDbEngineVersionsOutput`](crate::operation::describe_db_engine_versions::DescribeDbEngineVersionsOutput).
    pub fn build(self) -> crate::operation::describe_db_engine_versions::DescribeDbEngineVersionsOutput {
        crate::operation::describe_db_engine_versions::DescribeDbEngineVersionsOutput {
            marker: self.marker,
            db_engine_versions: self.db_engine_versions,
            _request_id: self._request_id,
        }
    }
}
