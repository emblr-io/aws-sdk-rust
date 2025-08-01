// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeEndpointsOutput {
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>Endpoint description.</p>
    pub endpoints: ::std::option::Option<::std::vec::Vec<crate::types::Endpoint>>,
    _request_id: Option<String>,
}
impl DescribeEndpointsOutput {
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>Endpoint description.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.endpoints.is_none()`.
    pub fn endpoints(&self) -> &[crate::types::Endpoint] {
        self.endpoints.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeEndpointsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeEndpointsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeEndpointsOutput`](crate::operation::describe_endpoints::DescribeEndpointsOutput).
    pub fn builder() -> crate::operation::describe_endpoints::builders::DescribeEndpointsOutputBuilder {
        crate::operation::describe_endpoints::builders::DescribeEndpointsOutputBuilder::default()
    }
}

/// A builder for [`DescribeEndpointsOutput`](crate::operation::describe_endpoints::DescribeEndpointsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeEndpointsOutputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) endpoints: ::std::option::Option<::std::vec::Vec<crate::types::Endpoint>>,
    _request_id: Option<String>,
}
impl DescribeEndpointsOutputBuilder {
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
    /// Appends an item to `endpoints`.
    ///
    /// To override the contents of this collection use [`set_endpoints`](Self::set_endpoints).
    ///
    /// <p>Endpoint description.</p>
    pub fn endpoints(mut self, input: crate::types::Endpoint) -> Self {
        let mut v = self.endpoints.unwrap_or_default();
        v.push(input);
        self.endpoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>Endpoint description.</p>
    pub fn set_endpoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Endpoint>>) -> Self {
        self.endpoints = input;
        self
    }
    /// <p>Endpoint description.</p>
    pub fn get_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Endpoint>> {
        &self.endpoints
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeEndpointsOutput`](crate::operation::describe_endpoints::DescribeEndpointsOutput).
    pub fn build(self) -> crate::operation::describe_endpoints::DescribeEndpointsOutput {
        crate::operation::describe_endpoints::DescribeEndpointsOutput {
            marker: self.marker,
            endpoints: self.endpoints,
            _request_id: self._request_id,
        }
    }
}
