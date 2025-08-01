// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the result of a successful invocation of the <code>DescribeReservedDBInstances</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeReservedDbInstancesOutput {
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>A list of reserved DB instances.</p>
    pub reserved_db_instances: ::std::option::Option<::std::vec::Vec<crate::types::ReservedDbInstance>>,
    _request_id: Option<String>,
}
impl DescribeReservedDbInstancesOutput {
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>A list of reserved DB instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reserved_db_instances.is_none()`.
    pub fn reserved_db_instances(&self) -> &[crate::types::ReservedDbInstance] {
        self.reserved_db_instances.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeReservedDbInstancesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeReservedDbInstancesOutput {
    /// Creates a new builder-style object to manufacture [`DescribeReservedDbInstancesOutput`](crate::operation::describe_reserved_db_instances::DescribeReservedDbInstancesOutput).
    pub fn builder() -> crate::operation::describe_reserved_db_instances::builders::DescribeReservedDbInstancesOutputBuilder {
        crate::operation::describe_reserved_db_instances::builders::DescribeReservedDbInstancesOutputBuilder::default()
    }
}

/// A builder for [`DescribeReservedDbInstancesOutput`](crate::operation::describe_reserved_db_instances::DescribeReservedDbInstancesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeReservedDbInstancesOutputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) reserved_db_instances: ::std::option::Option<::std::vec::Vec<crate::types::ReservedDbInstance>>,
    _request_id: Option<String>,
}
impl DescribeReservedDbInstancesOutputBuilder {
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
    /// Appends an item to `reserved_db_instances`.
    ///
    /// To override the contents of this collection use [`set_reserved_db_instances`](Self::set_reserved_db_instances).
    ///
    /// <p>A list of reserved DB instances.</p>
    pub fn reserved_db_instances(mut self, input: crate::types::ReservedDbInstance) -> Self {
        let mut v = self.reserved_db_instances.unwrap_or_default();
        v.push(input);
        self.reserved_db_instances = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of reserved DB instances.</p>
    pub fn set_reserved_db_instances(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReservedDbInstance>>) -> Self {
        self.reserved_db_instances = input;
        self
    }
    /// <p>A list of reserved DB instances.</p>
    pub fn get_reserved_db_instances(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReservedDbInstance>> {
        &self.reserved_db_instances
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeReservedDbInstancesOutput`](crate::operation::describe_reserved_db_instances::DescribeReservedDbInstancesOutput).
    pub fn build(self) -> crate::operation::describe_reserved_db_instances::DescribeReservedDbInstancesOutput {
        crate::operation::describe_reserved_db_instances::DescribeReservedDbInstancesOutput {
            marker: self.marker,
            reserved_db_instances: self.reserved_db_instances,
            _request_id: self._request_id,
        }
    }
}
